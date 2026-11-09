package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

// fakeBatchAPI answers the Message Batches endpoints: every batch is
// in progress at the first look and ended at the second; each request's
// articles are labelled alternately spam (m) and ham (d).
func fakeBatchAPI(t *testing.T) (*httptest.Server, *int) {
	var mu sync.Mutex
	batches := map[string][]string{} // id -> custom_id of each request, with the article count
	looks := map[string]int{}
	created := 0
	nRE := regexp.MustCompile(`Label these (\d+) articles`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/v1/messages/batches")
		switch {
		case r.Method == http.MethodPost && path == "":
			var body struct {
				Requests []struct {
					CustomID string `json:"custom_id"`
					Params   struct {
						Messages []struct {
							Content []struct{ Text string } `json:"content"`
						} `json:"messages"`
					} `json:"params"`
				} `json:"requests"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			created++
			id := fmt.Sprintf("msgbatch_%d", created)
			for _, q := range body.Requests {
				n := "0"
				if m := nRE.FindStringSubmatch(q.Params.Messages[0].Content[0].Text); m != nil {
					n = m[1]
				}
				batches[id] = append(batches[id], q.CustomID+" "+n)
			}
			fmt.Fprintf(w, `{"id":%q,"type":"message_batch","processing_status":"in_progress","request_counts":{"processing":%d}}`, id, len(body.Requests))
		case r.Method == http.MethodGet && strings.HasSuffix(path, "/results"):
			w.Header().Set("Content-Type", "application/x-jsonl")
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/results")
			for _, q := range batches[id] {
				var cid string
				var n int
				fmt.Sscan(q, &cid, &n)
				var text strings.Builder
				for i := 1; i <= n; i++ {
					fmt.Fprintf(&text, "%d%c\n", i, "md"[i%2])
				}
				msg := map[string]any{"id": "m", "type": "message", "role": "assistant", "model": "claude-haiku-5-5",
					"content": []any{map[string]any{"type": "text", "text": text.String()}}, "stop_reason": "end_turn",
					"usage": map[string]any{"input_tokens": 1000, "output_tokens": 100}}
				b, _ := json.Marshal(map[string]any{"custom_id": cid, "result": map[string]any{"type": "succeeded", "message": msg}})
				w.Write(append(b, '\n'))
			}
		case r.Method == http.MethodGet:
			id := strings.TrimPrefix(path, "/")
			looks[id]++
			status := "in_progress"
			if looks[id] >= 2 {
				status = "ended"
			}
			fmt.Fprintf(w, `{"id":%q,"type":"message_batch","processing_status":%q,"request_counts":{}}`, id, status)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &created
}

func TestLabelUnsureBatchAPI(t *testing.T) {
	addr := fakeServer(t, 4, 150)
	api, created := fakeBatchAPI(t)
	t.Setenv("ANTHROPIC_BASE_URL", api.URL)
	t.Setenv("ANTHROPIC_API_KEY", "test")
	batchPoll = 10 * time.Millisecond
	dir := t.TempDir()
	modelPath := testModel(t, dir)
	db := filepath.Join(dir, "b.db")
	if err := run([]string{"-server", addr, "-db", db, "-mode", "unsure", "-model-file", modelPath, "-chunk", "50",
		"-groups", "*", "-nocem-types", "", "-share", "1", "-ham-every", "0"}); err != nil {
		t.Fatal(err)
	}
	err := labelUnsure([]string{"-db", db, "-server", addr, "-batch-api", "-batch-articles", "100", "-in-flight", "2",
		"-batch", "20", "-key-file", filepath.Join(dir, "nokey"), "-budget", "10", "-fetch-conns", "2", "-copies-usd", "0"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := sf.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := st.VerdictCount()
	spent, _ := st.Spent()
	st.Close()
	if n == 0 || *created < 2 {
		t.Fatalf("%d labels from %d batches", n, *created)
	}
	// half price: 1000 in + 100 out per request at Haiku's $0.10/$0.50
	reqs := (int(n) + 19) / 20
	if want := float64(reqs) * (1000*0.10 + 100*0.50) / 1e6 / 2; spent < want*0.99 || spent > want*1.01 {
		t.Fatalf("spent $%.6f for %d requests, want $%.6f", spent, reqs, want)
	}
	if left, _ := filepath.Glob(filepath.Join(db+".batches", "*.json.gz")); len(left) != 0 {
		t.Fatalf("job files left: %v", left)
	}
	// a second run finds everything labelled
	if err := labelUnsure([]string{"-db", db, "-server", addr, "-batch-api", "-key-file", filepath.Join(dir, "nokey"), "-copies-usd", "0"}); err != nil {
		t.Fatal(err)
	}
}

func TestBatchJobFile(t *testing.T) {
	dir := t.TempDir()
	j := &batchJob{ID: "msgbatch_x", Reqs: [][]sf.Article{{{MsgID: "<a@x>", Key: "ka"}}, {{MsgID: "<b@x>", Key: "kb"}}}}
	if err := saveJob(dir, j); err != nil {
		t.Fatal(err)
	}
	jobs, err := loadJobs(dir)
	if err != nil || len(jobs) != 1 || jobs[0].ID != "msgbatch_x" || jobs[0].articles() != 2 || jobs[0].Reqs[1][0].Key != "kb" {
		t.Fatalf("%v %+v", err, jobs)
	}
	os.Remove(jobs[0].path)
}
