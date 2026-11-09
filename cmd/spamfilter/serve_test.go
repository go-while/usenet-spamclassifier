package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

func TestServePages(t *testing.T) {
	addr := fakeServer(t, 3, 50)
	dir := t.TempDir()
	db := filepath.Join(dir, "s.db")
	st, err := sf.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	st.SetGroupRange("g0", 1, 50)
	st.GroupProgress("g0", 50, 50, 7)
	st.AddSpam([]sf.SpamRow{{MsgID: "<0.7@x>", Key: "k", Group: "g0", ArtNum: 7, Stage: sf.StageRules, Reason: "subj:mmf"}})
	st.AddNotices([]sf.Notice{{Issuer: "bot", Type: "spam", ID: "n1", Entries: []sf.NoticeEntry{{MsgID: "<0.3@x>", Groups: "g0", Subject: "BUY"}}}})
	st.PutVerdicts([]sf.Article{{MsgID: "<0.1@x>", Key: "k1", Subject: "hello <script>"}}, []sf.Verdict{{Key: "k1", Label: sf.Ham, Stage: sf.StageLLM, Reason: "", Model: "m"}})
	st.Close()

	var ex []sf.Example
	for i := 0; i < 400; i++ {
		a := sf.Article{Subject: fmt.Sprintf("question %d about gardening", i), From: "u@example.org", Groups: 1, Lines: 10}
		if i%2 == 0 {
			a.Subject = "cheap pills online now"
		}
		ex = append(ex, sf.Example{A: a, Spam: i%2 == 0})
	}
	m, _, err := sf.Train(ex, 16, 3, 0.9, 0.9, 1)
	if err != nil {
		t.Fatal(err)
	}
	ro, err := sf.OpenStoreRO(db)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	match, _ := wildmat("*")
	s := &server{st: ro, model: m, rules: sf.DefaultRules, match: match, addr: addr, timeout: 5e9,
		types: map[string]bool{"spam": true}, tmpl: newTemplates()}
	// what refreshStats would fill in
	s.spam, _ = ro.SpamCounts()
	s.labels, _ = ro.LabelCounts()
	nc, _ := ro.NocemCounts()
	for k, n := range nc {
		s.nocem = append(s.nocem, kv{k, n})
	}
	ts := httptest.NewServer(s.handler())
	defer ts.Close()
	for path, want := range map[string][]string{
		"/":                   {"g0", "subj:mmf", "llm/ham"},
		"/groups?prefix=g":    {"g0"},
		"/g?name=g0":          {"MAKE MONEY FAST", "in filter", "stored: rules subj:mmf", "NoCeM spam by bot"},
		"/g?name=g0&show=ham": {"clean"},
		"/a?g=g0&n=7":         {"MAKE MONEY FAST", "body &lt;b&gt;&amp;amp; text"},
		"/m?id=0.3@x":         {"type <b>spam</b>", "counted as spam"},
		"/m?id=%3Cnone@x%3E":  {"Not in the spam table", "Not listed"},
		"/labels?label=ham":   {"hello &lt;script&gt;"},
		"/nocem":              {"bot", "yes"},
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("%s: %d %s", path, resp.StatusCode, b)
			continue
		}
		for _, w := range want {
			if !strings.Contains(string(b), w) {
				t.Errorf("%s: no %q in page", path, w)
			}
		}
	}
	// the ham filter shows no spam rows
	resp, _ := http.Get(ts.URL + "/g?name=g0&show=ham")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(b), `<tr class="spam">`) {
		t.Error("show=ham lists spam")
	}
}
