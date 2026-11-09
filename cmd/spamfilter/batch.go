package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

// ---- label-unsure -batch-api: label through the Message Batches API

// batchPerArticle is the estimated cost of one article in a batch: half the
// measured $0.029 per 1000 of the Messages API (Haiku).
const batchPerArticle = 0.0145 / 1000

// batchCost is the estimated cost of one article in a batch for a model:
// on the Messages API Sonnet measured $0.63 per 1000, Haiku with thinking
// at high effort $0.073 (batch $0.0364 measured).
func batchCost(model string, think bool) float64 {
	switch {
	case strings.Contains(model, "sonnet"):
		return 0.315 / 1000
	case think:
		return 0.0365 / 1000
	}
	return batchPerArticle
}

// batchPoll is how often the batches in flight are checked.
var batchPoll = time.Minute

// batchJob is a submitted Message Batch and the articles of its requests,
// kept in a file until its results are stored: the batch is paid for once
// it runs, so a restart must not lose it.
type batchJob struct {
	ID   string
	Reqs [][]sf.Article
	path string
	at   time.Time
}

func (j *batchJob) articles() int {
	n := 0
	for _, r := range j.Reqs {
		n += len(r)
	}
	return n
}

// saveJob writes the job to dir/<id>.json.gz.
func saveJob(dir string, j *batchJob) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	j.path = filepath.Join(dir, j.ID+".json.gz")
	f, err := os.Create(j.path + ".tmp")
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	err = json.NewEncoder(gz).Encode(struct {
		ID   string
		Reqs [][]sf.Article
	}{j.ID, j.Reqs})
	if cerr := gz.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), j.path)
}

func loadJobs(dir string) ([]*batchJob, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.json.gz"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var jobs []*batchJob
	for _, name := range names {
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		gz, err := gzip.NewReader(bufio.NewReader(f))
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		j := &batchJob{path: name, at: time.Now()}
		err = json.NewDecoder(gz).Decode(j)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		jobs = append(jobs, j)
	}
	return jobs, nil
}

// fetchAll fetches the bodies of arts on several connections (the items
// sorted by group, split in contiguous parts) and returns the articles the
// server had, with the start of the body added.
func fetchAll(fs []*fetcher, arts []sf.Article) ([]sf.Article, error) {
	idx := make([]int, len(arts))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return arts[idx[a]].Source < arts[idx[b]].Source })
	got := make([]sf.Article, len(arts))
	ok := make([]bool, len(arts))
	var wg sync.WaitGroup
	errs := make([]error, len(fs))
	per := (len(idx) + len(fs) - 1) / len(fs)
	for p, f := range fs {
		lo, hi := min(p*per, len(idx)), min((p+1)*per, len(idx))
		if lo >= hi {
			continue
		}
		part := idx[lo:hi]
		wg.Add(1)
		go func() {
			defer wg.Done()
			items := make([]fetchItem, len(part))
			for i, k := range part {
				g, _, _ := strings.Cut(arts[k].Source, ":")
				items[i] = fetchItem{g, artNumber(arts[k].Source)}
			}
			_, errs[p] = f.fetch(items, func(i int, head, body []string) {
				k := part[i]
				if a, fine := withBody(arts[k], head, body); fine {
					got[k], ok[k] = a, true
				}
			})
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	var out []sf.Article
	for i, a := range got {
		if ok[i] {
			out = append(out, a)
		}
	}
	return out, nil
}

// batchRun labels the candidates in order: it fetches batchArts articles
// at a time, submits them as one Message Batch, keeps up to inFlight
// batches waiting, and stores each batch's verdicts when it ends. It stops
// submitting at stopAfter labels (counting those in flight), at the budget
// (counting the estimate of those in flight) or on Ctrl-C; the batches in
// flight are then kept on disk for the next run.
func batchRun(ctx context.Context, lab *labeler, lf *labelFlags, jobsDir string, jobs []*batchJob, src artSource,
	fs []*fetcher, batchArts, inFlight int, stopAfter int64) error {
	perArt := batchCost(lab.first.Model, !lab.first.NoThinking)
	counts := map[string]int64{}
	start := time.Now()
	var fetched, missing int64
	inFlightArts := func() int64 {
		var n int64
		for _, j := range jobs {
			n += int64(j.articles())
		}
		return n
	}
	finish := func(j *batchJob) error {
		vss, err := lab.first.BatchVerdicts(ctx, j.ID, j.Reqs)
		if err != nil {
			return err
		}
		for i, arts := range j.Reqs {
			if err := lab.st.PutVerdicts(arts, vss[i]); err != nil {
				return err
			}
			for _, v := range vss[i] {
				if v.Label != "" {
					lab.labelled++
					counts[v.Label]++
				}
			}
		}
		if err := lab.account(lab.first, &lab.prev1); err != nil {
			return err
		}
		log.Printf("label-unsure: batch %s done after %s: %d labelled this run (spam %d, ham %d, unsure %d); $%.2f this run, $%.2f in all; %s",
			j.ID, time.Since(j.at).Round(time.Second), lab.labelled, counts[sf.Spam], counts[sf.Ham], counts[sf.Unsure],
			lab.own, lab.spent, time.Since(start).Round(time.Second))
		return os.Remove(j.path)
	}
	// waitSome polls the batches in flight until at least one has ended,
	// and stores the results of all that have
	waitSome := func() error {
		for {
			var rest []*batchJob
			done := 0
			for _, j := range jobs {
				ended, _, err := lab.first.BatchEnded(ctx, j.ID)
				if err != nil {
					log.Printf("label-unsure: batch %s: %v", j.ID, err)
					rest = append(rest, j)
					continue
				}
				if !ended {
					rest = append(rest, j)
					continue
				}
				if err := finish(j); err != nil {
					return err
				}
				done++
			}
			jobs = rest
			if done > 0 || len(jobs) == 0 {
				return nil
			}
			select {
			case <-time.After(batchPoll):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	// the overview articles come from src a segment at a time
	var buf []sf.Article
	srcDone := false
	next := func() ([]sf.Article, error) {
		if len(buf) == 0 && !srcDone {
			arts, err := src(10 * batchArts)
			if err != nil {
				return nil, err
			}
			buf, srcDone = arts, len(arts) == 0
		}
		n := min(batchArts, len(buf))
		part := buf[:n]
		buf = buf[n:]
		if n == 0 {
			return nil, nil
		}
		t0 := time.Now()
		got, err := fetchAll(fs, part)
		if err != nil {
			return nil, err
		}
		fetched += int64(len(got))
		missing += int64(len(part) - len(got))
		log.Printf("label-unsure: fetched %d articles in %s (%d not on the server)", len(got), time.Since(t0).Round(time.Second), len(part)-len(got))
		return got, nil
	}

	submitting := true
	for {
		if ctx.Err() != nil {
			log.Printf("label-unsure: stopped; %d batches in flight are kept in %s for the next run", len(jobs), jobsDir)
			return nil
		}
		pending := inFlightArts()
		switch {
		case !submitting:
		case srcDone && len(buf) == 0:
			submitting = false
		case lab.labelled+pending >= stopAfter:
			log.Printf("label-unsure: %d labelled and %d in flight: -stop-after reached", lab.labelled, pending)
			submitting = false
		case lab.spent+float64(pending+int64(batchArts))*perArt > lf.budget:
			log.Printf("label-unsure: $%.2f spent and about $%.2f in flight: budget of $%.2f reached", lab.spent, float64(pending)*perArt, lf.budget)
			submitting = false
		}
		if submitting && len(jobs) < inFlight {
			arts, err := next()
			if err != nil {
				return err
			}
			if len(arts) == 0 {
				if srcDone && len(buf) == 0 {
					submitting = false
				}
				continue
			}
			id, reqs, err := lab.first.SubmitBatch(ctx, arts)
			if err != nil {
				return err
			}
			j := &batchJob{ID: id, Reqs: reqs, at: time.Now()}
			if err := saveJob(jobsDir, j); err != nil {
				return err
			}
			jobs = append(jobs, j)
			log.Printf("label-unsure: submitted batch %s: %d articles in %d requests; %d batches in flight", id, len(arts), len(reqs), len(jobs))
			continue
		}
		if len(jobs) == 0 {
			log.Printf("label-unsure: done: %d labelled this run, %d fetched, %d not on the server; next: train, then rescore", lab.labelled, fetched, missing)
			return nil
		}
		if err := waitSome(); err != nil {
			if ctx.Err() != nil {
				continue
			}
			return err
		}
	}
}

// artSource gives up to n more overview articles to label; none when it
// has no more.
type artSource func(n int) ([]sf.Article, error)

// candSource reads the candidates in order from the candidate files.
func candSource(order []candRec, candDir string) artSource {
	pos := 0
	return func(n int) ([]sf.Article, error) {
		seg := order[pos:min(pos+n, len(order))]
		pos += len(seg)
		if len(seg) == 0 {
			return nil, nil
		}
		need := map[int32]int{}
		for i, r := range seg {
			need[r.idx] = i
		}
		arts := make([]sf.Article, len(seg))
		err := sf.ReadCandidates(candDir, func(i int, c sf.Candidate) error {
			if j, ok := need[int32(i)]; ok {
				arts[j] = c.Article
			}
			return nil
		})
		return arts, err
	}
}

// sliceSource gives the articles of a slice in order.
func sliceSource(arts []sf.Article) artSource {
	return func(n int) ([]sf.Article, error) {
		k := min(n, len(arts))
		part := arts[:k]
		arts = arts[k:]
		return part, nil
	}
}
