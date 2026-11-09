package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

// ---- label-unsure, audit, rescore: label what the scan left open, with
// the article bodies, and spot-check what it flagged

// labelFlags are the model API options label-unsure and audit share.
type labelFlags struct {
	model, escalate, escOn, keyFile string
	effort                          string
	think                           bool
	batch, conc                     int
	budget                          float64
}

func (lf *labelFlags) register(fs *flag.FlagSet, escalate, escOn string) {
	fs.StringVar(&lf.model, "model", "claude-haiku-5-5", "model for the first pass")
	fs.StringVar(&lf.escalate, "escalate", escalate, "model for what the first pass labels with an -escalate-on label (\"\" = none)")
	fs.StringVar(&lf.escOn, "escalate-on", escOn, "first-pass labels to escalate, comma-separated")
	fs.StringVar(&lf.keyFile, "key-file", "/dev/shm/spamfilter_apikey.txt", "file holding the API key (else ANTHROPIC_API_KEY)")
	fs.StringVar(&lf.effort, "effort", "low", "effort for the first pass")
	fs.BoolVar(&lf.think, "thinking", false, "let the first-pass model think before it labels (more output tokens)")
	fs.IntVar(&lf.batch, "batch", 50, "articles per API request")
	fs.IntVar(&lf.conc, "concurrency", 8, "API requests in flight")
	fs.Float64Var(&lf.budget, "budget", 150, "stop once this many dollars (list price) are spent in this database, all runs together")
}

func (lf *labelFlags) labeler(st *sf.Store) (*labeler, error) {
	opts := []option.RequestOption{option.WithMaxRetries(5)}
	if key, err := readKey(lf.keyFile); err == nil {
		opts = append(opts, option.WithAPIKey(key))
	} else if os.Getenv("ANTHROPIC_API_KEY") == "" {
		return nil, fmt.Errorf("no API key: %v, and ANTHROPIC_API_KEY is not set", err)
	}
	client := anthropic.NewClient(opts...)
	lab := &labeler{st: st, budget: lf.budget, batch: lf.batch * lf.conc, escOn: map[string]bool{"": true}}
	lab.first = &sf.LLM{Client: client, Model: lf.model, Effort: lf.effort, BatchSize: lf.batch, Concurrency: lf.conc, NoThinking: !lf.think}
	if lf.escalate != "" && lf.escalate != lf.model {
		lab.second = &sf.LLM{Client: client, Model: lf.escalate, Effort: "low", BatchSize: lf.batch, Concurrency: lf.conc}
	}
	for _, l := range splitList(lf.escOn) {
		lab.escOn[l] = true
	}
	var err error
	lab.spent, err = st.Spent()
	return lab, err
}

// fetcher gets whole articles by group and number on one connection,
// reconnecting once when a group's fetch fails.
type fetcher struct {
	server   string
	timeout  time.Duration
	limit    *sf.Limiter
	compress bool
	c        *sf.NNTP
}

type fetchItem struct {
	group string
	num   int64
}

func (f *fetcher) conn() (*sf.NNTP, error) {
	if f.c == nil {
		c, err := sf.DialNNTPLimited(f.server, f.timeout, f.limit)
		if err != nil {
			return nil, err
		}
		c.ModeReader()
		if err := compressOn(c, f.compress); err != nil {
			c.Quit()
			return nil, err
		}
		f.c = c
	}
	return f.c, nil
}

func (f *fetcher) drop() {
	if f.c != nil {
		f.c.Quit()
		f.c = nil
	}
}

// fetch fetches the items, a group at a time, and calls fn for each one
// the server has. It returns how many it could not get.
func (f *fetcher) fetch(items []fetchItem, fn func(i int, head, body []string)) (missing int, err error) {
	idx := make([]int, len(items))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool {
		x, y := items[idx[a]], items[idx[b]]
		if x.group != y.group {
			return x.group < y.group
		}
		return x.num < y.num
	})
	got := make([]bool, len(items))
	for s := 0; s < len(idx); {
		e := s
		for e < len(idx) && items[idx[e]].group == items[idx[s]].group {
			e++
		}
		group := items[idx[s]].group
		byNum := map[int64]int{}
		var nums []int64
		for _, i := range idx[s:e] {
			if _, dup := byNum[items[i].num]; !dup {
				nums = append(nums, items[i].num)
			}
			byNum[items[i].num] = i
		}
		var gerr error
		for attempt := 0; attempt < 2; attempt++ {
			c, err := f.conn()
			if err != nil {
				return missing, err
			}
			if _, _, _, gerr = c.Group(group); gerr == nil {
				gerr = c.Articles(nums, 100, func(num int64, head, body []string) error {
					if i, ok := byNum[num]; ok && !got[i] {
						got[i] = true
						fn(i, head, body)
					}
					return nil
				})
			}
			if gerr == nil {
				break
			}
			f.drop()
		}
		if gerr != nil {
			log.Printf("fetch: %s: %v; skipped", group, gerr)
		}
		s = e
	}
	for _, g := range got {
		if !g {
			missing++
		}
	}
	return missing, nil
}

// withBody adds what the fetched article tells the model to the overview
// article c: the start of the body and the Organization. Key, groups and
// the other headers stay as the overview gives them, so the verdict goes
// under the key the scan looks up and trains on the same features.
func withBody(c sf.Article, head, body []string) (sf.Article, bool) {
	full := sf.NewArticle(head, body, -1)
	if c.MsgID != "" && full.MsgID != c.MsgID {
		return c, false // renumbered: not the article we meant
	}
	c.Snippet = full.Snippet
	c.Organization = full.Organization
	c.BodyHash = full.BodyHash
	c.NoBody = false
	return c, true
}

// candKey is the binary form of an FSL key (hex of 12 bytes).
type candKey [12]byte

func toCandKey(k string) (ck candKey, ok bool) {
	b, err := hex.DecodeString(k)
	if err != nil || len(b) != len(ck) {
		return ck, false
	}
	copy(ck[:], b)
	return ck, true
}

// candRec is what label-unsure keeps in memory of a candidate.
type candRec struct {
	idx     int32 // line index in the candidate files
	hier    int32
	bikey   uint64
	counted bool
	bi      float32
	prio    float64
}

func labelUnsure(args []string) error {
	fs := flag.NewFlagSet("label-unsure", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database")
	server := fs.String("server", "", "news server, HOST:PORT")
	candDir := fs.String("cand-dir", "", "candidate files of run -mode unsure (default: the database path + \".unsure\")")
	biDir := fs.String("bi-dir", "", "Breidbart counts of the full scan (default: the database path + \".bi\")")
	copiesUSD := fs.Float64("copies-usd", 40, "spend at most this much in this run on the most-copied candidates first (Breidbart index -min-bi up to the threshold); 0 = skip them")
	minBI := fs.Float64("min-bi", 3, "Breidbart index from which a candidate counts as copied")
	stopAfter := fs.Int64("stop-after", 500000, "stop after this many labels in this run (then retrain and rescore)")
	block := fs.Int("block", 2000, "articles fetched and labelled at a time")
	maxMbit := fs.Float64("max-mbit", 100, "cap on the download from the news server (0 = none)")
	timeout := fs.Duration("timeout", 2*time.Minute, "network timeout")
	compress := fs.Bool("compress", true, "COMPRESS DEFLATE when the server offers it")
	seed := fs.Uint64("seed", 1, "random seed for the spread")
	dry := fs.Bool("dry", false, "only report the selection and its estimated cost")
	modelFile := fs.String("model-file", "", "only candidates this local model cannot decide (\"\" = all)")
	batchAPI := fs.Bool("batch-api", false, "send through the Message Batches API: half price, results within 24 hours; jobs survive a restart")
	batchArts := fs.Int("batch-articles", 100000, "batch API: articles per Message Batch")
	inFlight := fs.Int("in-flight", 6, "batch API: Message Batches waiting for results at once")
	fetchConns := fs.Int("fetch-conns", 3, "batch API: server connections fetching articles")
	jobsDir := fs.String("jobs-dir", "", "batch API: where submitted batches are kept until their results are stored (default: the database path + \".batches\")")
	var lf labelFlags
	lf.register(fs, "", "")
	fs.Parse(args)
	if *candDir == "" {
		*candDir = *dbPath + ".unsure"
	}
	if *jobsDir == "" {
		*jobsDir = *dbPath + ".batches"
	}
	if *biDir == "" {
		*biDir = *dbPath + ".bi"
	}
	if *server == "" && !*dry {
		return errors.New("need -server HOST:PORT")
	}
	st, err := sf.OpenStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	t0 := time.Now()
	known, err := st.VerdictKeys()
	if err != nil {
		return err
	}
	var jobs []*batchJob
	if *batchAPI {
		// batches of an earlier run that have no stored results yet
		if jobs, err = loadJobs(*jobsDir); err != nil {
			return err
		}
		for _, j := range jobs {
			for _, r := range j.Reqs {
				for _, a := range r {
					known[a.Key] = true
				}
			}
		}
		if len(jobs) > 0 {
			log.Printf("label-unsure: %d batches of an earlier run waiting for results", len(jobs))
		}
	}
	var decided func(a sf.Article) bool
	if *modelFile != "" {
		m, err := sf.LoadModel(*modelFile)
		if err != nil {
			return err
		}
		decided = func(a sf.Article) bool { l, _ := m.Decide(a); return l != "" }
	}
	var decidedN int64
	// one candidate per FSL key, none already labelled
	seen := map[candKey]bool{}
	hierID := map[string]int32{}
	var hiers []string
	var recs []candRec
	var lines, dups, labelled int64
	err = sf.ReadCandidates(*candDir, func(i int, c sf.Candidate) error {
		if c.Kind != sf.CandUnsure {
			return nil
		}
		lines++
		ck, ok := toCandKey(c.Key)
		if !ok || seen[ck] {
			dups++
			return nil
		}
		seen[ck] = true
		if known[c.Key] {
			labelled++
			return nil
		}
		if decided != nil && decided(c.Article) {
			decidedN++
			return nil
		}
		group, _, _ := strings.Cut(c.Source, ":")
		h := sf.Hierarchy(group)
		id, ok := hierID[h]
		if !ok {
			id = int32(len(hiers))
			hierID[h] = id
			hiers = append(hiers, h)
		}
		k, counted := sf.BIKey(c.Article, sf.DefaultRules.MinLines)
		recs = append(recs, candRec{idx: int32(i), hier: id, bikey: k, counted: counted})
		return nil
	})
	if err != nil {
		return err
	}
	seen, known = nil, nil
	log.Printf("label-unsure: %d uncertain lines, %d repeats of a key, %d keys labelled before, %d decided by -model-file, %d to choose from (%s)",
		lines, dups, labelled, decidedN, len(recs), time.Since(t0).Round(time.Second))

	// the Breidbart index of each, from the full scan's counts
	want := map[uint64]float32{}
	for _, r := range recs {
		if r.counted {
			want[r.bikey] = 0
		}
	}
	nrec, err := sf.SumBIKeys(*biDir, want)
	if err != nil {
		return err
	}
	for i := range recs {
		if recs[i].counted {
			recs[i].bi = want[recs[i].bikey]
		}
	}
	want = nil
	log.Printf("label-unsure: Breidbart index looked up in %d records (%s)", nrec, time.Since(t0).Round(time.Second))

	// tier 1: copied, most copies first; tier 2: the rest, a weighted
	// random order in which a hierarchy's share grows with the square root
	// of its size, so small hierarchies get more than their share
	thr := float32(sf.DefaultRules.BIThreshold)
	perHier := make([]int, len(hiers))
	for _, r := range recs {
		perHier[r.hier]++
	}
	rng := rand.New(rand.NewPCG(*seed, *seed^0x9e3779b97f4a7c15))
	var tier1, tier2 []candRec
	var over, copies1 int64
	for _, r := range recs {
		switch {
		case r.bi >= thr:
			over++ // flagged by the Breidbart pass already
		case *copiesUSD > 0 && float64(r.bi) >= *minBI:
			tier1 = append(tier1, r)
			copies1 += int64(r.bi)
		default:
			r.prio = -math.Log(1-rng.Float64()) * math.Sqrt(float64(perHier[r.hier]))
			tier2 = append(tier2, r)
		}
	}
	recs = nil
	sort.Slice(tier1, func(i, j int) bool { return tier1[i].bi > tier1[j].bi })
	sort.Slice(tier2, func(i, j int) bool { return tier2[i].prio < tier2[j].prio })
	const perItem = 0.029 / 1000 // measured, Haiku with body snippets
	log.Printf("label-unsure: tier 1 (copied, index %.0f-%.0f): %d keys, about %d copies, $%.0f to label all; tier 2: %d keys, $%.0f to label all; %d at or above %.0f skipped",
		*minBI, thr, len(tier1), copies1, float64(len(tier1))*perItem, len(tier2), float64(len(tier2))*perItem, over, thr)
	type hc struct {
		h string
		n int
	}
	var hs []hc
	for i, n := range perHier {
		hs = append(hs, hc{hiers[i], n})
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].n > hs[j].n })
	var top []string
	for _, x := range hs[:min(len(hs), 15)] {
		top = append(top, fmt.Sprintf("%s %d", x.h, x.n))
	}
	log.Printf("label-unsure: by hierarchy: %s", strings.Join(top, ", "))
	if *dry {
		if *batchAPI {
			log.Printf("label-unsure: with the batch API about $%.0f to label all", float64(len(tier1)+len(tier2))*batchPerArticle)
		}
		return nil
	}

	lab, err := lf.labeler(st)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	limit := sf.NewLimiter(*maxMbit)
	if *batchAPI {
		lab.first.Batch = true
		var fs []*fetcher
		for range max(*fetchConns, 1) {
			f := &fetcher{server: *server, timeout: *timeout, limit: limit, compress: *compress}
			defer f.drop()
			fs = append(fs, f)
		}
		return batchRun(ctx, lab, &lf, *jobsDir, jobs, candSource(append(tier1, tier2...), *candDir), fs, *batchArts, *inFlight, *stopAfter)
	}
	f := &fetcher{server: *server, timeout: *timeout, limit: limit, compress: *compress}
	defer f.drop()

	counts := map[string]int64{}
	var missing int64
	start := time.Now()
	// seg is the next stretch of the order; its articles are read from the
	// candidate files in one go
	order := append(tier1, tier2...)
	pos, end1 := 0, len(tier1)
	for pos < len(order) && lab.labelled < *stopAfter && lab.spent < lf.budget && ctx.Err() == nil {
		if pos < end1 && lab.own >= *copiesUSD {
			log.Printf("label-unsure: $%.2f spent on tier 1, on to tier 2", lab.own)
			pos = end1
			continue
		}
		segEnd := min(len(order), pos+int(min(*stopAfter-lab.labelled, 250000)))
		if pos < end1 {
			segEnd = min(segEnd, end1)
		}
		seg := order[pos:segEnd]
		need := map[int32]int{}
		for i, r := range seg {
			need[r.idx] = i
		}
		arts := make([]sf.Article, len(seg))
		err := sf.ReadCandidates(*candDir, func(i int, c sf.Candidate) error {
			if j, ok := need[int32(i)]; ok {
				arts[j] = c.Article
			}
			return nil
		})
		if err != nil {
			return err
		}
		for b := 0; b < len(seg) && lab.labelled < *stopAfter && lab.spent < lf.budget && ctx.Err() == nil; b += *block {
			if pos < end1 && lab.own >= *copiesUSD {
				break
			}
			part := arts[b:min(b+*block, len(seg))]
			items := make([]fetchItem, len(part))
			for i, a := range part {
				g, _, _ := strings.Cut(a.Source, ":")
				items[i] = fetchItem{g, artNumber(a.Source)}
			}
			var queued int
			miss, err := f.fetch(items, func(i int, head, body []string) {
				a, ok := withBody(part[i], head, body)
				if !ok {
					return
				}
				queued++
				lab.add(a, func(v sf.Verdict) { counts[v.Label]++ })
			})
			if err != nil {
				return err
			}
			missing += int64(miss + len(part) - miss - queued)
			if err := lab.flush(ctx); err != nil {
				return err
			}
			tier := 2
			if pos+b < end1 {
				tier = 1
			}
			log.Printf("label-unsure: tier %d: %d labelled this run (spam %d, ham %d, unsure %d), %d not fetched; $%.2f this run, $%.2f in all; %s",
				tier, lab.labelled, counts[sf.Spam], counts[sf.Ham], counts[sf.Unsure], missing, lab.own, lab.spent,
				time.Since(start).Round(time.Second))
		}
		pos = segEnd
	}
	switch {
	case ctx.Err() != nil:
		log.Printf("label-unsure: stopped; labels are saved, run again to continue (with -copies-usd 0 once tier 1 is done)")
	case lab.labelled >= *stopAfter:
		log.Printf("label-unsure: %d labels; next: train, then rescore", lab.labelled)
	case lab.spent >= lf.budget:
		log.Printf("label-unsure: budget of $%.2f reached", lf.budget)
	default:
		log.Printf("label-unsure: every candidate is labelled")
	}
	return nil
}

// ---- audit: spot-check flagged and clean articles

// auditClass groups the spam rows by what flagged them.
func auditClass(stage, reason string) string {
	switch {
	case stage == sf.StageRules && strings.HasPrefix(reason, "bi="):
		return "bi"
	case stage == sf.StageRules:
		return "subj"
	}
	return stage
}

func audit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database")
	server := fs.String("server", "", "news server, HOST:PORT")
	candDir := fs.String("cand-dir", "", "candidate files of run -mode unsure, for the clean sample (default: the database path + \".unsure\")")
	n := fs.Int("n", 20000, "flagged articles to check, split evenly over what flagged them (model, nocem, bi, subj, llm)")
	cleanN := fs.Int("clean-n", 3000, "articles the scan judged ham to check (from the candidate files)")
	group := fs.String("group", "", "check only flagged articles of this group (-n of them)")
	maxMbit := fs.Float64("max-mbit", 100, "cap on the download from the news server (0 = none)")
	timeout := fs.Duration("timeout", 2*time.Minute, "network timeout")
	compress := fs.Bool("compress", true, "COMPRESS DEFLATE when the server offers it")
	seed := fs.Uint64("seed", uint64(time.Now().UnixNano()), "random seed")
	report := fs.Bool("report", false, "only print the results stored so far")
	tag := fs.String("tag", "", "name of this round of spot checks: stored as kind flagged-TAG and clean-TAG, so a later round does not mix with the first (which compare uses)")
	var lf labelFlags
	lf.register(fs, "claude-sonnet-5-5", "")
	fs.Parse(args)
	if *candDir == "" {
		*candDir = *dbPath + ".unsure"
	}
	st, err := sf.OpenStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if *report {
		return auditReport(st, *tag)
	}
	if *server == "" {
		return errors.New("need -server HOST:PORT")
	}
	rng := rand.New(rand.NewPCG(*seed, *seed^0x2545f4914f6cdd1d))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	f := &fetcher{server: *server, timeout: *timeout, limit: sf.NewLimiter(*maxMbit), compress: *compress}
	defer f.drop()

	// flagged: random rows, an even share per class (rare classes take
	// more draws)
	var rows []sf.SpamRow
	if *n > 0 {
		if *group != "" {
			if rows, err = st.SampleSpam(*n, *group, rng.Int64N); err != nil {
				return err
			}
		} else {
			classes := []string{sf.StageModel, sf.StageNocem, "bi", "subj", sf.StageLLM}
			quota := *n / len(classes)
			have := map[string]int{}
			seen := map[string]bool{}
			for draws := 0; draws < 50 && len(rows) < quota*len(classes); draws++ {
				rs, err := st.SampleSpam(10000, "", rng.Int64N)
				if err != nil {
					return err
				}
				for _, r := range rs {
					c := auditClass(r.Stage, r.Reason)
					if seen[r.MsgID] || have[c] >= quota {
						continue
					}
					seen[r.MsgID] = true
					have[c]++
					rows = append(rows, r)
				}
			}
			log.Printf("audit: sampled %s", formatCountsInt(have))
		}
	}
	kindFlagged, kindClean := "flagged", "clean"
	if *tag != "" {
		kindFlagged, kindClean = "flagged-"+*tag, "clean-"+*tag
	}
	if err := auditRun(ctx, st, f, &lf, kindFlagged, "ham,unsure", len(rows), func(i int) (sf.AuditRow, sf.Article) {
		r := rows[i]
		return sf.AuditRow{MsgID: r.MsgID, Kind: kindFlagged, Group: r.Group, ArtNum: r.ArtNum, Stage: r.Stage, Reason: r.Reason},
			sf.Article{MsgID: r.MsgID, Key: r.Key}
	}); err != nil {
		return err
	}

	// clean: a random pick of the ham the unsure pass kept
	if *cleanN > 0 && ctx.Err() == nil {
		var clean []sf.Candidate
		seenN := 0
		err := sf.ReadCandidates(*candDir, func(_ int, c sf.Candidate) error {
			if c.Kind != sf.CandClean {
				return nil
			}
			seenN++ // reservoir sample
			if len(clean) < *cleanN {
				clean = append(clean, c)
			} else if j := rng.IntN(seenN); j < *cleanN {
				clean[j] = c
			}
			return nil
		})
		if err != nil {
			return err
		}
		log.Printf("audit: %d clean articles picked of %d kept", len(clean), seenN)
		if err := auditRun(ctx, st, f, &lf, kindClean, "spam,unsure", len(clean), func(i int) (sf.AuditRow, sf.Article) {
			c := clean[i]
			g, _, _ := strings.Cut(c.Source, ":")
			return sf.AuditRow{MsgID: c.MsgID, Kind: kindClean, Group: g, ArtNum: artNumber(c.Source), Reason: fmt.Sprintf("z=%.2f", c.Logit)}, c.Article
		}); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		log.Printf("audit: stopped; results so far are saved")
	}
	return auditReport(st, *tag)
}

// auditRun fetches and labels n articles, item(i) giving the audit row and
// the article to start from (the overview article, or only Message-ID and
// key), and stores the results. escOn are the first-pass labels the
// stronger model checks again: those that disagree with the scan.
func auditRun(ctx context.Context, st *sf.Store, f *fetcher, lf *labelFlags, kind, escOn string, n int,
	item func(i int) (sf.AuditRow, sf.Article)) error {
	if n == 0 {
		return nil
	}
	l := *lf
	l.escOn = escOn
	lab, err := l.labeler(st)
	if err != nil {
		return err
	}
	const block = 2000
	var done int
	for b := 0; b < n && ctx.Err() == nil && lab.spent < l.budget; b += block {
		e := min(b+block, n)
		rows := make([]sf.AuditRow, e-b)
		base := make([]sf.Article, e-b)
		items := make([]fetchItem, e-b)
		for i := range rows {
			rows[i], base[i] = item(b + i)
			items[i] = fetchItem{rows[i].Group, rows[i].ArtNum}
		}
		var out []sf.AuditRow
		_, err := f.fetch(items, func(i int, head, body []string) {
			var a sf.Article
			if base[i].Source != "" { // an overview article
				var ok bool
				if a, ok = withBody(base[i], head, body); !ok {
					return
				}
			} else {
				a = sf.NewArticle(head, body, -1)
				if a.MsgID != base[i].MsgID {
					return
				}
				a.Key = base[i].Key
			}
			lab.add(a, func(v sf.Verdict) {
				r := rows[i]
				r.Label, r.Why, r.Model = v.Label, v.Reason, v.Model
				out = append(out, r)
			})
		})
		if err != nil {
			return err
		}
		if err := lab.flush(ctx); err != nil {
			return err
		}
		if err := st.AddAudit(out); err != nil {
			return err
		}
		done += len(out)
		log.Printf("audit: %s: %d of %d checked, $%.2f in all", kind, done, n, lab.spent)
	}
	return nil
}

func auditReport(st *sf.Store, tag string) error {
	kindFlagged, kindClean := "flagged", "clean"
	if tag != "" {
		kindFlagged, kindClean = "flagged-"+tag, "clean-"+tag
	}
	type cnt struct{ n, spam, ham, unsure int }
	by := map[string]*cnt{}
	hier := map[string]*cnt{}
	add := func(m map[string]*cnt, k, label string) {
		c := m[k]
		if c == nil {
			c = &cnt{}
			m[k] = c
		}
		c.n++
		switch label {
		case sf.Spam:
			c.spam++
		case sf.Ham:
			c.ham++
		default:
			c.unsure++
		}
	}
	err := st.EachAudit(func(r sf.AuditRow) error {
		if r.Kind != kindFlagged && r.Kind != kindClean {
			return nil
		}
		k := "clean"
		if r.Kind == kindFlagged {
			k = "flagged/" + auditClass(r.Stage, r.Reason)
			add(hier, auditClass(r.Stage, r.Reason)+" "+sf.Hierarchy(r.Group), r.Label)
		}
		add(by, k, r.Label)
		return nil
	})
	if err != nil {
		return err
	}
	if len(by) == 0 {
		fmt.Println("no spot checks stored")
		return nil
	}
	pr := func(m map[string]*cnt, minN int) {
		var ks []string
		for k, c := range m {
			if c.n >= minN {
				ks = append(ks, k)
			}
		}
		sort.Slice(ks, func(i, j int) bool { return m[ks[i]].n > m[ks[j]].n })
		for _, k := range ks {
			c := m[k]
			p := func(x int) float64 { return 100 * float64(x) / float64(c.n) }
			fmt.Printf("  %-28s %6d  spam %5.1f%%  ham %5.1f%%  unsure %5.1f%%\n", k, c.n, p(c.spam), p(c.ham), p(c.unsure))
		}
	}
	fmt.Println("spot checks: the model API's label (with the body) for what the scan decided")
	pr(by, 1)
	fmt.Println("flagged, by what flagged it and hierarchy (100+ checked):")
	pr(hier, 100)
	return nil
}

func formatCountsInt(m map[string]int) string {
	m64 := map[string]int64{}
	for k, v := range m {
		m64[k] = int64(v)
	}
	return formatCounts64(m64)
}

// ---- rescore: how a model decides the candidates

func rescore(args []string) error {
	fs := flag.NewFlagSet("rescore", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database (for the default paths)")
	candDir := fs.String("cand-dir", "", "candidate files of run -mode unsure (default: the database path + \".unsure\")")
	modelPath := fs.String("model-file", "spamfilter.model", "local model")
	fs.Parse(args)
	if *candDir == "" {
		*candDir = *dbPath + ".unsure"
	}
	m, err := sf.LoadModel(*modelPath)
	if err != nil {
		return err
	}
	type cnt struct{ n, spam, ham, unsure int64 }
	by := map[string]*cnt{}
	seen := map[candKey]bool{}
	err = sf.ReadCandidates(*candDir, func(_ int, c sf.Candidate) error {
		if ck, ok := toCandKey(c.Key); ok {
			if seen[ck] {
				return nil
			}
			seen[ck] = true
		}
		k := map[string]string{sf.CandUnsure: "uncertain before", sf.CandClean: "ham before"}[c.Kind]
		x := by[k]
		if x == nil {
			x = &cnt{}
			by[k] = x
		}
		x.n++
		switch label, _ := m.Decide(c.Article); label {
		case sf.Spam:
			x.spam++
		case sf.Ham:
			x.ham++
		default:
			x.unsure++
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s (trained on %d), one candidate per key:\n", filepath.Base(*modelPath), m.Trained)
	for _, k := range []string{"uncertain before", "ham before"} {
		if x := by[k]; x != nil {
			p := func(v int64) float64 { return 100 * float64(v) / float64(x.n) }
			fmt.Printf("  %-17s %10d  now spam %5.1f%%  ham %5.1f%%  uncertain %5.1f%%\n", k, x.n, p(x.spam), p(x.ham), p(x.unsure))
		}
	}
	return nil
}

// ---- label-flagged: label one copy of each flagged key

func labelFlagged(args []string) error {
	fs := flag.NewFlagSet("label-flagged", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database")
	server := fs.String("server", "", "news server, HOST:PORT")
	class := fs.String("class", "bi", "which flags: bi (Breidbart copies), subj, model or nocem")
	maxN := fs.Int("max", 0, "label at most this many keys, the most-flagged first (0 = all)")
	block := fs.Int("block", 4000, "articles fetched and labelled at a time")
	maxMbit := fs.Float64("max-mbit", 100, "cap on the download from the news server (0 = none)")
	timeout := fs.Duration("timeout", 2*time.Minute, "network timeout")
	compress := fs.Bool("compress", true, "COMPRESS DEFLATE when the server offers it")
	dry := fs.Bool("dry", false, "only report how many keys and the estimated cost")
	var lf labelFlags
	lf.register(fs, "", "")
	fs.Parse(args)
	st, err := sf.OpenStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	known, err := st.VerdictKeys()
	if err != nil {
		return err
	}
	held, err := st.AuditKeys()
	if err != nil {
		return err
	}
	// one row per key (the first), with the number of flagged copies
	type pick struct {
		row    sf.SpamRow
		copies int
	}
	byKey := map[string]*pick{}
	t0 := time.Now()
	var rows int64
	err = st.EachSpam(func(r sf.SpamRow) error {
		if auditClass(r.Stage, r.Reason) != *class {
			return nil
		}
		rows++
		if known[r.Key] || held[r.Key] {
			return nil
		}
		if p := byKey[r.Key]; p != nil {
			p.copies++
		} else {
			byKey[r.Key] = &pick{r, 1}
		}
		return nil
	})
	if err != nil {
		return err
	}
	picks := make([]*pick, 0, len(byKey))
	var copies int64
	for _, p := range byKey {
		picks = append(picks, p)
		copies += int64(p.copies)
	}
	byKey = nil
	sort.Slice(picks, func(i, j int) bool { return picks[i].copies > picks[j].copies })
	if *maxN > 0 && len(picks) > *maxN {
		picks = picks[:*maxN]
	}
	const perItem = 0.029 / 1000
	log.Printf("label-flagged: %d %s rows; %d keys without a label cover %d of them; labelling %d keys, about $%.2f (%s)",
		rows, *class, len(picks), copies, len(picks), float64(len(picks))*perItem, time.Since(t0).Round(time.Second))
	if *dry || len(picks) == 0 {
		return nil
	}
	if *server == "" {
		return errors.New("need -server HOST:PORT")
	}
	lab, err := lf.labeler(st)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	f := &fetcher{server: *server, timeout: *timeout, limit: sf.NewLimiter(*maxMbit), compress: *compress}
	defer f.drop()
	counts := map[string]int64{}
	var labelledCopies int64
	start := time.Now()
	for b := 0; b < len(picks) && ctx.Err() == nil && lab.spent < lf.budget; b += *block {
		part := picks[b:min(b+*block, len(picks))]
		items := make([]fetchItem, len(part))
		for i, p := range part {
			items[i] = fetchItem{p.row.Group, p.row.ArtNum}
		}
		miss, err := f.fetch(items, func(i int, head, body []string) {
			a := sf.NewArticle(head, body, -1)
			if a.MsgID != part[i].row.MsgID {
				return
			}
			a.Key = part[i].row.Key // the overview key the scan looks up
			n := int64(part[i].copies)
			lab.add(a, func(v sf.Verdict) {
				counts[v.Label]++
				if v.Label == sf.Ham {
					labelledCopies += n
				}
			})
		})
		if err != nil {
			return err
		}
		if err := lab.flush(ctx); err != nil {
			return err
		}
		log.Printf("label-flagged: %d of %d keys labelled (spam %d, ham %d covering %d flagged copies, unsure %d), %d not fetched; $%.2f this run; %s",
			lab.labelled, len(picks), counts[sf.Spam], counts[sf.Ham], labelledCopies, counts[sf.Unsure], miss, lab.own,
			time.Since(start).Round(time.Second))
	}
	return nil
}
