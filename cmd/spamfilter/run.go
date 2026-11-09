package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"log"
	"math"
	"math/rand/v2"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

// ---- run: the automated pipeline against a news server

type runOpts struct {
	server, dbPath, mode, modelPath  string
	groups                           string
	chunk                            int64
	sampleRate                       float64
	sampleMin, sampleMax, sampleWant int64
	sampleWindows                    int64
	retrainEvery                     int64
	budget                           float64
	llm                              bool
	seed                             uint64
	timeout                          time.Duration
	biDir                            string
	bi                               bool
	nocemTypes                       string
	nocemKeep                        int64
	nocemMax                         int
	conns                            int
	maxMbit                          float64
	biAll                            bool
	compress                         bool
	nocemSkip                        string
	holdOut                          bool
	useBI                            bool
	share                            float64
	salt                             uint64
	candDir                          string
	hamEvery                         int64
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var o runOpts
	fs.StringVar(&o.server, "server", "", "news server, HOST:PORT")
	fs.StringVar(&o.dbPath, "db", "spamfilter.db", "SQLite database (created if missing)")
	fs.StringVar(&o.mode, "mode", "sample", "sample: label a random slice of every group with the model API (training data); full: scan everything; bi: rescan and flag the copies of what the bi command found; unsure: read -share of the chunks and keep what the local model can't decide, for label-unsure")
	fs.StringVar(&o.modelPath, "model-file", "spamfilter.model", "local model (from train), used by -mode full")
	fs.StringVar(&o.groups, "groups", "*,!control,!control.*,!junk,!to.*", "groups to process, wildmat list: comma-separated patterns, ! excludes, the last match wins")
	fs.Int64Var(&o.chunk, "chunk", 200000, "articles per OVER command")
	fs.Float64Var(&o.sampleRate, "sample-rate", 1.0/5000, "sample mode: share of a group's articles to fetch, as one contiguous window at a random place")
	fs.Int64Var(&o.sampleMin, "sample-min", 20, "sample mode: fetch at least this many articles of a group")
	fs.Int64Var(&o.sampleMax, "sample-max", 5000, "sample mode: fetch at most this many articles of a group")
	fs.Int64Var(&o.sampleWant, "sample-target", 200000, "sample mode: stop when this many items are labelled")
	fs.Int64Var(&o.sampleWindows, "sample-windows", 4, "sample mode: split a group's sample into this many windows at random places, so every era of the group is seen")
	fs.Int64Var(&o.retrainEvery, "retrain-every", 20000, "full mode: retrain the local model each time this many new items were labelled by the API (0 = never)")
	fs.Float64Var(&o.budget, "budget", 5, "stop sending to the model API once this many dollars (list price) are spent in this database, all runs together")
	fs.BoolVar(&o.llm, "llm", true, "full mode: send articles the local model is unsure about to the model API, within the budget")
	fs.Uint64Var(&o.seed, "seed", uint64(time.Now().UnixNano()), "random seed (group order, sample windows)")
	fs.DurationVar(&o.timeout, "timeout", 5*time.Minute, "network timeout")
	fs.StringVar(&o.biDir, "bi-dir", "", "directory for the Breidbart counts (default: the database path + \".bi\")")
	fs.StringVar(&o.nocemTypes, "nocem-types", strings.Join(sf.DefaultNocemTypes, ","), "full mode: NoCeM notice types whose Message-IDs are spam (\"\" = don't use NoCeM)")
	fs.Int64Var(&o.nocemKeep, "nocem-keep", 200, "full mode: keep the overview headers of one NoCeM-listed posting in this many (by From+Subject) as a training example")
	fs.IntVar(&o.nocemMax, "nocem-max", 150000, "at most this many NoCeM examples when retraining")
	fs.Float64Var(&o.maxMbit, "max-mbit", 0, "cap the download from the server at this many megabits per second, all connections together (0 = no cap)")
	fs.StringVar(&o.nocemSkip, "nocem-skip", strings.Join(sf.DefaultNocemSkip, ","), "NoCeM issuers whose listings are ignored (\"\" = none)")
	fs.BoolVar(&o.holdOut, "hold-out-audit", true, "full mode: don't use the labels of spot-checked articles (audit), so the spot checks stay a fair test")
	fs.BoolVar(&o.useBI, "use-bi", false, "full mode: also flag the copies of the keys the bi command found (as run -mode bi does), unless the article is ham by its label or the local model; use with -bi=false")
	fs.BoolVar(&o.compress, "compress", true, "COMPRESS DEFLATE (RFC 8054) on every server connection, when the server offers it")
	fs.BoolVar(&o.biAll, "bi-all", false, "bi mode: read every chunk, not only those the bi command listed")
	fs.IntVar(&o.conns, "conns", 1, "full, bi and unsure mode: groups scanned at once, each on its own server connection")
	fs.Float64Var(&o.share, "share", 0.1, "unsure mode: share of the chunks to read, picked by hash, the same on every run")
	fs.Uint64Var(&o.salt, "salt", 0, "unsure mode: another value picks other chunks (progress is kept per salt; use another -cand-dir)")
	fs.StringVar(&o.candDir, "cand-dir", "", "unsure mode: directory for the candidate files (default: the database path + \".unsure\")")
	fs.Int64Var(&o.hamEvery, "ham-every", 10000, "unsure mode: also keep one article in this many that the scan judges ham, for spot checks (0 = none)")
	fs.BoolVar(&o.bi, "bi", true, "full mode: record Breidbart counts for the corpus-wide index (see the bi command)")
	model := fs.String("model", "claude-haiku-5-5", "model for the first pass")
	effort := fs.String("effort", "low", "effort for the first pass")
	thinking := fs.Bool("thinking", false, "let the first-pass model think (more output tokens; no accuracy gain measured on a 347-item test)")
	escalate := fs.String("escalate", "claude-sonnet-5-5", "model for what the first pass labels with an -escalate-on label (\"\" = none)")
	escOn := fs.String("escalate-on", "unsure", "first-pass labels to escalate, comma-separated (unanswered items always go)")
	batch := fs.Int("batch", 50, "articles per API request")
	conc := fs.Int("concurrency", 4, "API requests in flight")
	keyFile := fs.String("key-file", "/dev/shm/spamfilter_apikey.txt", "file holding the API key (else ANTHROPIC_API_KEY)")
	fs.Parse(args)
	if o.server == "" {
		return errors.New("need -server HOST:PORT")
	}
	if o.mode != "sample" && o.mode != "full" && o.mode != "bi" && o.mode != "unsure" {
		return fmt.Errorf("-mode is sample, full, bi or unsure, not %q", o.mode)
	}
	if o.biDir == "" {
		o.biDir = o.dbPath + ".bi"
	}
	if o.candDir == "" {
		o.candDir = o.dbPath + ".unsure"
	}
	match, err := wildmat(o.groups)
	if err != nil {
		return err
	}
	st, err := sf.OpenStore(o.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	st.NocemSkip = splitList(o.nocemSkip)

	var lab *labeler
	if o.mode == "sample" || o.mode == "full" && o.llm {
		opts := []option.RequestOption{option.WithMaxRetries(5)}
		if key, err := readKey(*keyFile); err == nil {
			opts = append(opts, option.WithAPIKey(key))
		} else if os.Getenv("ANTHROPIC_API_KEY") == "" {
			return fmt.Errorf("no API key: %v, and ANTHROPIC_API_KEY is not set", err)
		}
		client := anthropic.NewClient(opts...)
		lab = &labeler{st: st, budget: o.budget, batch: *batch * *conc, escOn: map[string]bool{"": true}}
		lab.first = &sf.LLM{Client: client, Model: *model, Effort: *effort, BatchSize: *batch, Concurrency: *conc, NoThinking: !*thinking}
		if *escalate != "" && *escalate != *model {
			lab.second = &sf.LLM{Client: client, Model: *escalate, Effort: "low", BatchSize: *batch, Concurrency: *conc}
		}
		for _, l := range strings.Split(*escOn, ",") {
			lab.escOn[strings.TrimSpace(l)] = true
		}
		if lab.spent, err = st.Spent(); err != nil {
			return err
		}
	}
	var m *sf.Model
	var biw *sf.BIWriter
	var biKeys map[uint64]float32
	var biChunks map[uint32]bool
	if o.mode == "full" && o.bi {
		if biw, err = sf.OpenBIWriter(o.biDir); err != nil {
			return err
		}
		defer biw.Close()
	}
	if o.mode == "bi" || o.mode == "full" && o.useBI {
		if biKeys, err = sf.LoadBIKeys(filepath.Join(o.biDir, biKeysFile)); err != nil {
			return fmt.Errorf("bi mode needs the bi command's result: %w", err)
		}
		log.Printf("run: %d keys at or above the Breidbart threshold", len(biKeys))
		if !o.biAll && o.mode == "bi" {
			if biChunks, err = sf.LoadBIChunks(filepath.Join(o.biDir, biChunksFile)); err != nil {
				return fmt.Errorf("%w (run the bi command again, or use -bi-all)", err)
			}
			log.Printf("run: reading only the %d chunks that hold copies of them (same -chunk as the full scan)", len(biChunks))
		}
	}
	var cw *sf.CandWriter
	if o.mode == "unsure" {
		if cw, err = sf.OpenCandWriter(o.candDir); err != nil {
			return err
		}
		defer func() {
			if err := cw.Close(); err != nil {
				log.Printf("run: closing the candidate file: %v", err)
			}
		}()
	}
	if o.mode == "full" || o.mode == "unsure" {
		if m, err = sf.LoadModel(o.modelPath); err != nil {
			return fmt.Errorf("%s mode needs a trained model: %w", o.mode, err)
		}
		log.Printf("run: model %s: trained on %d, spam at logit>=%.2f, ham at logit<=%.2f", o.modelPath, m.Trained, m.SpamAt, m.HamAt)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	limit := sf.NewLimiter(o.maxMbit)
	c, err := sf.DialNNTPLimited(o.server, o.timeout, limit)
	if err != nil {
		return err
	}
	defer c.Quit()
	c.ModeReader()
	if err := compressOn(c, o.compress); err != nil {
		return err
	}
	log.Printf("run: COMPRESS DEFLATE %v", c.Compressed())
	format, err := c.OverviewFormat()
	if err != nil {
		return err
	}
	ov, err := sf.NewOverview(format)
	if err != nil {
		return err
	}
	active, err := c.ListActive()
	if err != nil {
		return err
	}
	var groups []sf.ActiveGroup
	for _, g := range active {
		if g.Status == "j" || strings.HasPrefix(g.Status, "=") || !match(g.Name) {
			continue
		}
		groups = append(groups, g)
		if err := st.SetGroupRange(g.Name, g.Low, g.High); err != nil {
			return err
		}
	}
	log.Printf("run: %d groups in LIST ACTIVE, %d selected by -groups", len(active), len(groups))
	var nocem sf.IDSet
	if (o.mode == "full" || o.mode == "unsure") && o.nocemTypes != "" {
		if nocem, err = sf.LoadNocemSet(st, splitList(o.nocemTypes)); err != nil {
			return err
		}
		log.Printf("run: %d Message-IDs listed as spam in NoCeM notices (%s)", len(nocem), o.nocemTypes)
	}
	var verdicts map[string]sf.Verdict
	var heldOut map[string]bool
	if o.mode == "full" || o.mode == "unsure" {
		if o.holdOut {
			if heldOut, err = st.AuditKeys(); err != nil {
				return err
			}
		}
		if verdicts, err = st.VerdictLabels(); err != nil {
			return err
		}
		for k := range heldOut {
			delete(verdicts, k)
		}
		log.Printf("run: %d labels decide their keys first (%d spot-checked keys held out)", len(verdicts), len(heldOut))
	}
	r := &runner{o: o, c: c, verdicts: verdicts, heldOut: heldOut, limit: limit, biChunks: biChunks, ov: ov, st: st, lab: lab, model: m, match: match, biw: biw, biKeys: biKeys, nocem: nocem, cw: cw,
		rng: rand.New(rand.NewPCG(o.seed, o.seed^0x2545f4914f6cdd1d)), rules: sf.DefaultRules}
	switch o.mode {
	case "sample":
		err = r.sample(ctx, groups)
	case "full":
		err = r.full(ctx, groups)
	case "bi":
		err = r.biPass(ctx, groups)
	case "unsure":
		err = r.unsurePass(ctx, groups)
	}
	if lab != nil {
		if ferr := lab.flush(ctx); err == nil {
			err = ferr
		}
	}
	if errors.Is(err, context.Canceled) {
		log.Printf("run: stopped; progress is saved, run again to continue")
		err = nil
	}
	g, sampled, nVerdicts, spam, _ := st.Counts()
	spent, _ := st.Spent()
	log.Printf("run: database: %d groups (%d sampled), %d labelled items, %d spam Message-IDs; API spend $%.2f of $%.2f budget",
		g, sampled, nVerdicts, spam, spent, o.budget)
	return err
}

type runner struct {
	o        runOpts
	c        *sf.NNTP
	ov       *sf.Overview
	st       *sf.Store
	lab      *labeler
	model    *sf.Model
	match    func(string) bool
	rng      *rand.Rand
	rules    sf.Rules
	biw      *sf.BIWriter          // full mode: Breidbart counts, pass 1
	biKeys   map[uint64]float32    // bi mode: keys at or above the threshold
	biChunks map[uint32]bool       // bi mode: the chunks holding their copies (nil = read all)
	nocem    sf.IDSet              // full mode: Message-IDs NoCeM issuers listed as spam
	cw       *sf.CandWriter        // unsure mode: where the candidates go
	verdicts map[string]sf.Verdict // full mode: the API labels (spam, ham) by key, read-only during the scan
	heldOut  map[string]bool       // keys of spot-checked articles: their labels are not used
	// mu serializes what follows the scoring of a chunk (database writes,
	// API labels, Breidbart counts, totals, retraining) when several
	// connections scan at once
	limit   *sf.Limiter // shared by all connections
	mu      sync.Mutex
	modelMu sync.Mutex // guards the model pointer: scoring must not wait for an API call under mu
}

// eachGroup calls fn for every group, on -conns connections at once (the
// first is r.c). The first error stops the others.
func (r *runner) eachGroup(ctx context.Context, groups []sf.ActiveGroup, fn func(ctx context.Context, c *sf.NNTP, ag sf.ActiveGroup) error) error {
	clients := []*sf.NNTP{r.c}
	for len(clients) < max(1, r.o.conns) {
		c, err := sf.DialNNTPLimited(r.o.server, r.o.timeout, r.limit)
		if err != nil {
			return fmt.Errorf("connection %d: %w", len(clients)+1, err)
		}
		defer c.Quit()
		c.ModeReader()
		if err := compressOn(c, r.o.compress); err != nil {
			return fmt.Errorf("connection %d: %w", len(clients)+1, err)
		}
		clients = append(clients, c)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	todo := make(chan sf.ActiveGroup)
	var (
		wg       sync.WaitGroup
		errMu    sync.Mutex
		firstErr error
	)
	for _, c := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ag := range todo {
				if err := fn(ctx, c, ag); err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
					cancel()
				}
			}
		}()
	}
feed:
	for _, ag := range groups {
		select {
		case todo <- ag:
		case <-ctx.Done():
			break feed
		}
	}
	close(todo)
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

// home is the group an article is processed in: the first group of its
// Xref that -groups selects. Its copies in other groups are skipped, so a
// crosspost counts once without keeping every Message-ID.
func (r *runner) home(a sf.Article) string {
	for _, g := range strings.Split(a.Newsgroups, ",") {
		if r.match(g) {
			return g
		}
	}
	return ""
}

func (r *runner) sample(ctx context.Context, groups []sf.ActiveGroup) error {
	r.rng.Shuffle(len(groups), func(i, j int) { groups[i], groups[j] = groups[j], groups[i] })
	queued := map[string]bool{}
	start := time.Now()
	var done, fetched int
	for _, ag := range groups {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		verdicts, err := r.st.VerdictCount()
		if err != nil {
			return err
		}
		if verdicts >= r.o.sampleWant {
			log.Printf("sample: %d items labelled, target reached", verdicts)
			return nil
		}
		if r.lab.spent >= r.o.budget {
			log.Printf("sample: budget of $%.2f reached", r.o.budget)
			return nil
		}
		gs, _, err := r.st.Group(ag.Name)
		if err != nil {
			return err
		}
		if gs.Sampled {
			continue
		}
		_, low, high, err := r.c.Group(ag.Name)
		if err != nil {
			log.Printf("sample: %v", err)
			continue
		}
		if n := high - low + 1; high >= low && n > 0 {
			want := min(max(int64(float64(n)*r.o.sampleRate), r.o.sampleMin), r.o.sampleMax, n)
			windows := max(min(r.o.sampleWindows, want/10), 1) // windows of at least 10 articles
			size := want / windows
			for w := int64(0); w < windows; w++ {
				// window w lies in the w-th part of the group's range
				part := n / windows
				from := low + w*part
				if part > size {
					from += r.rng.Int64N(part - size + 1)
				}
				err := r.c.OverFunc(from, from+size-1, func(line string) error {
					a, err := r.ov.Parse(line, ag.Name)
					if err != nil || r.home(a) != ag.Name || queued[a.Key] {
						return nil
					}
					fetched++
					if ok, err := r.st.HasVerdict(a.Key); err != nil || ok {
						return err
					}
					queued[a.Key] = true
					r.lab.add(a, nil)
					return nil
				})
				if err != nil {
					return fmt.Errorf("%s: %w", ag.Name, err)
				}
			}
			if err := r.lab.flushIfFull(ctx); err != nil {
				return err
			}
		}
		if err := r.st.GroupSampled(ag.Name); err != nil {
			return err
		}
		if done++; done%200 == 0 {
			log.Printf("sample: %d groups, %d articles fetched, $%.2f spent, %s", done, fetched, r.lab.spent, time.Since(start).Round(time.Second))
		}
	}
	return nil
}

func (r *runner) full(ctx context.Context, groups []sf.ActiveGroup) error {
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	start := time.Now()
	var trainedAt int64 // r.labels() when last trained
	var tot struct{ lines, home, spam, ham, uncertain int64 }
	return r.eachGroup(ctx, groups, func(ctx context.Context, c *sf.NNTP, ag sf.ActiveGroup) error {
		if r.o.retrainEvery > 0 {
			r.mu.Lock()
			var err error
			if labelled := r.labels(); labelled-trainedAt >= r.o.retrainEvery {
				trainedAt = labelled
				err = r.retrain()
			}
			r.mu.Unlock()
			if err != nil {
				return err
			}
		}
		gs, _, err := r.st.Group(ag.Name)
		if err != nil {
			return err
		}
		if gs.Done >= ag.High {
			return nil
		}
		_, low, high, err := c.Group(ag.Name)
		if err != nil {
			log.Printf("full: %v", err)
			return nil
		}
		from := max(low, gs.Done+1)
		for a0 := from; a0 <= high; a0 += r.o.chunk {
			b := min(a0+r.o.chunk-1, high)
			t0 := time.Now()
			res, err := r.scoreChunk(c, ag.Name, a0, b)
			if err != nil {
				return fmt.Errorf("%s %d-%d: %w", ag.Name, a0, b, err)
			}
			r.mu.Lock()
			err = r.commitChunk(ctx, ag.Name, a0, b, res, func(lines, nHome, nSpam int64) {
				tot.ham += res.ham
				tot.uncertain += int64(len(res.uncertain))
				tot.lines += lines
				tot.home += nHome
				tot.spam += nSpam
				el := time.Since(t0).Seconds()
				log.Printf("full: %s %d-%d: %d lines, %d home, %d spam (%.0f lines/s); total %d lines, %d spam, %d uncertain, $%.2f, %.1f GB down (%.1f GB of overview text), %s",
					ag.Name, a0, b, lines, nHome, nSpam, float64(lines)/max(el, 0.001), tot.lines, tot.spam, tot.uncertain,
					r.labSpent(), float64(sf.WireBytes.Load())/1e9, float64(sf.TextBytes.Load())/1e9, time.Since(start).Round(time.Second))
			})
			r.mu.Unlock()
			if err != nil {
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		return nil
	})
}

// commitChunk stores what scoring one chunk found: it looks up or asks for
// the uncertain items, records Breidbart counts and NoCeM examples, writes
// the spam and the group's progress, then calls report. Callers hold r.mu.
func (r *runner) commitChunk(ctx context.Context, group string, a0, b int64, res chunkResult, report func(lines, nHome, nSpam int64)) error {
	spam := res.spam
	// an item labelled before (sample, earlier chunks) is not sent
	// again; the copies of one item in this chunk go as one
	byKey := map[string][]sf.Article{}
	var keys []string
	for _, a := range res.uncertain {
		if _, seen := byKey[a.Key]; !seen {
			keys = append(keys, a.Key)
		}
		byKey[a.Key] = append(byKey[a.Key], a)
	}
	var known int
	for _, k := range keys {
		copies := byKey[k]
		var v sf.Verdict
		var ok bool
		if !r.heldOut[k] { // labels given during this run
			var err error
			if v, ok, err = r.st.Verdict(k); err != nil {
				return err
			}
		}
		if ok {
			known++
			if v.Label == sf.Spam {
				for _, a := range copies {
					spam = append(spam, spamRow(a, group, v.Stage, v.Reason))
				}
			}
			continue
		}
		if r.lab != nil && r.lab.spent < r.o.budget {
			r.lab.add(copies[0], func(v sf.Verdict) {
				if v.Label == sf.Spam {
					for _, a := range copies {
						spam = append(spam, spamRow(a, group, v.Stage, v.Reason))
					}
				}
			})
		}
	}
	if r.lab != nil {
		if err := r.lab.flush(ctx); err != nil {
			return err
		}
	}
	if known > 0 {
		log.Printf("full: %s: %d uncertain items had a stored verdict, not sent again", group, known)
	}
	if r.biw != nil {
		if err := r.biw.Add(sf.ChunkID(group, a0), res.bi); err != nil {
			return err
		}
	}
	if keep := keepNocem(res.nocem, r.o.nocemKeep); len(keep) > 0 {
		// the overview headers of NoCeM-listed spam are free training
		// examples; a slice of them is plenty (tens of millions are listed)
		vs := make([]sf.Verdict, len(keep))
		for i, a := range keep {
			vs[i] = sf.Verdict{Key: a.Key, Label: sf.Spam, Stage: sf.StageNocem, Reason: "nocem"}
		}
		if err := r.st.PutVerdicts(keep, vs); err != nil {
			return err
		}
	}
	nSpam := int64(len(spam))
	if err := r.st.AddSpam(spam); err != nil {
		return err
	}
	if err := r.st.GroupProgress(group, b, res.home, nSpam); err != nil {
		return err
	}
	report(res.lines, res.home, nSpam)
	return nil
}

// judgement is what the full scan decides an article by.
type judgement struct {
	verdict func(key string) (sf.Verdict, bool) // labels of the model API (nil = none)
	nocem   func(msgid string) bool
	rules   sf.Rules
	model   *sf.Model
	bi      func(a sf.Article) (float32, bool) // Breidbart index at or above the threshold (nil = none)
}

// judge decides one article: a label of the model API (it saw more than
// the headers), the NoCeM listing, the subject rules, then the local
// model; a copy of a key at or above the Breidbart threshold is spam
// unless the model calls it ham (jobs, tests, weather reports and feeds
// repeat without being spam). label is spam, ham or "" (uncertain); for
// the model, reason is its spam probability.
func (j judgement) judge(a sf.Article) (label, stage, reason string) {
	if j.verdict != nil {
		if v, ok := j.verdict(a.Key); ok {
			return v.Label, v.Stage, v.Reason
		}
	}
	if j.nocem != nil && j.nocem(a.MsgID) {
		return sf.Spam, sf.StageNocem, "nocem"
	}
	if v, ok := j.rules.Decide(a, 0); ok {
		return v.Label, v.Stage, v.Reason
	}
	label, p := j.model.Decide(a)
	if label != sf.Ham && j.bi != nil {
		if bi, ok := j.bi(a); ok {
			return sf.Spam, sf.StageRules, fmt.Sprintf("bi=%.1f", bi)
		}
	}
	return label, sf.StageModel, fmt.Sprintf("p=%.3f", p)
}

// judge is the judgement without labels and Breidbart index (web view).
func judge(a sf.Article, nocem func(msgid string) bool, rules sf.Rules, m *sf.Model) (label, stage, reason string) {
	return judgement{nocem: nocem, rules: rules, model: m}.judge(a)
}

// judgement returns the scan's judgement with the current model.
func (r *runner) judgement(m *sf.Model) judgement {
	j := judgement{nocem: r.nocemHas, rules: r.rules, model: m}
	if r.verdicts != nil {
		j.verdict = func(k string) (sf.Verdict, bool) { v, ok := r.verdicts[k]; return v, ok }
	}
	if r.biKeys != nil && r.o.mode == "full" {
		j.bi = func(a sf.Article) (float32, bool) {
			k, counted := sf.BIKey(a, r.rules.MinLines)
			bi, ok := r.biKeys[k]
			return bi, counted && ok
		}
	}
	return j
}

func (r *runner) nocemHas(msgid string) bool { return r.nocem != nil && r.nocem.Has(msgid) }

type chunkResult struct {
	lines, home, ham int64
	spam             []sf.SpamRow
	uncertain        []sf.Article
	bi               map[uint64]float32 // Breidbart key -> sum of sqrt(groups)
	nocem            []sf.Article       // articles NoCeM listed as spam: training examples
	cands            []sf.Candidate     // unsure mode: the uncertain items and a sample of the ham
}

// scoreChunk streams one OVER range and judges the articles on all cores:
// the read loop only hands lines to the workers, which parse, apply the
// rules and score with the local model.
func (r *runner) scoreChunk(c *sf.NNTP, group string, a0, b int64) (chunkResult, error) {
	var (
		res chunkResult
		mu  sync.Mutex
		wg  sync.WaitGroup
		in  = make(chan string, 8192)
	)
	r.modelMu.Lock()
	model := r.model // retraining may swap it while this chunk runs
	r.modelMu.Unlock()
	jd := r.judgement(model)
	for range runtime.NumCPU() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			loc := chunkResult{bi: map[uint64]float32{}}
			for line := range in {
				a, err := r.ov.Parse(line, group)
				if err != nil || a.MsgID == "" || r.home(a) != group {
					continue
				}
				loc.home++
				k, counted := sf.BIKey(a, r.rules.MinLines)
				if r.o.mode == "bi" { // only the Breidbart index decides
					if bi, ok := r.biKeys[k]; counted && ok {
						loc.spam = append(loc.spam, spamRow(a, group, sf.StageRules, fmt.Sprintf("bi=%.1f", bi)))
					}
					continue
				}
				if counted && r.biw != nil {
					loc.bi[k] += float32(math.Sqrt(float64(max(a.Groups, 1))))
				}
				switch label, stage, reason := jd.judge(a); {
				case stage == sf.StageNocem:
					loc.spam = append(loc.spam, spamRow(a, group, stage, reason))
					loc.nocem = append(loc.nocem, a)
				case label == sf.Spam:
					loc.spam = append(loc.spam, spamRow(a, group, stage, reason))
				case label == sf.Ham:
					loc.ham++
					if r.cw != nil && r.o.hamEvery > 0 && keyHash(a.Key)%uint64(r.o.hamEvery) == 0 {
						loc.cands = append(loc.cands, sf.Candidate{Article: a, Logit: float32(model.Logit(a)), Kind: sf.CandClean})
					}
				case r.cw != nil:
					loc.cands = append(loc.cands, sf.Candidate{Article: a, Logit: float32(model.Logit(a)), Kind: sf.CandUnsure})
				default:
					loc.uncertain = append(loc.uncertain, a)
				}
			}
			mu.Lock()
			res.home += loc.home
			res.ham += loc.ham
			res.spam = append(res.spam, loc.spam...)
			res.uncertain = append(res.uncertain, loc.uncertain...)
			res.nocem = append(res.nocem, loc.nocem...)
			res.cands = append(res.cands, loc.cands...)
			if res.bi == nil {
				res.bi = loc.bi
			} else {
				for k, v := range loc.bi {
					res.bi[k] += v
				}
			}
			mu.Unlock()
		}()
	}
	var lines int64
	err := c.OverFunc(a0, b, func(line string) error {
		lines++
		in <- line
		return nil
	})
	close(in)
	wg.Wait()
	res.lines = lines
	return res, err
}

// retrain fits a new local model on all labelled items (the sample plus
// what the API labelled during the scan) and uses it from the next group
// on, if it is at least as good as the current one on the spam label.
func (r *runner) retrain() error {
	ex, labelled, _, err := loadExamples(r.st, splitList(strings.Join(nocemTrainTypes, ",")), r.o.nocemMax, r.heldOut, pickedSinceDefault, nil)
	if err != nil {
		return err
	}
	t0 := time.Now()
	m, rep, err := sf.Train(ex, r.model.Bits, 6, 0.98, 0.98, uint64(len(ex)))
	if err != nil {
		log.Printf("full: retrain: %v; keeping the current model", err)
		return nil
	}
	logReport(fmt.Sprintf("full: retrained on %d labelled items and %d NoCeM examples in %s", labelled, len(ex)-labelled, time.Since(t0).Round(time.Second)), rep)
	if rep.Precision < 0.97 {
		log.Printf("full: retrain: spam precision %.3f below 0.97 on test data; keeping the current model", rep.Precision)
		return nil
	}
	r.modelMu.Lock()
	r.model = m
	r.modelMu.Unlock()
	if err := m.Save(r.o.modelPath); err != nil {
		log.Printf("full: saving the retrained model: %v", err)
	}
	return nil
}

// biPass is the Breidbart pass 2: rescan every group and flag the copies
// of the keys the bi command found at or above the threshold.
func (r *runner) biPass(ctx context.Context, groups []sf.ActiveGroup) error {
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	start := time.Now()
	var totLines, totSpam, matched, skipped int64
	defer func() {
		if r.biChunks != nil {
			log.Printf("bi: read %d of the %d listed chunks, skipped %d", matched, len(r.biChunks), skipped)
		}
	}()
	return r.eachGroup(ctx, groups, func(ctx context.Context, c *sf.NNTP, ag sf.ActiveGroup) error {
		done, err := r.st.BIDone(ag.Name)
		if err != nil {
			return err
		}
		if done >= ag.High {
			return nil
		}
		_, low, high, err := c.Group(ag.Name)
		if err != nil {
			log.Printf("bi: %v", err)
			return nil
		}
		for a0 := max(low, done+1); a0 <= high; a0 += r.o.chunk {
			b := min(a0+r.o.chunk-1, high)
			if r.biChunks != nil && !r.biChunks[sf.ChunkID(ag.Name, a0)] {
				r.mu.Lock()
				skipped++
				err := r.st.SetBIDone(ag.Name, b)
				r.mu.Unlock()
				if err != nil {
					return err
				}
				continue
			}
			if r.biChunks != nil {
				r.mu.Lock()
				matched++
				r.mu.Unlock()
			}
			res, err := r.scoreChunk(c, ag.Name, a0, b)
			if err != nil {
				return fmt.Errorf("%s %d-%d: %w", ag.Name, a0, b, err)
			}
			r.mu.Lock()
			err = r.st.AddSpam(res.spam)
			if err == nil {
				err = r.st.SetBIDone(ag.Name, b)
			}
			if err == nil {
				totLines += res.lines
				totSpam += int64(len(res.spam))
				log.Printf("bi: %s %d-%d: %d lines, %d flagged; total %d lines, %d flagged, %.1f GB down, %s",
					ag.Name, a0, b, res.lines, len(res.spam), totLines, totSpam, float64(sf.WireBytes.Load())/1e9, time.Since(start).Round(time.Second))
			}
			r.mu.Unlock()
			if err != nil {
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		return nil
	})
}

func spamRow(a sf.Article, group, stage, reason string) sf.SpamRow {
	return sf.SpamRow{MsgID: a.MsgID, Key: a.Key, Group: group, ArtNum: artNumber(a.Source), Posted: a.Date, Stage: stage, Reason: reason}
}

// labels counts the labels the API added this run.
func (r *runner) labels() int64 {
	if r.lab != nil {
		return r.lab.labelled
	}
	return 0
}

// keepNocem picks one NoCeM-listed posting in every (by its From+Subject
// key, so all copies of a posting go the same way).
func keepNocem(arts []sf.Article, every int64) []sf.Article {
	if every <= 0 {
		return nil
	}
	var out []sf.Article
	for _, a := range arts {
		if keyHash(a.Key)%uint64(every) == 0 {
			out = append(out, a)
		}
	}
	return out
}

func keyHash(key string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(key))
	return h.Sum64()
}

func (r *runner) labSpent() float64 {
	if r.lab == nil {
		return 0
	}
	return r.lab.spent
}

func artNumber(source string) int64 {
	i := strings.LastIndexByte(source, ':')
	var n int64
	fmt.Sscan(source[i+1:], &n)
	return n
}

// labeler batches articles for the model API, stores the verdicts, keeps
// the spend in the database and stops sending at the budget.
type labeler struct {
	st            *sf.Store
	first, second *sf.LLM
	escOn         map[string]bool
	budget, spent float64 // spent: all runs together, from the database
	own           float64 // spent by this run
	batch         int
	pending       []sf.Article
	done          []func(sf.Verdict)
	labelled      int64 // verdicts the API gave in this run
	prev1, prev2  sf.Usage
	dry           bool // do not store the verdicts (recheck)
}

func (l *labeler) add(a sf.Article, done func(sf.Verdict)) {
	l.pending = append(l.pending, a)
	l.done = append(l.done, done)
}

func (l *labeler) flushIfFull(ctx context.Context) error {
	if len(l.pending) < l.batch {
		return nil
	}
	return l.flush(ctx)
}

func (l *labeler) flush(ctx context.Context) error {
	for len(l.pending) > 0 {
		if l.spent >= l.budget {
			l.pending, l.done = nil, nil
			return nil
		}
		n := min(len(l.pending), l.batch)
		arts, dones := l.pending[:n], l.done[:n]
		l.pending, l.done = l.pending[n:], l.done[n:]
		vs, err := l.first.Classify(ctx, arts, nil)
		if serr := l.account(l.first, &l.prev1); serr != nil {
			return serr
		}
		if err != nil {
			return err
		}
		if err := l.put(arts, vs); err != nil {
			return err
		}
		for _, v := range vs {
			if v.Label != "" {
				l.labelled++
			}
		}
		if l.second != nil && l.spent < l.budget {
			var again []sf.Article
			var idx []int
			for i, v := range vs {
				if l.escOn[v.Label] {
					again = append(again, arts[i])
					idx = append(idx, i)
				}
			}
			if len(again) > 0 {
				vs2, err := l.second.Classify(ctx, again, nil)
				if serr := l.account(l.second, &l.prev2); serr != nil {
					return serr
				}
				if err != nil {
					return err
				}
				if err := l.put(again, vs2); err != nil {
					return err
				}
				for j, i := range idx {
					if vs2[j].Label != "" {
						vs[i] = vs2[j]
					}
				}
			}
		}
		for i, v := range vs {
			if dones[i] != nil && v.Label != "" {
				dones[i](v)
			}
		}
	}
	return nil
}

func (l *labeler) put(arts []sf.Article, vs []sf.Verdict) error {
	if l.dry {
		return nil
	}
	return l.st.PutVerdicts(arts, vs)
}

func (l *labeler) account(c *sf.LLM, prev *sf.Usage) error {
	u := c.Usage()
	d := u.Sub(*prev)
	*prev = u
	usd := c.Cost(d)
	l.own += usd
	if err := l.st.AddSpend(c.Model, d, usd); err != nil {
		return err
	}
	// from the database: other runs may be spending at the same time
	spent, err := l.st.Spent()
	if err != nil {
		return err
	}
	l.spent = spent
	return nil
}

// wildmat compiles a comma-separated list of patterns; "!" excludes; the
// last pattern that matches decides; no match excludes.
func wildmat(list string) (func(string) bool, error) {
	type pat struct {
		p   string
		neg bool
	}
	var ps []pat
	for _, p := range strings.Split(list, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimPrefix(p, "!")
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("bad pattern %q: %w", p, err)
		}
		ps = append(ps, pat{p, neg})
	}
	return func(g string) bool {
		ok := false
		for _, p := range ps {
			if m, _ := path.Match(p.p, g); m {
				ok = !p.neg
			}
		}
		return ok
	}, nil
}

// ---- train

// loadExamples reads the labelled items (unsure ones and the keys in held
// are left out) and up to nocemMax NoCeM spam examples to learn from: first
// the overview headers the full scan kept (not those only a skipped issuer
// listed), then entries of the notices themselves. labelled is the number
// of the first kind, which come first in ex.
//
// The random sample (thresholds and test) is the labels stored before
// pickedSince, or, when sample is not nil, the keys in sample: relabel
// stores new times, so after it the times no longer tell them apart.
func loadExamples(st *sf.Store, nocemTypes []string, nocemMax int, held map[string]bool, pickedSince string, sample map[string]bool) (ex []sf.Example, labelled, unsure int, err error) {
	var extra, picked []sf.Example
	skipped, err := st.SkippedNocemVerdicts()
	if err != nil {
		return nil, 0, 0, err
	}
	err = st.EachVerdict(func(a sf.Article, v sf.Verdict) error {
		switch {
		case held[v.Key]:
		case v.Stage == sf.StageNocem && skipped[v.Key]:
		case v.Stage == sf.StageNocem:
			extra = append(extra, sf.Example{A: a, Spam: true, Extra: true})
		case v.Label != sf.Spam && v.Label != sf.Ham:
			unsure++
		case sample != nil && !sample[v.Key], sample == nil && pickedSince != "" && v.At >= pickedSince:
			// picked for being hard (label-unsure, label-flagged): learned
			// from, but thresholds set on them would not fit the archive
			picked = append(picked, sf.Example{A: a, Spam: v.Label == sf.Spam, Extra: true})
		case v.Label == sf.Spam:
			ex = append(ex, sf.Example{A: a, Spam: true})
		case v.Label == sf.Ham:
			ex = append(ex, sf.Example{A: a})
		default:
			unsure++
		}
		return nil
	})
	if err != nil {
		return nil, 0, 0, err
	}
	labelled = len(ex)
	ex = append(ex, picked...)
	if len(nocemTypes) == 0 || nocemMax <= 0 {
		return ex, labelled, unsure, nil
	}
	if len(extra) > nocemMax {
		// an even spread over the scan, not just its first groups
		step := float64(len(extra)) / float64(nocemMax)
		for i := 0; i < nocemMax; i++ {
			ex = append(ex, extra[int(float64(i)*step)])
		}
		return ex, labelled, unsure, nil
	}
	ex = append(ex, extra...)
	more, err := nocemExamples(st, nocemTypes, nocemMax-len(extra))
	return append(ex, more...), labelled, unsure, err
}

// sampleKeys returns the keys of the model labels in the database at path
// stored before pickedSince: the random sample.
func sampleKeys(path, pickedSince string) (map[string]bool, error) {
	st, err := sf.OpenStore(path)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	keys := map[string]bool{}
	err = st.EachVerdict(func(_ sf.Article, v sf.Verdict) error {
		if v.Stage == sf.StageLLM && v.At < pickedSince {
			keys[v.Key] = true
		}
		return nil
	})
	return keys, err
}

// pickedSinceDefault is when label-unsure and label-flagged started: labels
// from then on were picked (uncertain to the model, or Breidbart copies),
// the ones before are the random sample of run -mode sample and the scan.
const pickedSinceDefault = "2026-11-03"

// nocemTrainTypes are the NoCeM types learned from. flood and aioe-spam
// are left out: their headers look like ordinary postings (the flooding
// shows in the volume), so as examples they would teach the model that
// ordinary postings are spam.
var nocemTrainTypes = []string{"spam", "mmf", "spew", "emp", "cleanfeed-emp", "hipcrime"}

// nocemExamples returns NoCeM entries as spam examples: one per From+Subject
// key, none of the held-out keys nocem-eval measures on, at most max.
func nocemExamples(st *sf.Store, types []string, max int) ([]sf.Example, error) {
	if len(types) == 0 || max <= 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	var ex []sf.Example
	errFull := errors.New("full")
	err := st.NocemEntries(types, func(_ string, e sf.NoticeEntry) error {
		if e.HeldOut() {
			return nil
		}
		k := e.Key()
		if seen[k] {
			return nil
		}
		seen[k] = true
		ex = append(ex, sf.Example{A: e.Article(), Spam: true, Extra: true})
		if len(ex) >= max {
			return errFull
		}
		return nil
	})
	if err == errFull {
		err = nil
	}
	return ex, err
}

func logReport(prefix string, rep sf.TrainReport) {
	log.Printf("%s: trained on %d; spam at logit>=%.2f: precision %.3f, recall %.3f; ham at logit<=%.2f: precision %.3f, recall %.3f; uncertain %.1f%%",
		prefix, rep.Train, rep.SpamAt, rep.Precision, rep.Recall, rep.HamAt, rep.HamPrecision, rep.HamRecall, 100*rep.Uncertain)
}

func train(args []string) error {
	fs := flag.NewFlagSet("train", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database")
	out := fs.String("o", "spamfilter.model", "model file to write")
	bits := fs.Int("bits", 22, "feature space size, as a power of two")
	epochs := fs.Int("epochs", 6, "passes over the training data")
	prec := fs.Float64("precision", 0.98, "precision the spam and ham labels must reach on held-out data")
	hamPrec := fs.Float64("ham-precision", 0, "precision the ham label must reach, if not -precision: a stricter ham label keeps articles undecided (so copy counts and the API still judge them) while the spam label is looser")
	curve := fs.Bool("curve", true, "first train on 25, 50 and 75% of the data, to see whether more labels would help")
	nocemTypes := fs.String("nocem-types", strings.Join(nocemTrainTypes, ","), "also learn from NoCeM entries of these types that give a subject, as spam (empty = none)")
	nocemMax := fs.Int("nocem-max", 150000, "at most this many NoCeM examples, one per From+Subject")
	pickedSince := fs.String("picked-since", pickedSinceDefault, "labels stored from this time on (RFC 3339 prefix) were picked for being hard: learn from them, but set the thresholds and test on the earlier, random sample (\"\" = treat all alike)")
	sampleDB := fs.String("sample-db", "", "take the random sample from this database: its labels stored before -picked-since (for a database where relabel has rewritten the times)")
	holdOut := fs.Bool("hold-out-audit", true, "leave the spot-checked articles (audit) out, so the spot checks stay a fair test")
	nocemSkip := fs.String("nocem-skip", strings.Join(sf.DefaultNocemSkip, ","), "NoCeM issuers whose listings are ignored (\"\" = none)")
	fs.Parse(args)
	st, err := sf.OpenStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	st.NocemSkip = splitList(*nocemSkip)
	var held map[string]bool
	if *holdOut {
		if held, err = st.AuditKeys(); err != nil {
			return err
		}
	}
	var sample map[string]bool
	if *sampleDB != "" {
		if sample, err = sampleKeys(*sampleDB, *pickedSince); err != nil {
			return err
		}
		log.Printf("train: %d random-sample keys from %s", len(sample), *sampleDB)
	}
	ex, labelled, unsure, err := loadExamples(st, splitList(*nocemTypes), *nocemMax, held, *pickedSince, sample)
	if err != nil {
		return err
	}
	log.Printf("train: %d labelled examples (%d unsure left out); 80%% to learn from, 10%% to set thresholds, 10%% to test", labelled, unsure)
	if len(ex) > labelled {
		log.Printf("train: plus %d picked labels and NoCeM spam examples to learn from (not used for thresholds or the test)", len(ex)-labelled)
	}
	if *hamPrec == 0 {
		*hamPrec = *prec
	}
	if *curve {
		reps, err := sf.LearningCurve(ex, []float64{0.25, 0.5, 0.75}, uint8(*bits), *epochs, *prec, *hamPrec, 1)
		if err != nil {
			return err
		}
		for _, r := range reps {
			logReport("curve", r)
		}
	}
	m, rep, err := sf.Train(ex, uint8(*bits), *epochs, *prec, *hamPrec, 1)
	if err != nil {
		return err
	}
	logReport("train", rep)
	log.Printf("train: test set %d spam, %d ham", rep.TestSpam, rep.TestHam)
	if *curve {
		log.Printf("train: if recall still rises from 75%% to 100%%, more labels will help (run -mode sample with a higher -sample-target)")
	}
	if rep.TestSpam < 200 {
		// thresholds set on a handful of spam say nothing (and a model that
		// never reaches the precision flags nothing): don't write it
		return fmt.Errorf("only %d spam in the test set; is the random sample right (-picked-since, -sample-db)?", rep.TestSpam)
	}
	if err := m.Save(*out); err != nil {
		return err
	}
	log.Printf("train: wrote %s", *out)
	return nil
}

// ---- nocem: read NoCeM notices into the database

func nocemCmd(args []string) error {
	fs := flag.NewFlagSet("nocem", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database")
	server := fs.String("server", "", "news server, HOST:PORT")
	groups := fs.String("groups", "news.lists.filters,alt.nocem.misc", "groups holding NoCeM notices, comma-separated")
	batch := fs.Int("batch", 200, "ARTICLE commands sent at once")
	maxN := fs.Int64("max", 0, "read at most this many notice articles per group in this run (0 = all)")
	timeout := fs.Duration("timeout", 5*time.Minute, "network timeout")
	compress := fs.Bool("compress", true, "COMPRESS DEFLATE when the server offers it")
	fs.Parse(args)
	if *server == "" {
		return errors.New("need -server HOST:PORT")
	}
	st, err := sf.OpenStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	c, err := sf.DialNNTP(*server, *timeout)
	if err != nil {
		return err
	}
	defer c.Quit()
	c.ModeReader()
	if err := compressOn(c, *compress); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	start := time.Now()
	for _, g := range strings.Split(*groups, ",") {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		_, low, high, err := c.Group(g)
		if err != nil {
			return err
		}
		done, err := st.NocemDone(g)
		if err != nil {
			return err
		}
		from := max(low, done+1)
		end := high
		if *maxN > 0 {
			end = min(high, from+*maxN-1)
		}
		log.Printf("nocem: %s: reading %d-%d of %d-%d", g, from, end, low, high)
		var notices, entries, added int64
		types := map[string]int64{}
		const step = 2000 // progress is saved after each step
		for a0 := from; a0 <= end; a0 += step {
			if ctx.Err() != nil {
				log.Printf("nocem: stopped; run again to continue")
				return nil
			}
			b := min(a0+step-1, end)
			nums := make([]int64, 0, b-a0+1)
			for n := a0; n <= b; n++ {
				nums = append(nums, n)
			}
			var ns []sf.Notice
			err := c.Articles(nums, *batch, func(num int64, head, body []string) error {
				n, ok := sf.ParseNotice(body)
				if !ok || len(n.Entries) == 0 {
					return nil
				}
				if n.Type == "" {
					n.Type = "unknown"
				}
				notices++
				entries += int64(len(n.Entries))
				types[n.Type] += int64(len(n.Entries))
				ns = append(ns, n)
				return nil
			})
			if err != nil {
				return fmt.Errorf("%s %d-%d: %w", g, a0, b, err)
			}
			k, err := st.AddNotices(ns)
			if err != nil {
				return err
			}
			added += k
			if err := st.SetNocemDone(g, b); err != nil {
				return err
			}
			if (b-from+1)%(step*25) == 0 || b == end {
				log.Printf("nocem: %s up to %d: %d notices, %d entries (%d new Message-IDs); by type: %s; %s",
					g, b, notices, entries, added, formatCounts64(types), time.Since(start).Round(time.Second))
			}
		}
	}
	counts, err := st.NocemCounts()
	if err != nil {
		return err
	}
	var keys []string
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return counts[keys[i]] > counts[keys[j]] })
	log.Printf("nocem: Message-IDs in the database by type and issuer (top 25):")
	for _, k := range keys[:min(25, len(keys))] {
		log.Printf("  %10d  %s", counts[k], k)
	}
	return nil
}

// nocemEval scores the NoCeM-listed spam that comes with a subject with the
// local model: an independent measure of how much spam it recognises.
func nocemEval(args []string) error {
	fs := flag.NewFlagSet("nocem-eval", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database")
	modelPath := fs.String("model-file", "spamfilter.model", "local model")
	types := fs.String("types", strings.Join(sf.DefaultNocemTypes, ","), "notice types to evaluate")
	show := fs.Int("show", 20, "print this many of the entries the model calls ham")
	heldOut := fs.Bool("held-out", true, "only the one key in ten that train leaves out")
	nocemSkip := fs.String("nocem-skip", strings.Join(sf.DefaultNocemSkip, ","), "NoCeM issuers whose listings are ignored (\"\" = none)")
	fs.Parse(args)
	st, err := sf.OpenStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	st.NocemSkip = splitList(*nocemSkip)
	m, err := sf.LoadModel(*modelPath)
	if err != nil {
		return err
	}
	counts := map[string]map[string]int{}
	shown := 0
	seen := map[string]bool{} // one per From+Subject: copies would count a posting many times
	err = st.NocemEntries(splitList(*types), func(t string, e sf.NoticeEntry) error {
		if *heldOut && !e.HeldOut() {
			return nil
		}
		k := e.Key()
		if seen[k] {
			return nil
		}
		seen[k] = true
		label, p := m.Decide(e.Article())
		if label == "" {
			label = "uncertain"
		}
		if counts[t] == nil {
			counts[t] = map[string]int{}
		}
		counts[t][label]++
		if label == sf.Ham && shown < *show {
			shown++
			fmt.Printf("ham p=%.3f [%s] %q from %q\n", p, e.Groups, e.Subject, e.Sender)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for t, c := range counts {
		total := c[sf.Spam] + c[sf.Ham] + c["uncertain"]
		log.Printf("nocem-eval: type %s, %d postings (From+Subject) with a subject: model says spam %.1f%%, uncertain %.1f%%, ham %.1f%%",
			t, total, 100*ratioF(c[sf.Spam], total), 100*ratioF(c["uncertain"], total), 100*ratioF(c[sf.Ham], total))
	}
	return nil
}

func ratioF(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func formatCounts64(m map[string]int64) string {
	c := map[string]int{}
	for k, v := range m {
		c[k] = int(v)
	}
	return formatCounts(c)
}

// ---- adjudicate: a stronger model checks the labels the local model doubts

func adjudicate(args []string) error {
	fs := flag.NewFlagSet("adjudicate", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database")
	n := fs.Int("n", 2000, "items to check: those whose out-of-fold score contradicts their label most")
	model := fs.String("model", "claude-sonnet-5-5", "model that gives the second opinion")
	budget := fs.Float64("budget", 5, "stop once this many dollars are spent in this database, all runs together")
	batch := fs.Int("batch", 50, "articles per API request")
	conc := fs.Int("concurrency", 4, "API requests in flight")
	keyFile := fs.String("key-file", "/dev/shm/spamfilter_apikey.txt", "file holding the API key (else ANTHROPIC_API_KEY)")
	dry := fs.Bool("dry-run", false, "only list what would be sent")
	fs.Parse(args)
	st, err := sf.OpenStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	var arts []sf.Article
	var labels []sf.Verdict
	var ex []sf.Example
	err = st.EachVerdict(func(a sf.Article, v sf.Verdict) error {
		if v.Label != sf.Spam && v.Label != sf.Ham {
			return nil
		}
		if v.Model == *model {
			return nil // already this model's answer
		}
		if v.Stage == sf.StageNocem {
			return nil // the issuer's judgement, not a model's
		}
		arts, labels = append(arts, a), append(labels, v)
		ex = append(ex, sf.Example{A: a, Spam: v.Label == sf.Spam})
		return nil
	})
	if err != nil {
		return err
	}
	t0 := time.Now()
	z, err := sf.OutOfFold(ex, 5, 22, 6, 1)
	if err != nil {
		return err
	}
	// how strongly the score contradicts the label
	type cand struct {
		i      int
		margin float64
	}
	var cs []cand
	for i, e := range ex {
		m := -z[i] // a spam label with a low score
		if !e.Spam {
			m = z[i] // a ham label with a high score
		}
		if m > 0 {
			cs = append(cs, cand{i, m})
		}
	}
	sort.Slice(cs, func(a, b int) bool { return cs[a].margin > cs[b].margin })
	cs = cs[:min(*n, len(cs))]
	log.Printf("adjudicate: %d labelled items scored out of fold in %s; sending the %d most doubtful to %s",
		len(ex), time.Since(t0).Round(time.Second), len(cs), *model)
	if *dry {
		for _, c := range cs[:min(30, len(cs))] {
			fmt.Printf("%-5s logit %6.1f [%s] %s\n", labels[c.i].Label, z[c.i], arts[c.i].Newsgroups, arts[c.i].Subject)
		}
		return nil
	}
	spent, err := st.Spent()
	if err != nil {
		return err
	}
	if spent >= *budget {
		return fmt.Errorf("budget of $%.2f already spent ($%.2f)", *budget, spent)
	}
	opts := []option.RequestOption{option.WithMaxRetries(5)}
	if key, err := readKey(*keyFile); err == nil {
		opts = append(opts, option.WithAPIKey(key))
	} else if os.Getenv("ANTHROPIC_API_KEY") == "" {
		return fmt.Errorf("no API key: %v, and ANTHROPIC_API_KEY is not set", err)
	}
	c := &sf.LLM{Client: anthropic.NewClient(opts...), Model: *model, Effort: "low", BatchSize: *batch, Concurrency: *conc}
	send := make([]sf.Article, len(cs))
	for j, cd := range cs {
		send[j] = arts[cd.i]
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	vs, err := c.Classify(ctx, send, nil)
	u := c.Usage()
	usd := sf.Cost(*model, u)
	if serr := st.AddSpend(*model, u, usd); serr != nil {
		return serr
	}
	if err != nil {
		return err
	}
	if err := st.PutVerdicts(send, vs); err != nil {
		return err
	}
	flips := map[string]int{}
	for j, v := range vs {
		old := labels[cs[j].i].Label
		if v.Label == "" {
			flips["no answer"]++
			continue
		}
		flips[old+" -> "+v.Label]++
	}
	log.Printf("adjudicate: %s; $%.2f; now run train again", formatCounts(flips), usd)
	return nil
}

// ---- bi: aggregate the Breidbart counts of a full scan

const (
	biKeysFile   = "spamkeys.bin"
	biChunksFile = "spamchunks.bin"
)

func biCmd(args []string) error {
	fs := flag.NewFlagSet("bi", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database (its .bi directory holds the counts)")
	biDir := fs.String("bi-dir", "", "directory of the counts (default: the database path + \".bi\")")
	threshold := fs.Float64("threshold", float64(sf.DefaultRules.BIThreshold), "Breidbart index at which copies are spam")
	fs.Parse(args)
	if *biDir == "" {
		*biDir = *dbPath + ".bi"
	}
	t0 := time.Now()
	keys, st, err := sf.AggregateBI(*biDir, float32(*threshold))
	if err != nil {
		return err
	}
	if err := sf.SaveBIKeys(filepath.Join(*biDir, biKeysFile), keys); err != nil {
		return err
	}
	if err := sf.SaveBIChunks(filepath.Join(*biDir, biChunksFile), st.Chunks); err != nil {
		return err
	}
	log.Printf("bi: %d records, %d keys (item and month), %d at or above %.0f, highest %.1f, in %d chunks; %s; next: run -mode bi",
		st.Records, st.Keys, st.Over, *threshold, st.Max, len(st.Chunks), time.Since(t0).Round(time.Second))
	return nil
}

// ---- history, spam-export, status

func history(args []string) error {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database")
	out := fs.String("o", "spam.history", "file to write (INN history text format)")
	arrived := fs.Int64("arrived", time.Now().Unix(), "arrival time to record, unix seconds; INN's expire drops the lines /remember/ days after it")
	nocemTypes := fs.String("nocem-types", strings.Join(sf.DefaultNocemTypes, ","), "also write the Message-IDs NoCeM notices list under these types (\"\" = only what the scan flagged)")
	nocemSkip := fs.String("nocem-skip", strings.Join(sf.DefaultNocemSkip, ","), "NoCeM issuers whose listings are ignored (\"\" = none)")
	fs.Parse(args)
	st, err := sf.OpenStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	st.NocemSkip = splitList(*nocemSkip)
	f, err := os.Create(*out + ".tmp")
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	n, err := sf.WriteHistory(w, st, *arrived, splitList(*nocemTypes))
	if err == nil {
		err = w.Flush()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(f.Name(), *out); err != nil {
		return err
	}
	log.Printf("history: %d lines written to %s", n, *out)
	return nil
}

func spamExport(args []string) error {
	fs := flag.NewFlagSet("spam-export", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database")
	out := fs.String("o", "-", "file to write, - for stdout")
	fs.Parse(args)
	st, err := sf.OpenStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	f := os.Stdout
	if *out != "-" {
		if f, err = os.Create(*out); err != nil {
			return err
		}
		defer f.Close()
	}
	w := bufio.NewWriterSize(f, 1<<20)
	n := 0
	err = st.EachSpam(func(r sf.SpamRow) error {
		n++
		v := sf.Verdict{Label: sf.Spam, Stage: r.Stage, Reason: r.Reason}
		rule, code := v.CleanfeedRule()
		return writeJSON(w, struct {
			MsgID  string `json:"msgid"`
			Label  string `json:"label"`
			Stage  string `json:"stage"`
			Reason string `json:"reason"`
			Rule   string `json:"rule"`
			Code   string `json:"code"`
			Source string `json:"source"`
		}{r.MsgID, sf.Spam, r.Stage, r.Reason, rule, code, fmt.Sprintf("%s:%d", r.Group, r.ArtNum)})
	})
	if err == nil {
		err = w.Flush()
	}
	log.Printf("spam-export: %d lines", n)
	return err
}

func status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database")
	fs.Parse(args)
	st, err := sf.OpenStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	g, sampled, verdicts, spam, err := st.Counts()
	if err != nil {
		return err
	}
	spent, _ := st.Spent()
	fmt.Printf("groups %d, sampled %d, labelled items %d, spam Message-IDs %d, API spend $%.2f\n", g, sampled, verdicts, spam, spent)
	return nil
}
