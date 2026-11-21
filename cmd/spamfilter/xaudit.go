package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

// ---- audit-openai: spot-check the current scan with an OpenAI model, a
// second opinion from another model family. The results and the OpenAI
// spend go to their own database (-out): the scan's database is only read,
// so its audit table (which holds keys out of training) stays as it is.
//
// Classes: the five flag sources (model, llm, nocem, bi, subj), unflagged
// (random articles of the archive the scan did not flag) and calib
// (articles Claude already checked, to see how often the two agree).

var xauditClasses = []string{sf.StageModel, sf.StageLLM, sf.StageNocem, "bi", "subj", "unflagged", "calib"}

type xItem struct {
	class string
	row   sf.AuditRow
	base  sf.Article // an overview article (Source set), or only Message-ID and key
}

func auditOpenAI(args []string) error {
	fs := flag.NewFlagSet("audit-openai", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "the scan's database (only read)")
	outPath := fs.String("out", "spamfilter-openai.db", "database for the results and the OpenAI spend")
	server := fs.String("server", "", "news server, HOST:PORT")
	conns := fs.Int("conns", 4, "connections to the news server")
	maxMbit := fs.Float64("max-mbit", 200, "cap on the download from the news server (0 = none)")
	timeout := fs.Duration("timeout", 2*time.Minute, "network timeout")
	compress := fs.Bool("compress", true, "COMPRESS DEFLATE when the server offers it")
	plan := fs.String("plan", "model=100000,llm=20000,nocem=20000,bi=20000,subj=10000,unflagged=20000,calib=20000",
		"articles to check per class ("+strings.Join(xauditClasses, ", ")+"); rows already in -out count")
	scale := fs.Float64("scale", 1, "multiply every count of -plan (0.01 for a pilot)")
	modelFile := fs.String("model-file", "spamfilter-after4-s97.model", "the scan's local model: tells undecided from clean in the unflagged sample")
	model := fs.String("model", "gpt-6-luna", "OpenAI model")
	effort := fs.String("effort", "low", "reasoning effort")
	keyFile := fs.String("key-file", "/dev/shm/openai_apikey.txt", "file holding the OpenAI API key (else OPENAI_API_KEY)")
	batch := fs.Int("batch", 50, "articles per request")
	conc := fs.Int("concurrency", 16, "requests in flight")
	budget := fs.Float64("budget", 30, "stop once this many dollars (list price) are spent in -out, all runs together")
	tag := fs.String("tag", "luna", "suffix of the kinds stored: flagged-TAG, unflagged-TAG, calib-TAG")
	seed := fs.Uint64("seed", uint64(time.Now().UnixNano()), "random seed")
	report := fs.Bool("report", false, "only print the results stored so far")
	fs.Parse(args)

	want, err := parsePlan(*plan, *scale)
	if err != nil {
		return err
	}
	out, err := sf.OpenStore(*outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	if *report {
		return xauditReport(out, *tag)
	}
	if *server == "" {
		return errors.New("need -server HOST:PORT")
	}
	key, err := readKey(*keyFile)
	if err != nil {
		if key = os.Getenv("OPENAI_API_KEY"); key == "" {
			return fmt.Errorf("no API key: %v, and OPENAI_API_KEY is not set", err)
		}
	}
	spent, err := out.Spent()
	if err != nil {
		return err
	}
	if spent >= *budget {
		log.Printf("audit-openai: $%.2f spent of $%.2f; nothing to do", spent, *budget)
		return xauditReport(out, *tag)
	}
	st, err := sf.OpenStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	// what earlier runs stored counts toward the plan
	kFlagged, kUnflagged, kCalib := "flagged-"+*tag, "unflagged-"+*tag, "calib-"+*tag
	have := map[string]int{}
	seen := map[string]bool{}
	err = out.EachAudit(func(r sf.AuditRow) error {
		switch r.Kind {
		case kFlagged:
			have[auditClass(r.Stage, r.Reason)]++
		case kUnflagged:
			have["unflagged"]++
		case kCalib:
			have["calib"]++
		default:
			return nil
		}
		seen[r.MsgID] = true
		return nil
	})
	if err != nil {
		return err
	}
	need := map[string]int{}
	for _, c := range xauditClasses {
		need[c] = max(want[c]-have[c], 0)
	}
	log.Printf("audit-openai: stored %s; to check %s; $%.2f spent of $%.2f", formatCountsInt(have), formatCountsInt(need), spent, *budget)

	rng := rand.New(rand.NewPCG(*seed, *seed^0x2545f4914f6cdd1d))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	limit := sf.NewLimiter(*maxMbit)

	// flagged: random rows of the spam table until every class has its count
	var items []xItem
	got := map[string]int{}
	flaggedLeft := func() bool {
		for _, c := range []string{sf.StageModel, sf.StageLLM, sf.StageNocem, "bi", "subj"} {
			if got[c] < need[c] {
				return true
			}
		}
		return false
	}
	for draws := 0; draws < 300 && flaggedLeft() && ctx.Err() == nil; draws++ {
		rs, err := st.SampleSpam(10000, "", rng.Int64N)
		if err != nil {
			return err
		}
		for _, r := range rs {
			c := auditClass(r.Stage, r.Reason)
			if seen[r.MsgID] || got[c] >= need[c] {
				continue
			}
			seen[r.MsgID] = true
			got[c]++
			items = append(items, xItem{class: c,
				row:  sf.AuditRow{MsgID: r.MsgID, Kind: kFlagged, Group: r.Group, ArtNum: r.ArtNum, Stage: r.Stage, Reason: r.Reason},
				base: sf.Article{MsgID: r.MsgID, Key: r.Key}})
		}
	}

	// calib: a random pick of the scan database's spot checks, which hold
	// Claude's label (Haiku's, or Sonnet's where it disagreed with the scan)
	if n := need["calib"]; n > 0 {
		var pick []sf.AuditRow
		seenN := 0
		err := st.EachAudit(func(r sf.AuditRow) error {
			if r.Label == "" || seen[r.MsgID] || !strings.HasPrefix(r.MsgID, "<") {
				return nil
			}
			seenN++
			if len(pick) < n {
				pick = append(pick, r)
			} else if j := rng.IntN(seenN); j < n {
				pick[j] = r
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, r := range pick {
			seen[r.MsgID] = true
			got["calib"]++
			items = append(items, xItem{class: "calib",
				row:  sf.AuditRow{MsgID: r.MsgID, Kind: kCalib, Group: r.Group, ArtNum: r.ArtNum, Stage: r.Kind, Reason: r.Label + " " + r.Model},
				base: sf.Article{MsgID: r.MsgID}})
		}
	}

	// unflagged: random articles of the archive that the spam table lacks
	if n := need["unflagged"]; n > 0 && ctx.Err() == nil {
		us, err := sampleUnflagged(ctx, st, *modelFile, *server, *timeout, limit, *compress, *conns, n, seen, *seed, kUnflagged)
		if err != nil {
			return err
		}
		got["unflagged"] += len(us)
		items = append(items, us...)
	}
	log.Printf("audit-openai: sampled %s", formatCountsInt(got))

	// mixed order, so a run stopped by the budget still covers every class
	rng.Shuffle(len(items), func(i, j int) { items[i], items[j] = items[j], items[i] })

	oa := &sf.OpenAI{Key: key, Model: *model, Effort: *effort, BatchSize: *batch, Concurrency: *conc}
	fetchers := make([]*fetcher, max(*conns, 1))
	for i := range fetchers {
		fetchers[i] = &fetcher{server: *server, timeout: *timeout, limit: limit, compress: *compress}
		defer fetchers[i].drop()
	}
	var prev sf.Usage
	var done, missing, unlabelled int
	const block = 4000
	for b := 0; b < len(items) && ctx.Err() == nil; b += block {
		if spent >= *budget {
			log.Printf("audit-openai: budget reached ($%.2f of $%.2f)", spent, *budget)
			break
		}
		blk := items[b:min(b+block, len(items))]
		arts := make([]sf.Article, len(blk))
		ok := make([]bool, len(blk))
		var wg sync.WaitGroup
		for j, f := range fetchers {
			wg.Add(1)
			go func(j int, f *fetcher) {
				defer wg.Done()
				var idx []int
				var ids []string
				for i := j; i < len(blk); i += len(fetchers) {
					idx = append(idx, i)
					ids = append(ids, blk[i].row.MsgID)
				}
				f.fetchIDs(ids, func(k int, head, body []string) {
					i := idx[k]
					if a, good := articleFor(blk[i].base, head, body); good {
						arts[i], ok[i] = a, true
					}
				})
			}(j, f)
		}
		wg.Wait()
		var send []sf.Article
		var sidx []int
		for i := range blk {
			if ok[i] {
				send = append(send, arts[i])
				sidx = append(sidx, i)
			} else {
				missing++
			}
		}
		vs, cerr := oa.Classify(ctx, send)
		u := oa.Usage()
		d := u.Sub(prev)
		prev = u
		if err := out.AddSpend(*model, d, oa.Cost(d)); err != nil {
			return err
		}
		if spent, err = out.Spent(); err != nil {
			return err
		}
		var rows []sf.AuditRow
		for k, v := range vs {
			if v.Label == "" {
				if k < len(sidx) {
					unlabelled++
				}
				continue
			}
			r := blk[sidx[k]].row
			r.Label, r.Why, r.Model = v.Label, v.Reason, v.Model
			rows = append(rows, r)
		}
		if err := out.AddAudit(rows); err != nil {
			return err
		}
		done += len(rows)
		log.Printf("audit-openai: %d of %d checked (%d not on the server, %d without an answer), $%.2f spent",
			done, len(items), missing, unlabelled, spent)
		if cerr != nil && ctx.Err() == nil {
			return cerr
		}
	}
	if ctx.Err() != nil {
		log.Printf("audit-openai: stopped; results so far are saved")
	}
	return xauditReport(out, *tag)
}

func parsePlan(s string, scale float64) (map[string]int, error) {
	m := map[string]int{}
	known := map[string]bool{}
	for _, c := range xauditClasses {
		known[c] = true
	}
	for _, kv := range splitList(s) {
		k, v, ok := strings.Cut(kv, "=")
		n, err := strconv.Atoi(v)
		if !ok || err != nil || n < 0 || !known[k] {
			return nil, fmt.Errorf("bad -plan entry %q (want CLASS=N, classes %s)", kv, strings.Join(xauditClasses, ", "))
		}
		m[k] = int(float64(n)*scale + 0.5)
	}
	return m, nil
}

// articleFor builds the article to label from what the server sent: the
// overview article with the body added, or the whole article.
func articleFor(base sf.Article, head, body []string) (sf.Article, bool) {
	if base.Source != "" {
		return withBody(base, head, body)
	}
	a := sf.NewArticle(head, body, -1)
	if a.MsgID != base.MsgID {
		return a, false
	}
	if base.Key != "" {
		a.Key = base.Key
	}
	return a, true
}

// fetchIDs fetches articles by Message-ID and calls fn for each one the
// server has; a broken connection is retried once, then the rest skipped.
func (f *fetcher) fetchIDs(ids []string, fn func(i int, head, body []string)) {
	got := make([]bool, len(ids))
	for attempt := 0; attempt < 2; attempt++ {
		var todo []int
		var send []string
		for i, id := range ids {
			if !got[i] && strings.HasPrefix(id, "<") && strings.HasSuffix(id, ">") && !strings.ContainsAny(id, " \t\r\n") {
				todo = append(todo, i)
				send = append(send, id)
			}
		}
		if len(send) == 0 {
			return
		}
		c, err := f.conn()
		if err != nil {
			log.Printf("fetch: %v", err)
			continue
		}
		err = c.ArticlesByID(send, 100, func(k int, head, body []string) error {
			got[todo[k]] = true
			fn(todo[k], head, body)
			return nil
		})
		if err == nil {
			return
		}
		log.Printf("fetch: %v", err)
		f.drop()
	}
}

// sampleUnflagged draws random articles of the archive (a group weighted by
// its size, a random number, one home copy from the overview around it)
// until it has n that the spam table lacks. Stage tells how the scan let
// each one through: "verdict" (a stored label for its key) or "model" (the
// local model's decision: ham, or undecided).
func sampleUnflagged(ctx context.Context, st *sf.Store, modelFile, server string, timeout time.Duration, limit *sf.Limiter,
	compress bool, conns, n int, seen map[string]bool, seed uint64, kind string) ([]xItem, error) {
	m, err := sf.LoadModel(modelFile)
	if err != nil {
		return nil, err
	}
	groups, err := st.GroupRanges()
	if err != nil {
		return nil, err
	}
	cum := make([]int64, len(groups))
	var total int64
	for i, g := range groups {
		total += g.High - g.Low + 1
		cum[i] = total
	}
	if total == 0 {
		return nil, errors.New("no group ranges in the database")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cands := make(chan sf.Article, 64)
	var wg sync.WaitGroup
	for w := 0; w < max(conns, 1); w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(seed+uint64(w)+1, seed^0x9e3779b97f4a7c15))
			var c *sf.NNTP
			var ov *sf.Overview
			defer func() {
				if c != nil {
					c.Quit()
				}
			}()
			for ctx.Err() == nil {
				if c == nil {
					var err error
					if c, err = sf.DialNNTPLimited(server, timeout, limit); err != nil {
						log.Printf("unflagged: %v", err)
						time.Sleep(10 * time.Second)
						continue
					}
					c.ModeReader()
					if err := compressOn(c, compress); err != nil {
						log.Printf("unflagged: %v", err)
					}
					format, err := c.OverviewFormat()
					if err == nil {
						ov, err = sf.NewOverview(format)
					}
					if err != nil {
						log.Printf("unflagged: overview format: %v", err)
						c.Quit()
						c = nil
						return
					}
				}
				x := rng.Int64N(total)
				gi := sort.Search(len(cum), func(i int) bool { return cum[i] > x })
				g := groups[gi]
				num := g.Low + rng.Int64N(g.High-g.Low+1)
				if _, _, _, err := c.Group(g.Name); err != nil {
					if strings.HasPrefix(err.Error(), "GROUP ") {
						continue // the server's answer (411: gone); the connection is fine
					}
					c.Quit()
					c = nil
					continue
				}
				lines, err := c.Over(num, min(num+19, g.High))
				if err != nil {
					if strings.HasPrefix(err.Error(), "OVER ") {
						continue
					}
					c.Quit()
					c = nil
					continue
				}
				var home []sf.Article
				for _, l := range lines {
					a, err := ov.Parse(l, g.Name)
					if err != nil {
						continue
					}
					first, _, _ := strings.Cut(a.Newsgroups, ",")
					if first == g.Name {
						home = append(home, a)
					}
				}
				if len(home) == 0 {
					continue
				}
				select {
				case cands <- home[rng.IntN(len(home))]:
				case <-ctx.Done():
					return
				}
			}
		}(w)
	}
	go func() { // closed once every worker is gone
		wg.Wait()
		close(cands)
	}()
	var out []xItem
	var flagged, tries int
	for len(out) < n && ctx.Err() == nil {
		a, alive := <-cands
		if !alive {
			return nil, fmt.Errorf("unflagged: news server connections failed after %d of %d", len(out), n)
		}
		tries++
		if seen[a.MsgID] || !strings.HasPrefix(a.MsgID, "<") {
			continue
		}
		loc, err := st.SpamLocation([]string{a.MsgID})
		if err != nil {
			cancel()
			for range cands {
			}
			return nil, err
		}
		if _, isSpam := loc[a.MsgID]; isSpam {
			flagged++
			continue
		}
		seen[a.MsgID] = true
		stage, reason := sf.StageModel, ""
		if v, ok, err := st.Verdict(a.Key); err == nil && ok {
			stage, reason = "verdict", v.Label
		} else {
			label, p := m.Decide(a)
			if label == "" {
				label = "undecided"
			}
			reason = fmt.Sprintf("%s p=%.3f", label, p)
		}
		out = append(out, xItem{class: "unflagged",
			row:  sf.AuditRow{MsgID: a.MsgID, Kind: kind, Group: g0(a.Source), ArtNum: artNumber(a.Source), Stage: stage, Reason: reason},
			base: a})
		if len(out)%2000 == 0 {
			log.Printf("unflagged: %d of %d (%d drawn, %d of them flagged)", len(out), n, tries, flagged)
		}
	}
	cancel()
	for range cands { // until the workers have stopped
	}
	log.Printf("unflagged: %d picked, %d drawn, %d of them flagged (%.1f%%)", len(out), tries, flagged, 100*float64(flagged)/float64(max(tries, 1)))
	return out, nil
}

func g0(source string) string {
	i := strings.LastIndexByte(source, ':')
	if i < 0 {
		return source
	}
	return source[:i]
}

func xauditReport(out *sf.Store, tag string) error {
	kFlagged, kUnflagged, kCalib := "flagged-"+tag, "unflagged-"+tag, "calib-"+tag
	type cnt struct{ n, spam, ham, unsure int }
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
	flagged, hier, unflagged := map[string]*cnt{}, map[string]*cnt{}, map[string]*cnt{}
	calib := map[string]*cnt{} // by Claude's label: Luna's labels
	models := map[string]int{}
	err := out.EachAudit(func(r sf.AuditRow) error {
		switch r.Kind {
		case kFlagged:
			c := auditClass(r.Stage, r.Reason)
			add(flagged, c, r.Label)
			add(hier, c+" "+sf.Hierarchy(r.Group), r.Label)
		case kUnflagged:
			k := r.Stage + ":" + r.Reason
			if r.Stage == sf.StageModel {
				k, _, _ = strings.Cut(k, " ")
			}
			add(unflagged, k, r.Label)
		case kCalib:
			claude, _, _ := strings.Cut(r.Reason, " ")
			add(calib, claude, r.Label)
		default:
			return nil
		}
		models[r.Model]++
		return nil
	})
	if err != nil {
		return err
	}
	if len(models) == 0 {
		fmt.Println("no results stored for tag", tag)
		return nil
	}
	pr := func(m map[string]*cnt, minN int, est func(*cnt) float64) {
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
			line := fmt.Sprintf("  %-28s %7d  spam %5.1f%%  ham %5.1f%%  unsure %5.1f%%", k, c.n, p(c.spam), p(c.ham), p(c.unsure))
			if est != nil {
				if e := est(c); e >= 0 {
					line += fmt.Sprintf("  est. spam %5.1f%%", 100*e)
				}
			}
			fmt.Println(line)
		}
	}
	// calibration: Luna's error rates against Claude's labels. sens: the
	// share of Claude's spam Luna calls spam; fpr: the share of Claude's
	// ham and unsure Luna calls spam. They do not depend on how much spam a
	// sample holds, so a class's spam share on Claude's scale follows from
	// Luna's spam share there (Rogan-Gladen): (obs - fpr) / (sens - fpr).
	sens, fpr := -1.0, -1.0
	if len(calib) > 0 {
		var cs, cn cnt
		for claude, c := range calib {
			x := &cn
			if claude == sf.Spam {
				x = &cs
			}
			x.n += c.n
			x.spam += c.spam
		}
		fmt.Printf("calibration: articles Claude checked before, by Claude's label, and the %s labels for them\n", tag)
		pr(calib, 1, nil)
		if cs.n > 0 && cn.n > 0 {
			sens, fpr = float64(cs.spam)/float64(cs.n), float64(cn.spam)/float64(cn.n)
			fmt.Printf("  %s finds %.1f%% of Claude's spam (%d) and calls %.1f%% of Claude's ham and unsure spam (%d)\n",
				tag, 100*sens, cs.n, 100*fpr, cn.n)
		}
	}
	est := func(c *cnt) float64 {
		if sens < 0 || sens-fpr < 0.2 || c.n == 0 {
			return -1
		}
		e := (float64(c.spam)/float64(c.n) - fpr) / (sens - fpr)
		return min(max(e, 0), 1)
	}
	fmt.Printf("flagged by the scan, by what flagged it (est. spam: on Claude's scale, from the calibration)\n")
	pr(flagged, 1, est)
	fmt.Println("flagged, by what flagged it and hierarchy (300+ checked):")
	pr(hier, 300, est)
	fmt.Println("not flagged, by how the scan let it through:")
	pr(unflagged, 1, est)
	spent, err := out.Spent()
	if err != nil {
		return err
	}
	fmt.Printf("models: %s; spent $%.2f\n", formatCountsInt(models), spent)
	return nil
}
