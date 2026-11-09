// Command spamfilter labels Usenet articles as spam, ham or unsure: for
// analysis, and to derive filter rules (cleanfeed-ng bad_* lists).
//
//	spamfilter over   -state DIR -server HOST:119 GROUP...  fetch overview lines
//	spamfilter scan   -state DIR [MBOX|DIR...]              merge overview and mbox articles
//	spamfilter rules  -state DIR                            Breidbart index, subject rules
//	spamfilter llm    -state DIR [flags]                    label a sample with a Claude model
//	spamfilter export -state DIR -o FILE                    one JSONL line per labelled article
//	spamfilter stats  -state DIR                            counts; rules vs model
//
// Files in DIR:
//
//	over/<group>.ov.gz         raw OVER lines, one gzip member per fetched chunk
//	over/<group>.last          last article number fetched (resume point)
//	over/overview.fmt          the server's LIST OVERVIEW.FMT
//	articles.tsv.gz            one line per Message-ID: msgid key bodyhash date groups reply source
//	items-mbox.jsonl.gz        one article per key, from mbox files (with body text)
//	items-over.jsonl.gz        one article per key seen only in the overview
//	rules.jsonl, llm.jsonl     verdicts per key
//
// A Message-ID found in both sources is counted once; its overview line
// wins. The key (see spamfilter.FSLKey) is the same in both sources, so the
// model sees the mbox text of an article when there is one.
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"log"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

const (
	overDir      = "over"
	overFmtFile  = "overview.fmt"
	articlesFile = "articles.tsv.gz"
	itemsMbox    = "items-mbox.jsonl.gz"
	itemsOver    = "items-over.jsonl.gz"
	rulesFile    = "rules.jsonl"
	llmFile      = "llm.jsonl"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "over":
		err = over(args)
	case "scan":
		err = scan(args)
	case "rules":
		err = rules(args)
	case "llm":
		err = llm(args)
	case "export":
		err = export(args)
	case "stats":
		err = stats(args)
	case "run":
		err = run(args)
	case "train":
		err = train(args)
	case "bi":
		err = biCmd(args)
	case "adjudicate":
		err = adjudicate(args)
	case "nocem":
		err = nocemCmd(args)
	case "nocem-eval":
		err = nocemEval(args)
	case "history":
		err = history(args)
	case "spam-export":
		err = spamExport(args)
	case "serve":
		err = serve(args)
	case "label-unsure":
		err = labelUnsure(args)
	case "audit":
		err = audit(args)
	case "rescore":
		err = rescore(args)
	case "nntp-bench":
		err = nntpBench(args)
	case "label-flagged":
		err = labelFlagged(args)
	case "compare":
		err = compare(args)
	case "recheck":
		err = recheck(args)
	case "relabel":
		err = relabel(args)
	case "status":
		err = status(args)
	default:
		usage()
	}
	if err != nil {
		log.Fatalf("spamfilter %s: %v", cmd, err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: spamfilter run|train|history|spam-export|status -db FILE [flags]
  run -mode sample  -db FILE -server HOST:PORT   label a random slice of every group with the model (training data)
  run -mode full    -db FILE -server HOST:PORT   scan every group: rules, local model, model API for the uncertain
  train       -db FILE -o MODEL                  train the local model on the labelled items
  nocem       -db FILE -server HOST:PORT         read NoCeM notices (news.lists.filters, alt.nocem.misc) into the database
  nocem-eval  -db FILE -model-file MODEL          how much of the NoCeM-listed spam the local model recognises
  adjudicate  -db FILE [-n 2000]                 a stronger model re-checks the labels the local model doubts most
  bi          -db FILE                           sum the Breidbart counts of a full scan (then: run -mode bi)
  run -mode bi      -db FILE -server HOST:PORT   rescan and flag the copies of the keys bi found
  run -mode unsure  -db FILE -server HOST:PORT   read -share of the chunks, keep what the local model can't decide
  label-unsure -db FILE -server HOST:PORT        label those candidates with their bodies (most copied first, then a spread)
  rescore     -db FILE -model-file MODEL          how a model decides the candidates (after train)
  audit       -db FILE -server HOST:PORT         spot-check flagged and clean articles with the model API
  label-flagged -db FILE -server HOST:PORT -class bi   label one copy of each flagged key (the next scan uses the labels)
  compare     -before FILE -after FILE           compare two scans, measured on the spot checks
  recheck     -db FILE -server HOST:PORT        label spot-checked articles again (not stored) and compare with the spot check
  relabel     -db FILE -server HOST:PORT        label stored API spam labels in offer and anti-spam groups again (batch API)
  history     -db FILE -o FILE                   INN history lines for the spam Message-IDs
  spam-export -db FILE -o FILE                   the spam Message-IDs as JSONL
  status      -db FILE                           progress and API spend

or, working on files: spamfilter over|scan|rules|llm|export|stats -state DIR [flags] [ARGS...]
  over   -state DIR -server HOST:PORT GROUP...  fetch overview lines from a news server (resumes)
  scan   -state DIR [MBOX|DIR...]              merge fetched overview lines and mbox files (plain, .gz, .zip)
  rules  -state DIR                            label the clear cases: Breidbart index, spam subjects
  llm    -state DIR [-limit N]                 label a random sample of the rest with a Claude model (estimate only without -yes)
  export -state DIR [-o FILE]                  {"msgid","label","stage","reason","rule","code","source"} per labelled article
  stats  -state DIR                            label counts; rules vs model on the audited items
run "spamfilter CMD -h" for the flags of a command
`)
	os.Exit(2)
}

// ---- over

func over(args []string) error {
	fs := flag.NewFlagSet("over", flag.ExitOnError)
	state := fs.String("state", "", "state directory (created if missing)")
	server := fs.String("server", "", "news server, HOST:PORT")
	chunk := fs.Int64("chunk", 1000, "articles per OVER command")
	delay := fs.Duration("delay", time.Second, "pause between OVER commands")
	maxPer := fs.Int64("max", 0, "fetch at most this many article numbers per group in this run (0 = to the end)")
	compress := fs.Bool("compress", false, "use COMPRESS DEFLATE when the server offers it (off: with INN 2.8.0 the second command after it got no answer)")
	timeout := fs.Duration("timeout", 2*time.Minute, "network timeout per command")
	groupsFile := fs.String("groups-file", "", "file with one group name per line, in addition to the arguments")
	fs.Parse(args)
	groups := fs.Args()
	if *groupsFile != "" {
		b, err := os.ReadFile(*groupsFile)
		if err != nil {
			return err
		}
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				groups = append(groups, strings.Fields(l)[0])
			}
		}
	}
	if *state == "" || *server == "" || len(groups) == 0 {
		return errors.New("need -state DIR, -server HOST:PORT and at least one group")
	}
	dir := filepath.Join(*state, overDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	c, err := sf.DialNNTP(*server, *timeout)
	if err != nil {
		return err
	}
	defer c.Quit()
	c.ModeReader()
	if caps, err := c.Capabilities(); err == nil && *compress && hasCap(caps, "COMPRESS", "DEFLATE") {
		if err := c.Compress(); err != nil {
			return err
		}
		log.Printf("over: COMPRESS DEFLATE on")
	}
	format, err := c.OverviewFormat()
	if err != nil {
		return err
	}
	if _, err := sf.NewOverview(format); err != nil {
		return err
	}
	fmtPath := filepath.Join(dir, overFmtFile)
	if old, err := os.ReadFile(fmtPath); err == nil && strings.TrimSpace(string(old)) != strings.Join(format, "\n") {
		return fmt.Errorf("%s differs from this server's overview format; use another state directory", fmtPath)
	}
	if err := os.WriteFile(fmtPath, []byte(strings.Join(format, "\n")+"\n"), 0644); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	for _, g := range groups {
		if strings.ContainsAny(g, "/\\ ") || strings.HasPrefix(g, ".") {
			log.Printf("over: skipping odd group name %q", g)
			continue
		}
		if err := overGroup(ctx, c, dir, g, *chunk, *maxPer, *delay); err != nil {
			return fmt.Errorf("%s: %w", g, err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

// compressOn switches c to COMPRESS DEFLATE when on and the server
// offers it in CAPABILITIES.
func compressOn(c *sf.NNTP, on bool) error {
	if !on {
		return nil
	}
	caps, err := c.Capabilities()
	if err != nil || !hasCap(caps, "COMPRESS", "DEFLATE") {
		return nil
	}
	return c.Compress()
}

func hasCap(caps []string, name, arg string) bool {
	for _, c := range caps {
		f := strings.Fields(c)
		if len(f) > 0 && f[0] == name && (arg == "" || containsStr(f[1:], arg)) {
			return true
		}
	}
	return false
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func overGroup(ctx context.Context, c *sf.NNTP, dir, group string, chunk, maxPer int64, delay time.Duration) error {
	_, low, high, err := c.Group(group)
	if err != nil {
		return err
	}
	lastPath := filepath.Join(dir, group+".last")
	start := low
	if b, err := os.ReadFile(lastPath); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n+1 > start {
			start = n + 1
		}
	}
	end := high
	if maxPer > 0 && start+maxPer-1 < end {
		end = start + maxPer - 1
	}
	if start > end {
		log.Printf("over: %s: nothing new (%d-%d, have up to %d)", group, low, high, start-1)
		return nil
	}
	log.Printf("over: %s: fetching %d-%d of %d-%d", group, start, end, low, high)
	total := 0
	for a := start; a <= end; a += chunk {
		b := min(a+chunk-1, end)
		lines, err := c.Over(a, b)
		if err != nil {
			return err
		}
		if len(lines) > 0 {
			if err := appendGzMember(filepath.Join(dir, group+".ov.gz"), lines); err != nil {
				return err
			}
		}
		if err := os.WriteFile(lastPath, []byte(strconv.FormatInt(b, 10)+"\n"), 0644); err != nil {
			return err
		}
		total += len(lines)
		if b < end {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				log.Printf("over: %s: stopped at %d, %d lines this run", group, b, total)
				return nil
			}
		}
	}
	log.Printf("over: %s: %d lines", group, total)
	return nil
}

// appendGzMember adds the lines to path as one complete gzip member, so a
// stopped run never leaves a cut-off member behind.
func appendGzMember(path string, lines []string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	w := bufio.NewWriter(gz)
	for _, l := range lines {
		w.WriteString(l)
		w.WriteByte('\n')
	}
	err = w.Flush()
	if e := gz.Close(); err == nil {
		err = e
	}
	if e := f.Close(); err == nil {
		err = e
	}
	return err
}

// ---- scan

func scan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	state := fs.String("state", "", "state directory (created if missing)")
	noOver := fs.Bool("no-over", false, "ignore fetched overview lines in DIR/over")
	fs.Parse(args)
	if *state == "" {
		return errors.New("need -state DIR")
	}
	if err := os.MkdirAll(*state, 0755); err != nil {
		return err
	}
	mboxes, err := mboxFiles(fs.Args())
	if err != nil {
		return err
	}
	var overFiles []string
	if !*noOver {
		overFiles, _ = filepath.Glob(filepath.Join(*state, overDir, "*.ov.gz"))
		sort.Strings(overFiles)
	}
	if len(mboxes) == 0 && len(overFiles) == 0 {
		return errors.New("nothing to scan: no mbox files given and no overview lines in DIR/over")
	}

	aw, err := createGz(filepath.Join(*state, articlesFile))
	if err != nil {
		return err
	}
	mw, err := createGz(filepath.Join(*state, itemsMbox))
	if err != nil {
		return err
	}
	ow, err := createGz(filepath.Join(*state, itemsOver))
	if err != nil {
		return err
	}
	seenMsg := map[uint64]uint8{} // 1 overview, 2 mbox
	mboxKeys := map[string]struct{}{}
	overKeys := map[string]struct{}{}
	var st struct{ over, mbox, both, dupMbox, dupOver, noMsgID, overBad int }
	start := time.Now()

	row := func(a sf.Article, src uint8) bool {
		key := a.MsgID
		if key == "" {
			st.noMsgID++
			key = fmt.Sprintf("nomid:%s:%d", a.Key, a.Date)
		}
		h := fnv.New64a()
		h.Write([]byte(key))
		k := h.Sum64()
		if prev, ok := seenMsg[k]; ok {
			switch {
			case prev != src:
				st.both++
			case src == 1:
				st.dupOver++ // a crosspost fetched from another group
			default:
				st.dupMbox++ // the same article in another group's file
			}
			return false
		}
		seenMsg[k] = src
		hash := a.BodyHash
		if hash == "" {
			hash = "-"
		}
		reply := "0"
		if a.Reply {
			reply = "1"
		}
		fmt.Fprintf(aw, "%s\t%s\t%s\t%d\t%d\t%s\t%s\n", tsvSafe(a.MsgID), a.Key, hash, a.Date, a.Groups, reply, tsvSafe(a.Source))
		return true
	}

	// overview first: its rows win for a Message-ID in both sources
	if len(overFiles) > 0 {
		format, err := readLines(filepath.Join(*state, overDir, overFmtFile))
		if err != nil {
			return err
		}
		ov, err := sf.NewOverview(format)
		if err != nil {
			return err
		}
		for _, path := range overFiles {
			group := strings.TrimSuffix(filepath.Base(path), ".ov.gz")
			n := 0
			err := readGzLines(path, func(line string) error {
				a, err := ov.Parse(line, group)
				if err != nil {
					st.overBad++
					return nil
				}
				n++
				st.over++
				if row(a, 1) {
					overKeys[a.Key] = struct{}{}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			log.Printf("%s: %d overview lines", path, n)
		}
	}
	// mbox files: rows for Message-IDs the server lacks, and the body text
	// for every key
	menc := json.NewEncoder(mw)
	menc.SetEscapeHTML(false)
	for _, path := range mboxes {
		n := 0
		err := sf.ReadFile(path, func(a sf.Article) error {
			n++
			st.mbox++
			row(a, 2)
			if _, ok := mboxKeys[a.Key]; ok {
				return nil
			}
			mboxKeys[a.Key] = struct{}{}
			return menc.Encode(a)
		})
		if err != nil {
			return err
		}
		log.Printf("%s: %d articles", path, n)
	}
	// overview items only for keys no mbox article has: those carry text
	if len(overKeys) > 0 {
		format, _ := readLines(filepath.Join(*state, overDir, overFmtFile))
		ov, _ := sf.NewOverview(format)
		oenc := json.NewEncoder(ow)
		oenc.SetEscapeHTML(false)
		for _, path := range overFiles {
			group := strings.TrimSuffix(filepath.Base(path), ".ov.gz")
			err := readGzLines(path, func(line string) error {
				a, err := ov.Parse(line, group)
				if err != nil {
					return nil
				}
				if _, ok := mboxKeys[a.Key]; ok {
					return nil
				}
				if _, ok := overKeys[a.Key]; !ok {
					return nil // already written
				}
				delete(overKeys, a.Key)
				return oenc.Encode(a)
			})
			if err != nil {
				return err
			}
		}
	}
	for _, w := range []*gzFile{aw, mw, ow} {
		if err := w.Close(); err != nil {
			return err
		}
	}
	log.Printf("scan: %d overview lines, %d mbox articles; %d Message-IDs in both, %d crosspost duplicates in the overview, %d in mbox files; %d without Message-ID, %d bad overview lines; %d articles, %d keys with mbox text; %s",
		st.over, st.mbox, st.both, st.dupOver, st.dupMbox, st.noMsgID, st.overBad, len(seenMsg), len(mboxKeys), time.Since(start).Round(time.Second))
	return nil
}

// mboxFiles expands directories into the mbox files under them.
func mboxFiles(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		fi, err := os.Stat(a)
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			out = append(out, a)
			continue
		}
		var found []string
		err = filepath.WalkDir(a, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			n := d.Name()
			if !d.IsDir() && (strings.HasSuffix(n, ".mbox") || strings.HasSuffix(n, ".mbox.gz") || strings.HasSuffix(n, ".mbox.zip")) {
				found = append(found, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(found)
		out = append(out, found...)
	}
	return out, nil
}

func tsvSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}

// ---- rules

func rules(args []string) error {
	fs := flag.NewFlagSet("rules", flag.ExitOnError)
	state := fs.String("state", "", "state directory")
	bi := fs.Float64("bi", sf.DefaultRules.BIThreshold, "Breidbart index at which an article is spam")
	days := fs.Int("window", 45, "window for the Breidbart index, in days")
	minLines := fs.Int("min-lines", sf.DefaultRules.MinLines, "shorter articles are not judged by the index")
	fs.Parse(args)
	if *state == "" {
		return errors.New("need -state DIR")
	}
	r := sf.Rules{BIThreshold: *bi, Window: time.Duration(*days) * 24 * time.Hour, MinLines: *minLines}

	cl := sf.NewClusters()
	perKey := map[string]int{}
	err := readArticles(*state, func(ar artRow) {
		cl.Add(ar.key, ar.hash, ar.date, ar.groups, ar.reply)
		perKey[ar.key]++
	})
	if err != nil {
		return err
	}
	out, err := os.Create(filepath.Join(*state, rulesFile+".tmp"))
	if err != nil {
		return err
	}
	w := bufio.NewWriter(out)
	reasons := map[string]int{}
	var items, spamItems, spamArticles int
	err = readItems(*state, func(a sf.Article) error {
		items++
		v, ok := r.Decide(a, cl.Index(a.Key, r.Window))
		if !ok {
			return nil
		}
		spamItems++
		spamArticles += perKey[a.Key]
		reasons[reasonKind(v.Reason)] += perKey[a.Key]
		return writeJSON(w, v)
	})
	if err != nil {
		out.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(out.Name(), filepath.Join(*state, rulesFile)); err != nil {
		return err
	}
	log.Printf("rules: %d of %d keys spam (%d articles); by rule, in articles: %s",
		spamItems, items, spamArticles, formatCounts(reasons))
	return nil
}

func reasonKind(r string) string {
	if strings.HasPrefix(r, "bi=") {
		return "bi"
	}
	return r
}

// ---- llm

func llm(args []string) error {
	fs := flag.NewFlagSet("llm", flag.ExitOnError)
	state := fs.String("state", "", "state directory")
	model := fs.String("model", "claude-haiku-5-5", "Claude model for the first pass")
	effort := fs.String("effort", "low", "effort for the first pass: low, medium, high, xhigh, max")
	thinking := fs.Bool("thinking", false, "let the first-pass model think (more output tokens; no accuracy gain measured on a 347-item test)")
	escalate := fs.String("escalate", "claude-sonnet-5-5", "model for what the first pass labels unsure or leaves unanswered (\"\" = none), e.g. claude-opus-5-5")
	escEffort := fs.String("escalate-effort", "low", "effort for the escalation model")
	escOn := fs.String("escalate-on", "unsure", "first-pass labels to send to the escalation model, comma-separated: unsure, spam, ham (unanswered items always go)")
	limit := fs.Int("limit", 1000, "items to label in this run, a random sample of the unlabelled ones (0 = all of them)")
	audit := fs.Int("audit", 0, "also send this many items the rules labelled, to check the rules against the model")
	batch := fs.Int("batch", 50, "articles per request")
	conc := fs.Int("concurrency", 4, "requests in flight")
	seed := fs.Uint64("seed", 1, "random seed for the sample")
	keyFile := fs.String("key-file", "~/.claude/spamfilter_apikey.txt", "file holding the API key (else ANTHROPIC_API_KEY)")
	workspace := fs.String("workspace", os.Getenv("ANTHROPIC_WORKSPACE_ID"), "workspace id, needed only for a key that is not scoped to a workspace")
	yes := fs.Bool("yes", false, "run the requests; without it, only show the sample size and a cost estimate")
	show := fs.Bool("show-prompt", false, "print the first request's user message and exit")
	fs.Parse(args)
	if *state == "" {
		return errors.New("need -state DIR")
	}

	ruled, err := readVerdicts(filepath.Join(*state, rulesFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	labelled, err := readVerdicts(filepath.Join(*state, llmFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	rng := rand.New(rand.NewPCG(*seed, *seed^0x9e3779b97f4a7c15))
	sample := newReservoir(*limit, rng)
	auditSample := newReservoir(*audit, rng)
	var open int
	err = readItems(*state, func(a sf.Article) error {
		if _, ok := labelled[a.Key]; ok {
			return nil
		}
		if _, ok := ruled[a.Key]; ok {
			if *audit > 0 {
				auditSample.add(a)
			}
			return nil
		}
		open++
		sample.add(a)
		return nil
	})
	if err != nil {
		return err
	}
	arts := append(sample.items, auditSample.items...)
	rng.Shuffle(len(arts), func(i, j int) { arts[i], arts[j] = arts[j], arts[i] })
	log.Printf("llm: %d items without a label, %d already labelled by the model, %d by rules; this run: %d (+%d audit)",
		open, len(labelled), len(ruled), len(sample.items), len(auditSample.items))
	if len(arts) == 0 {
		return nil
	}
	if *show {
		fmt.Print(sf.FormatBatch(arts[:min(*batch, len(arts))]))
		return nil
	}

	opts := []option.RequestOption{option.WithMaxRetries(5)}
	if key, err := readKey(*keyFile); err == nil {
		opts = append(opts, option.WithAPIKey(key))
	} else if os.Getenv("ANTHROPIC_API_KEY") == "" {
		return fmt.Errorf("no API key: %v, and ANTHROPIC_API_KEY is not set", err)
	}
	if *workspace != "" {
		opts = append(opts, option.WithHeader("anthropic-workspace-id", *workspace))
	}
	client := anthropic.NewClient(opts...)
	first := &sf.LLM{Client: client, Model: *model, Effort: *effort, BatchSize: *batch, Concurrency: *conc, NoThinking: !*thinking}
	var second *sf.LLM
	if *escalate != "" && *escalate != *model {
		second = &sf.LLM{Client: client, Model: *escalate, Effort: *escEffort, BatchSize: *batch, Concurrency: *conc}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if !*yes {
		return estimate(ctx, first, second, arts, *batch)
	}

	f, err := os.OpenFile(filepath.Join(*state, llmFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)

	// first pass; what it labels with an -escalate-on label or leaves
	// unanswered goes to the escalation model, whose line, written later,
	// wins when read back
	vs, err := runPass(ctx, first, arts, w)
	if err != nil {
		return err
	}
	if second == nil {
		return nil
	}
	byKey := map[string]sf.Article{}
	for _, a := range arts {
		byKey[a.Key] = a
	}
	escLabels := map[string]bool{"": true}
	for _, l := range strings.Split(*escOn, ",") {
		escLabels[strings.TrimSpace(l)] = true
	}
	var again []sf.Article
	for _, v := range vs {
		if escLabels[v.Label] {
			again = append(again, byKey[v.Key])
		}
	}
	if len(again) == 0 {
		return nil
	}
	log.Printf("llm: escalating %d of %d items to %s", len(again), len(arts), second.Model)
	_, err = runPass(ctx, second, again, w)
	return err
}

// runPass labels the articles with one model, appending each finished batch
// to w, and logs usage and cost. The verdicts come back in the order of arts;
// a missing answer has an empty Label.
func runPass(ctx context.Context, c *sf.LLM, arts []sf.Article, w *bufio.Writer) ([]sf.Verdict, error) {
	start := time.Now()
	var done, unlabelled int
	vs, err := c.Classify(ctx, arts, func(vs []sf.Verdict) {
		for _, v := range vs {
			if v.Label == "" {
				unlabelled++
				continue
			}
			v.MsgID = ""
			writeJSON(w, v)
			done++
		}
		w.Flush() // a stopped run keeps what it paid for
		log.Printf("llm %s: %d/%d labelled, %d requests, %s", c.Model, done, len(arts), c.Usage().Requests, time.Since(start).Round(time.Second))
	})
	w.Flush()
	u := c.Usage()
	labels := map[string]int{}
	for _, v := range vs {
		if v.Label != "" {
			labels[v.Label]++
		}
	}
	log.Printf("llm %s: %d labelled (%s), %d without a usable answer, %d requests, %d refused",
		c.Model, done, formatCounts(labels), unlabelled, u.Requests, u.Refusals)
	log.Printf("llm %s: input %d, cache write %d, cache read %d, output %d tokens",
		c.Model, u.Input, u.CacheWrite, u.CacheRead, u.Output)
	if p := priceOf(c.Model); p.in > 0 {
		cost := (float64(u.Input)+1.25*float64(u.CacheWrite)+0.1*float64(u.CacheRead))*p.in/1e6 + float64(u.Output)*p.out/1e6
		log.Printf("llm %s: cost ~$%.2f at list prices", c.Model, cost)
	}
	return vs, err
}

// estimate counts the tokens of one request (free) and extrapolates.
func estimate(ctx context.Context, first, second *sf.LLM, arts []sf.Article, batch int) error {
	sampleArts := arts[:min(batch, len(arts))]
	tok, err := first.CountTokens(ctx, sampleArts)
	if err != nil {
		return fmt.Errorf("counting tokens: %w", err)
	}
	perItem := float64(tok) / float64(len(sampleArts))
	inTok := perItem * float64(len(arts))
	outTok := float64(len(arts)) * 12 // the label lines; thinking comes on top
	log.Printf("estimate: %d requests, ~%.0f input tokens (%d for the first request of %d articles), ~%.0f output tokens plus thinking",
		(len(arts)+batch-1)/batch, inTok, tok, len(sampleArts), outTok)
	if p := priceOf(first.Model); p.in > 0 {
		log.Printf("estimate: first pass ~$%.2f input + ~$%.2f output at %s list prices ($%.2f / $%.2f per M tokens)",
			inTok*p.in/1e6, outTok*p.out/1e6, first.Model, p.in, p.out)
	}
	if second != nil {
		if p := priceOf(second.Model); p.in > 0 {
			n := float64(len(arts)) / 10
			log.Printf("estimate: escalation to %s, per 10%% of items sent: ~$%.2f", second.Model, (n*perItem*p.in+n*12*p.out)/1e6)
		}
	}
	log.Printf("estimate: thinking adds output tokens; nothing sent; add -yes to run")
	return nil
}

type price struct{ in, out float64 }

func priceOf(model string) price {
	in, out := sf.Price(model)
	return price{in, out}
}

func readKey(path string) (string, error) {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, path[2:])
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(b))
	if key == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return key, nil
}

type reservoir struct {
	n     int
	seen  int
	items []sf.Article
	rng   *rand.Rand
}

func newReservoir(n int, rng *rand.Rand) *reservoir { return &reservoir{n: n, rng: rng} }

// add keeps a uniform random sample of n items; n <= 0 keeps all.
func (r *reservoir) add(a sf.Article) {
	r.seen++
	if r.n <= 0 || len(r.items) < r.n {
		r.items = append(r.items, a)
		return
	}
	if j := r.rng.IntN(r.seen); j < r.n {
		r.items[j] = a
	}
}

// ---- export

func export(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	state := fs.String("state", "", "state directory")
	outPath := fs.String("o", "-", "output file, - for stdout")
	fs.Parse(args)
	if *state == "" {
		return errors.New("need -state DIR")
	}
	verdicts, err := mergedVerdicts(*state)
	if err != nil {
		return err
	}
	var out io.Writer = os.Stdout
	var file *os.File
	if *outPath != "-" {
		file, err = os.Create(*outPath + ".tmp")
		if err != nil {
			return err
		}
		out = file
	}
	w := bufio.NewWriter(out)
	counts := map[string]int{}
	var total int
	err = readArticles(*state, func(ar artRow) {
		total++
		v, ok := verdicts[ar.key]
		if !ok || ar.msgid == "" {
			counts["none"]++
			return
		}
		counts[v.Label]++
		rule, code := v.CleanfeedRule()
		writeJSON(w, struct {
			MsgID  string `json:"msgid"`
			Label  string `json:"label"`
			Stage  string `json:"stage"`
			Reason string `json:"reason"`
			Rule   string `json:"rule"`
			Code   string `json:"code"`
			Source string `json:"source"`
		}{ar.msgid, v.Label, v.Stage, v.Reason, rule, code, ar.source})
	})
	if err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if file != nil {
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Rename(file.Name(), *outPath); err != nil {
			return err
		}
	}
	log.Printf("export: %d articles: %s", total, formatCounts(counts))
	return nil
}

// mergedVerdicts gives one verdict per key: the rules' where they decided,
// the model's for the rest.
func mergedVerdicts(state string) (map[string]sf.Verdict, error) {
	m, err := readVerdicts(filepath.Join(state, llmFile))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if m == nil {
		m = map[string]sf.Verdict{}
	}
	ruled, err := readVerdicts(filepath.Join(state, rulesFile))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for k, v := range ruled {
		m[k] = v
	}
	return m, nil
}

// ---- stats

func stats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	state := fs.String("state", "", "state directory")
	show := fs.Int("show", 20, "print up to this many items where rules and model disagree")
	fs.Parse(args)
	if *state == "" {
		return errors.New("need -state DIR")
	}
	ruled, err := readVerdicts(filepath.Join(*state, rulesFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	labelled, err := readVerdicts(filepath.Join(*state, llmFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	byLabel, byReason := map[string]int{}, map[string]int{}
	for _, v := range labelled {
		byLabel[v.Label]++
		byReason[v.Reason]++
	}
	fmt.Printf("rules: %d items spam\n", len(ruled))
	fmt.Printf("model: %d items: %s\n", len(labelled), formatCounts(byLabel))
	fmt.Printf("model reasons: %s\n", formatCounts(byReason))
	var disagree []string
	both := 0
	for k, r := range ruled {
		if l, ok := labelled[k]; ok {
			both++
			if l.Label != r.Label {
				disagree = append(disagree, k)
			}
		}
	}
	if both == 0 {
		return nil
	}
	fmt.Printf("audit: %d items labelled by both, model disagrees with rules on %d\n", both, len(disagree))
	if len(disagree) == 0 || *show == 0 {
		return nil
	}
	want := map[string]bool{}
	for _, k := range disagree {
		want[k] = true
	}
	n := 0
	return readItems(*state, func(a sf.Article) error {
		if !want[a.Key] || n >= *show {
			return nil
		}
		n++
		fmt.Printf("\n%s rules=%s model=%s  %s\n  [%s] %s\n", a.Key, ruled[a.Key].Reason,
			labelled[a.Key].Reason, a.MsgID, a.Newsgroups, a.Subject)
		return nil
	})
}

// ---- state files

type gzFile struct {
	f  *os.File
	gz *gzip.Writer
	*bufio.Writer
	path string
}

// createGz writes to path.tmp and renames on Close, so a stopped scan
// leaves the old file in place.
func createGz(path string) (*gzFile, error) {
	f, err := os.Create(path + ".tmp")
	if err != nil {
		return nil, err
	}
	gz := gzip.NewWriter(f)
	return &gzFile{f: f, gz: gz, Writer: bufio.NewWriterSize(gz, 1<<20), path: path}, nil
}

func (g *gzFile) Close() error {
	err := g.Flush()
	if e := g.gz.Close(); err == nil {
		err = e
	}
	if e := g.f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return os.Rename(g.f.Name(), g.path)
}

func openGz(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		f.Close()
		return nil, err
	}
	return struct {
		io.Reader
		io.Closer
	}{gz, f}, nil
}

// readGzLines reads the lines of a (multi-member) gzip file. A member cut
// short at the end is reported and the lines before it are kept.
func readGzLines(path string, fn func(string) error) error {
	r, err := openGz(path)
	if err != nil {
		return err
	}
	defer r.Close()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<16), 1<<22)
	for sc.Scan() {
		if err := fn(sc.Text()); err != nil {
			return err
		}
	}
	if err := sc.Err(); errors.Is(err, io.ErrUnexpectedEOF) {
		log.Printf("%s: cut short at the end, lines before it kept", path)
		return nil
	} else {
		return err
	}
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

type artRow struct {
	msgid, key, hash string
	date             int64
	groups           int
	reply            bool
	source           string
}

func readArticles(state string, fn func(artRow)) error {
	return readGzLines(filepath.Join(state, articlesFile), func(line string) error {
		f := strings.Split(line, "\t")
		if len(f) != 7 {
			return nil
		}
		r := artRow{msgid: f[0], key: f[1], hash: f[2], reply: f[5] == "1", source: f[6]}
		if r.hash == "-" {
			r.hash = ""
		}
		r.date, _ = strconv.ParseInt(f[3], 10, 64)
		r.groups, _ = strconv.Atoi(f[4])
		fn(r)
		return nil
	})
}

// readItems gives one article per key: the mbox items, then the
// overview-only ones.
func readItems(state string, fn func(sf.Article) error) error {
	for _, name := range []string{itemsMbox, itemsOver} {
		r, err := openGz(filepath.Join(state, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		dec := json.NewDecoder(r)
		for {
			var a sf.Article
			if err := dec.Decode(&a); err == io.EOF {
				break
			} else if err != nil {
				r.Close()
				return fmt.Errorf("%s: %w", name, err)
			}
			if err := fn(a); err != nil {
				r.Close()
				return err
			}
		}
		r.Close()
	}
	return nil
}

// readVerdicts reads a verdict file; for a key given twice, the last line wins.
func readVerdicts(path string) (map[string]sf.Verdict, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := map[string]sf.Verdict{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		var v sf.Verdict
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil || v.Key == "" || v.Label == "" {
			continue // a line cut short by a stopped run
		}
		m[v.Key] = v
	}
	return m, sc.Err()
}

// writeJSON writes v as one line, with < > & left as they are, so
// Message-IDs stay greppable.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func formatCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return m[keys[i]] > m[keys[j]] || m[keys[i]] == m[keys[j]] && keys[i] < keys[j] })
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", k, m[k])
	}
	return strings.Join(parts, ", ")
}
