package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

// offerGroup matches groups made for offers: sales, jobs, ads,
// classifieds. The API labels in them were the ones the spot checks
// disagreed with most (Haiku called on-topic offers spam).
var offerGroup = regexp.MustCompile(`(?i)(^|[.,]\s*)(forsale|for-sale|sale|sales|market|marketplace|markt|job|jobs|offered|wanted|stellen|emploi|banen|announce|ads|ogloszenia|commerce|biete|verkaufe|kleinanzeigen|classified|classifieds)([.,]|$)|(^|,)\s*biz\.`)

// recheck labels spot-checked articles again with the first-pass model,
// without storing anything, and prints how the new labels compare with
// the spot check's (which a stronger model settled where they disagreed
// with the scan). For trying prompt changes and request sizes cheaply.
func recheck(args []string) error {
	fs := flag.NewFlagSet("recheck", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database")
	server := fs.String("server", "", "news server HOST:PORT for the article bodies")
	kind := fs.String("kind", "flagged-after3", "spot-check rows of this kind")
	stage := fs.String("stage", "llm", "only rows the scan flagged this way (\"\" = all)")
	n := fs.Int("n", 0, "check at most this many rows (0 = all)")
	maxMbit := fs.Float64("max-mbit", 100, "cap on the download from the news server (0 = none)")
	timeout := fs.Duration("timeout", 2*time.Minute, "network timeout")
	compress := fs.Bool("compress", true, "COMPRESS DEFLATE when the server offers it")
	out := fs.String("out", "", "also write one line per article to this file: Message-ID, group, spot check label, new label, new reason")
	var lf labelFlags
	lf.register(fs, "", "")
	fs.Parse(args)
	if *server == "" {
		return errors.New("need -server HOST:PORT")
	}
	st, err := sf.OpenStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	var rows []sf.AuditRow
	err = st.EachAudit(func(r sf.AuditRow) error {
		if r.Kind == *kind && (*stage == "" || r.Stage == *stage) && (*n == 0 || len(rows) < *n) {
			rows = append(rows, r)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("no spot-check rows of kind %q", *kind)
	}
	lab, err := lf.labeler(st)
	if err != nil {
		return err
	}
	lab.dry = true
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	f := &fetcher{server: *server, timeout: *timeout, limit: sf.NewLimiter(*maxMbit), compress: *compress}
	defer f.drop()

	items := make([]fetchItem, len(rows))
	for i, r := range rows {
		items[i] = fetchItem{r.Group, r.ArtNum}
	}
	got, why := make([]string, len(rows)), make([]string, len(rows))
	if _, err := f.fetch(items, func(i int, head, body []string) {
		a := sf.NewArticle(head, body, -1)
		if a.MsgID != rows[i].MsgID {
			return
		}
		lab.add(a, func(v sf.Verdict) { got[i], why[i] = v.Label, v.Reason })
	}); err != nil {
		return err
	}
	if err := lab.flush(ctx); err != nil {
		return err
	}
	if *out != "" {
		var b strings.Builder
		for i, r := range rows {
			if got[i] != "" {
				fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\n", r.MsgID, r.Group, r.Label, got[i], why[i])
			}
		}
		if err := os.WriteFile(*out, []byte(b.String()), 0o644); err != nil {
			return err
		}
	}
	// rows: what the spot check said; columns: the new label
	type tab map[string]map[string]int
	byPart := map[string]tab{}
	labels := []string{sf.Spam, sf.Ham, sf.Unsure}
	for i, r := range rows {
		if got[i] == "" {
			continue
		}
		part := "other groups"
		if offerGroup.MatchString(r.Group) {
			part = "offer groups"
		}
		for _, p := range []string{"all", part} {
			t := byPart[p]
			if t == nil {
				t = tab{}
				byPart[p] = t
			}
			if t[r.Label] == nil {
				t[r.Label] = map[string]int{}
			}
			t[r.Label][got[i]]++
		}
	}
	fmt.Printf("recheck %s/%s with %s (effort %s, thinking %v), %d per request: $%.2f this run\n", *kind, *stage, lf.model, lf.effort, lf.think, lf.batch, lab.own)
	for _, p := range []string{"all", "offer groups", "other groups"} {
		t := byPart[p]
		if t == nil {
			continue
		}
		var tot, agree int
		var b strings.Builder
		for _, want := range labels {
			var row int
			for _, g := range labels {
				row += t[want][g]
			}
			if row == 0 {
				continue
			}
			tot += row
			agree += t[want][want]
			fmt.Fprintf(&b, "    spot check %-6s %5d: now spam %5d  ham %5d  unsure %5d\n", want, row, t[want][sf.Spam], t[want][sf.Ham], t[want][sf.Unsure])
		}
		fmt.Printf("  %s: %d, agree %.1f%%\n%s", p, tot, 100*float64(agree)/float64(tot), b.String())
	}
	return nil
}
