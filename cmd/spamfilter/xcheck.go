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
	"strings"
	"sync"
	"syscall"
	"time"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

// ---- xcheck: a Claude model labels again what audit-openai checked in
// chosen hierarchies, to see whether the scan or the OpenAI model is wrong
// where they disagree. The verdicts are not stored in the scan's database
// (only the spend is, so the budget counts all runs); the labels go to the
// audit-openai database as kind xcheck-TAG.

func xcheck(args []string) error {
	fs := flag.NewFlagSet("xcheck", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "the scan's database: the spend is added there, nothing else")
	outPath := fs.String("out", "spamfilter-openai.db", "the audit-openai database: read its rows, store the new labels")
	from := fs.String("from", "flagged-luna", "kind of the rows to check again")
	hiers := fs.String("hier", "relcom,de,nl,fr,it,pl,biz,uk,free", "hierarchies to check, comma-separated")
	per := fs.Int("per", 3000, "at most this many rows per hierarchy (a random pick)")
	server := fs.String("server", "", "news server, HOST:PORT")
	conns := fs.Int("conns", 4, "connections to the news server")
	maxMbit := fs.Float64("max-mbit", 200, "cap on the download from the news server (0 = none)")
	timeout := fs.Duration("timeout", 2*time.Minute, "network timeout")
	compress := fs.Bool("compress", true, "COMPRESS DEFLATE when the server offers it")
	tag := fs.String("tag", "haiku", "the labels are stored as kind xcheck-TAG")
	seed := fs.Uint64("seed", uint64(time.Now().UnixNano()), "random seed")
	report := fs.Bool("report", false, "only print the results stored so far")
	var lf labelFlags
	lf.register(fs, "", "")
	fs.Parse(args)

	out, err := sf.OpenStore(*outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	kind := "xcheck-" + *tag
	if *report {
		return xcheckReport(out, *from, kind)
	}
	if *server == "" {
		return errors.New("need -server HOST:PORT")
	}
	want := map[string]bool{}
	for _, h := range splitList(*hiers) {
		want[h] = true
	}
	done := map[string]bool{}
	byHier := map[string][]sf.AuditRow{}
	err = out.EachAudit(func(r sf.AuditRow) error {
		switch {
		case r.Kind == kind:
			done[r.MsgID] = true
		case r.Kind == *from && want[sf.Hierarchy(r.Group)]:
			byHier[sf.Hierarchy(r.Group)] = append(byHier[sf.Hierarchy(r.Group)], r)
		}
		return nil
	})
	if err != nil {
		return err
	}
	rng := rand.New(rand.NewPCG(*seed, *seed^0x2545f4914f6cdd1d))
	var rows []sf.AuditRow
	picked := map[string]int{}
	for h, rs := range byHier {
		rng.Shuffle(len(rs), func(i, j int) { rs[i], rs[j] = rs[j], rs[i] })
		n := 0
		for _, r := range rs {
			if n >= *per {
				break
			}
			n++ // rows done earlier count toward -per
			if !done[r.MsgID] {
				rows = append(rows, r)
				picked[h]++
			}
		}
	}
	rng.Shuffle(len(rows), func(i, j int) { rows[i], rows[j] = rows[j], rows[i] })
	log.Printf("xcheck: %d to check: %s", len(rows), formatCountsInt(picked))

	st, err := sf.OpenStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	lab, err := lf.labeler(st)
	if err != nil {
		return err
	}
	lab.dry = true
	if lab.spent >= lf.budget {
		log.Printf("xcheck: $%.2f spent of $%.2f in %s; nothing to do", lab.spent, lf.budget, *dbPath)
		return xcheckReport(out, *from, kind)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	limit := sf.NewLimiter(*maxMbit)
	fetchers := make([]*fetcher, max(*conns, 1))
	for i := range fetchers {
		fetchers[i] = &fetcher{server: *server, timeout: *timeout, limit: limit, compress: *compress}
		defer fetchers[i].drop()
	}
	const block = 2000
	var checked, missing int
	for b := 0; b < len(rows) && ctx.Err() == nil; b += block {
		if lab.spent >= lf.budget {
			log.Printf("xcheck: budget reached ($%.2f of $%.2f)", lab.spent, lf.budget)
			break
		}
		blk := rows[b:min(b+block, len(rows))]
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
					ids = append(ids, blk[i].MsgID)
				}
				f.fetchIDs(ids, func(k int, head, body []string) {
					i := idx[k]
					if a, good := articleFor(sf.Article{MsgID: blk[i].MsgID}, head, body); good {
						arts[i], ok[i] = a, true
					}
				})
			}(j, f)
		}
		wg.Wait()
		var res []sf.AuditRow
		for i := range blk {
			if !ok[i] {
				missing++
				continue
			}
			r := blk[i]
			lab.add(arts[i], func(v sf.Verdict) {
				x := r
				x.Kind, x.Label, x.Why, x.Model = kind, v.Label, v.Reason, v.Model
				res = append(res, x)
			})
		}
		ferr := lab.flush(ctx)
		if err := out.AddAudit(res); err != nil {
			return err
		}
		checked += len(res)
		log.Printf("xcheck: %d of %d checked (%d not on the server), $%.2f spent in all (this run $%.2f)",
			checked, len(rows), missing, lab.spent, lab.own)
		if ferr != nil && ctx.Err() == nil {
			return ferr
		}
	}
	return xcheckReport(out, *from, kind)
}

func xcheckReport(out *sf.Store, from, kind string) error {
	first := map[string]string{} // msgid: the label of the -from row
	type row struct{ class, msgid, label string }
	var rows []row
	err := out.EachAudit(func(r sf.AuditRow) error {
		switch r.Kind {
		case from:
			first[r.MsgID] = r.Label
		case kind:
			rows = append(rows, row{class: auditClass(r.Stage, r.Reason) + " " + sf.Hierarchy(r.Group), msgid: r.MsgID, label: r.Label})
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("no", kind, "rows stored")
		return nil
	}
	type cnt struct{ n, spamX, spamF, agree int }
	by := map[string]*cnt{}
	tot := &cnt{}
	for _, r := range rows {
		f, ok := first[r.msgid]
		if !ok {
			continue
		}
		for _, c := range []*cnt{tot, by[r.class]} {
			if c == nil {
				c = &cnt{}
				by[r.class] = c
			}
			c.n++
			if r.label == sf.Spam {
				c.spamX++
			}
			if f == sf.Spam {
				c.spamF++
			}
			if (r.label == sf.Spam) == (f == sf.Spam) {
				c.agree++
			}
		}
	}
	var ks []string
	for k, c := range by {
		if c.n >= 50 {
			ks = append(ks, k)
		}
	}
	sort.Slice(ks, func(i, j int) bool { return by[ks[i]].n > by[ks[j]].n })
	name := strings.TrimPrefix(kind, "xcheck-")
	firstName := from[strings.LastIndexByte(from, '-')+1:]
	fmt.Printf("flagged articles labelled by both: share each calls spam, and how often they agree (spam or not)\n")
	fmt.Printf("  %-22s %6s  %8s  %8s  %6s\n", "flagged by, hierarchy", "n", name, firstName, "agree")
	pr := func(k string, c *cnt) {
		p := func(x int) float64 { return 100 * float64(x) / float64(c.n) }
		fmt.Printf("  %-22s %6d  %7.1f%%  %7.1f%%  %5.1f%%\n", k, c.n, p(c.spamX), p(c.spamF), p(c.agree))
	}
	for _, k := range ks {
		pr(k, by[k])
	}
	pr("all", tot)
	return nil
}
