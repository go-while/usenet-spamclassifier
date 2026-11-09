package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

// relabel sends stored API verdicts through the model again, with the
// article bodies, by the Message Batches API: the spam labels in groups
// made for offers and in the anti-spam groups, where the first labels
// were most often wrong. The new verdicts replace the old ones.
func relabel(args []string) error {
	fs := flag.NewFlagSet("relabel", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database")
	server := fs.String("server", "", "news server HOST:PORT for the article bodies")
	label := fs.String("label", sf.Spam, "relabel verdicts with this label")
	modelWas := fs.String("model-was", "", "only verdicts this model gave (\"\" = any)")
	before := fs.String("before", "", "only verdicts stored before this time (RFC 3339 UTC, as stored): a restart does not redo what is done")
	after := fs.String("after", "", "only verdicts stored at or after this time")
	offers := fs.Bool("offers", true, "only articles posted to a group made for offers (sales, jobs, ads) or to an anti-spam group")
	maxMbit := fs.Float64("max-mbit", 100, "cap on the download from the news server (0 = none)")
	timeout := fs.Duration("timeout", 2*time.Minute, "network timeout")
	compress := fs.Bool("compress", true, "COMPRESS DEFLATE when the server offers it")
	batchArts := fs.Int("batch-articles", 100000, "articles per Message Batch")
	inFlight := fs.Int("in-flight", 6, "Message Batches waiting at a time")
	fetchConns := fs.Int("fetch-conns", 3, "server connections fetching articles")
	jobsDir := fs.String("jobs-dir", "", "where submitted batches are kept until their results are stored (default: the database path + \".relabel\")")
	stopAfter := fs.Int64("stop-after", 1<<62, "stop submitting after this many labels")
	dry := fs.Bool("dry", false, "only count what would be sent and estimate the cost")
	var lf labelFlags
	lf.register(fs, "", "")
	fs.Parse(args)
	if *jobsDir == "" {
		*jobsDir = *dbPath + ".relabel"
	}
	st, err := sf.OpenStore(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	jobs, err := loadJobs(*jobsDir)
	if err != nil {
		return err
	}
	inJob := map[string]bool{}
	for _, j := range jobs {
		for _, r := range j.Reqs {
			for _, a := range r {
				inJob[a.Key] = true
			}
		}
	}

	t0 := time.Now()
	var arts []sf.Article
	var seen int64
	err = st.EachVerdictArticle(*label, sf.StageLLM, func(v sf.VerdictArticle) error {
		seen++
		switch {
		case *modelWas != "" && v.Model != *modelWas,
			*before != "" && v.At >= *before,
			*after != "" && v.At < *after,
			v.MsgID == "", inJob[v.Key],
			*offers && !offerGroup.MatchString(v.Newsgroups) && !sf.InAntiSpamGroup(v.Newsgroups):
			return nil
		}
		a := v.Article
		a.NoBody = true
		arts = append(arts, a)
		return nil
	})
	if err != nil {
		return err
	}
	ids := make([]string, len(arts))
	for i, a := range arts {
		ids[i] = a.MsgID
	}
	loc, err := st.SpamLocation(ids)
	if err != nil {
		return err
	}
	kept := arts[:0]
	for _, a := range arts {
		if src, ok := loc[a.MsgID]; ok {
			a.Source = src
			kept = append(kept, a)
		}
	}
	log.Printf("relabel: %d %s verdicts, %d chosen, %d of them with a known place on the server (%s); %d batches of an earlier run in flight",
		seen, *label, len(arts), len(kept), time.Since(t0).Round(time.Second), len(jobs))
	arts = kept
	if *dry {
		fmt.Printf("relabel: would send %d articles to %s: about $%.2f\n", len(arts), lf.model, float64(len(arts))*batchCost(lf.model, lf.think))
		return nil
	}
	if *server == "" {
		return errors.New("need -server HOST:PORT")
	}
	lab, err := lf.labeler(st)
	if err != nil {
		return err
	}
	lab.first.Batch = true
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	limit := sf.NewLimiter(*maxMbit)
	var fsx []*fetcher
	for range max(*fetchConns, 1) {
		f := &fetcher{server: *server, timeout: *timeout, limit: limit, compress: *compress}
		defer f.drop()
		fsx = append(fsx, f)
	}
	return batchRun(ctx, lab, &lf, *jobsDir, jobs, sliceSource(arts), fsx, *batchArts, *inFlight, *stopAfter)
}
