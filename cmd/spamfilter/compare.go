package main

import (
	"errors"
	"flag"
	"fmt"
	"sort"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

// compare puts two scans side by side: the spam rows by what flagged them,
// and the spot checks (audit) of the before database, looked up in the
// after one. The spot checks are a sample of before's flags (an even share
// per source) and of before's ham, labelled by the model API with the body.
func compare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	beforePath := fs.String("before", "", "database of the earlier scan (with the audit table)")
	afterPath := fs.String("after", "spamfilter.db", "database of the later scan")
	fs.Parse(args)
	if *beforePath == "" {
		return errors.New("need -before FILE")
	}
	before, err := sf.OpenStoreRO(*beforePath)
	if err != nil {
		return err
	}
	defer before.Close()
	after, err := sf.OpenStoreRO(*afterPath)
	if err != nil {
		return err
	}
	defer after.Close()

	// spam rows by class
	count := func(st *sf.Store) (map[string]int64, int64, error) {
		cs, err := st.SpamCounts()
		if err != nil {
			return nil, 0, err
		}
		m := map[string]int64{}
		var tot int64
		for _, c := range cs {
			cl := auditClass(c.Stage, c.Reason)
			if c.Reason == "bi" {
				cl = "bi"
			}
			m[cl] += c.N
			tot += c.N
		}
		return m, tot, nil
	}
	cb, tb, err := count(before)
	if err != nil {
		return err
	}
	ca, ta, err := count(after)
	if err != nil {
		return err
	}
	classes := []string{sf.StageModel, sf.StageNocem, "bi", "subj", sf.StageLLM}
	fmt.Printf("flagged Message-IDs        before        after\n")
	for _, c := range classes {
		fmt.Printf("  %-10s %16d %12d\n", c, cb[c], ca[c])
	}
	for c := range ca {
		if _, ok := cb[c]; !ok && !contains(classes, c) {
			fmt.Printf("  %-10s %16d %12d\n", c, cb[c], ca[c])
		}
	}
	fmt.Printf("  %-10s %16d %12d\n", "total", tb, ta)

	// the spot checks
	type cell struct{ spam, ham, unsure, spamAfter, hamAfter, unsureAfter int }
	by := map[string]*cell{}
	moved := map[string]int{} // before class -> after class, for flagged ham
	err = before.EachAudit(func(r sf.AuditRow) error {
		if r.Kind != "flagged" && r.Kind != "clean" {
			return nil // a later round (audit -tag)
		}
		k := "clean"
		if r.Kind == "flagged" {
			k = auditClass(r.Stage, r.Reason)
		}
		c := by[k]
		if c == nil {
			c = &cell{}
			by[k] = c
		}
		row, flagged, err := after.SpamByID(r.MsgID)
		if err != nil {
			return err
		}
		switch r.Label {
		case sf.Spam:
			c.spam++
			if flagged {
				c.spamAfter++
			}
		case sf.Ham:
			c.ham++
			if flagged {
				c.hamAfter++
				moved[k+" -> "+auditClass(row.Stage, row.Reason)]++
			}
		default:
			c.unsure++
			if flagged {
				c.unsureAfter++
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	pct := func(a, b int) string {
		if b == 0 {
			return "     -"
		}
		return fmt.Sprintf("%5.1f%%", 100*float64(a)/float64(b))
	}
	fmt.Printf("\nspot checks (label with the body)   spam: flagged after    ham: flagged after\n")
	var estB, estA, hamB, hamA float64 // flagged rows, of them ham: estimated from the samples
	for _, k := range append(classes, "clean") {
		c := by[k]
		if c == nil {
			continue
		}
		n := c.spam + c.ham + c.unsure
		fmt.Printf("  %-8s %5d checked: %5d spam %s    %5d ham %s\n", k, n, c.spam, pct(c.spamAfter, c.spam), c.ham, pct(c.hamAfter, c.ham))
		if k != "clean" && n > 0 {
			N := float64(cb[k])
			estB += N
			hamB += N * float64(c.ham) / float64(n)
			estA += N * float64(c.spamAfter+c.hamAfter+c.unsureAfter) / float64(n)
			hamA += N * float64(c.hamAfter) / float64(n)
		}
	}
	if estB > 0 {
		fmt.Printf("\nbefore's %0.f flags: about %.1fM ham by the spot checks (%.1f%%)\n", estB, hamB/1e6, 100*hamB/estB)
		fmt.Printf("of them still flagged after: about %.1fM, %.1fM of them ham (%.1f%%)\n", estA/1e6, hamA/1e6, 100*hamA/max(estA, 1))
		fmt.Printf("after flags %.1fM more that before had not flagged (from before's uncertain and ham; the clean row above samples the ham)\n",
			(float64(ta)-estA)/1e6)
	}
	if len(moved) > 0 {
		var ks []string
		for k := range moved {
			ks = append(ks, k)
		}
		sort.Slice(ks, func(i, j int) bool { return moved[ks[i]] > moved[ks[j]] })
		fmt.Printf("\nham still flagged, by what flags it now:")
		for _, k := range ks {
			fmt.Printf(" %s %d,", k, moved[k])
		}
		fmt.Println()
	}
	return nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
