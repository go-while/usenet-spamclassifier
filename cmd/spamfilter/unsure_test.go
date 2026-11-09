package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

func testModel(t *testing.T, dir string) string {
	t.Helper()
	var ex []sf.Example
	for i := 0; i < 400; i++ {
		a := sf.Article{Subject: fmt.Sprintf("question %d about gardening", i), From: "u@example.org", Newsgroups: "g1", Groups: 1, Lines: 10}
		if i%2 == 0 {
			a.Subject, a.From = "cheap pills online now", "x@spam.example"
		}
		ex = append(ex, sf.Example{A: a, Spam: i%2 == 0})
	}
	m, _, err := sf.Train(ex, 16, 3, 0.9, 0.9, 1)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "m.model")
	if err := m.Save(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUnsurePass(t *testing.T) {
	addr := fakeServer(t, 12, 300)
	dir := t.TempDir()
	modelPath := testModel(t, dir)
	db := filepath.Join(dir, "u.db")
	args := []string{"-server", addr, "-db", db, "-mode", "unsure", "-model-file", modelPath, "-chunk", "70",
		"-groups", "*", "-nocem-types", "", "-ham-every", "1", "-conns", "2"}

	count := func() (u, h int) {
		err := sf.ReadCandidates(db+".unsure", func(_ int, c sf.Candidate) error {
			if c.Kind == sf.CandUnsure {
				u++
			} else {
				h++
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := run(append(args, "-share", "0.5")); err != nil {
		t.Fatal(err)
	}
	u1, h1 := count()
	// the picked chunks: articles not flagged by the subject rule (every
	// 7th) in their home group (the crossposts' second copies are skipped)
	want := 0
	for g := 0; g < 12; g++ {
		for a0 := int64(1); a0 <= 300; a0 += 70 {
			if !unsurePicked(fmt.Sprintf("g%d", g), a0, 0.5, 0) {
				continue
			}
			for i := a0; i <= min(a0+69, 300); i++ {
				if i%7 != 0 {
					want++
				}
			}
		}
	}
	if u1+h1 != want || want == 0 {
		t.Fatalf("share 0.5: %d uncertain + %d ham kept, want %d in all", u1, h1, want)
	}
	// a second run continues: nothing left to read
	if err := run(append(args, "-share", "0.5")); err != nil {
		t.Fatal(err)
	}
	if u2, h2 := count(); u2 != u1 || h2 != h1 {
		t.Fatalf("second run added candidates: %d/%d, was %d/%d", u2, h2, u1, h1)
	}
	st, err := sf.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, spam, _ := st.Counts()
	st.Close()
	if spam != 0 {
		t.Fatalf("unsure mode wrote %d spam rows", spam)
	}
	if u1 > 0 {
		if err := labelUnsure([]string{"-db", db, "-dry"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rescore([]string{"-db", db, "-model-file", modelPath}); err != nil {
		t.Fatal(err)
	}
}

func TestFetcher(t *testing.T) {
	addr := fakeServer(t, 3, 50)
	f := &fetcher{server: addr, timeout: 0}
	defer f.drop()
	items := []fetchItem{{"g2", 5}, {"g0", 7}, {"g2", 3}, {"g0", 99}}
	got := map[int]sf.Article{}
	miss, err := f.fetch(items, func(i int, head, body []string) {
		base := sf.Article{MsgID: fmt.Sprintf("<%s.%d@x>", strings.TrimPrefix(items[i].group, "g"), items[i].num), NoBody: true}
		a, ok := withBody(base, head, body)
		if !ok {
			t.Errorf("item %d: Message-ID mismatch", i)
		}
		got[i] = a
	})
	if err != nil {
		t.Fatal(err)
	}
	// the fake answers article 99 too (it has no "no such article"), so
	// all four arrive
	if miss != 0 || len(got) != 4 {
		t.Fatalf("missing %d, got %d", miss, len(got))
	}
	if a := got[0]; a.NoBody || !strings.Contains(a.Snippet, "text") {
		t.Fatalf("no body: %+v", a)
	}
	// a renumbered article is not taken for the one meant
	if _, ok := withBody(sf.Article{MsgID: "<other@x>"}, []string{"Message-ID: <1.1@x>"}, []string{"x"}); ok {
		t.Fatal("Message-ID mismatch accepted")
	}
}

func TestJudgementOrder(t *testing.T) {
	m, err := sf.LoadModel(testModel(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	hamA := sf.Article{MsgID: "<h@x>", Key: "kh", Subject: "question 3 about gardening", From: "u@example.org", Newsgroups: "g1", Groups: 1, Lines: 10}
	spamA := sf.Article{MsgID: "<s@x>", Key: "ks", Subject: "cheap pills online now", From: "x@spam.example", Newsgroups: "g1", Groups: 1, Lines: 10}
	if l, _ := m.Decide(hamA); l != sf.Ham {
		t.Fatalf("test model calls the ham %q", l)
	}
	j := judgement{rules: sf.DefaultRules, model: m,
		verdict: func(k string) (sf.Verdict, bool) {
			if k == "kh" {
				return sf.Verdict{Label: sf.Ham, Stage: sf.StageLLM, Reason: "ham:discussion"}, true
			}
			return sf.Verdict{}, false
		},
		nocem: func(string) bool { return true },
		bi:    func(sf.Article) (float32, bool) { return 30, true },
	}
	// a label beats the NoCeM listing
	if l, st, _ := j.judge(hamA); l != sf.Ham || st != sf.StageLLM {
		t.Fatalf("labelled ham: %s %s", l, st)
	}
	j.nocem = nil
	j.verdict = nil
	// a Breidbart copy is spam, unless the model calls it ham
	if l, _, _ := j.judge(hamA); l != sf.Ham {
		t.Fatalf("ham copy flagged: %s", l)
	}
	if l, st, r := j.judge(spamA); l != sf.Spam || (st != sf.StageModel && st != sf.StageRules) {
		t.Fatalf("spam copy: %s %s %s", l, st, r)
	}
	uncertain := sf.Article{MsgID: "<u@x>", Key: "ku", Subject: "zzz qqq", From: "n@n.example", Newsgroups: "g9", Groups: 1, Lines: 10}
	if l, _ := m.Decide(uncertain); l == "" {
		if l, st, r := j.judge(uncertain); l != sf.Spam || st != sf.StageRules || r != "bi=30.0" {
			t.Fatalf("uncertain copy: %s %s %s", l, st, r)
		}
	}
}

func TestCompare(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, rows []sf.SpamRow) string {
		p := filepath.Join(dir, name)
		st, err := sf.OpenStore(p)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if err := st.AddSpam(rows); err != nil {
			t.Fatal(err)
		}
		if err := st.AddAudit([]sf.AuditRow{
			{MsgID: "<a@x>", Kind: "flagged", Group: "g", ArtNum: 1, Stage: sf.StageModel, Reason: "p=0.99", Label: sf.Ham},
			{MsgID: "<b@x>", Kind: "flagged", Group: "g", ArtNum: 2, Stage: sf.StageModel, Reason: "p=0.99", Label: sf.Spam},
		}); err != nil {
			t.Fatal(err)
		}
		return p
	}
	b := mk("b.db", []sf.SpamRow{{MsgID: "<a@x>", Key: "a", Group: "g", ArtNum: 1, Stage: sf.StageModel, Reason: "p=0.99"},
		{MsgID: "<b@x>", Key: "b", Group: "g", ArtNum: 2, Stage: sf.StageModel, Reason: "p=0.99"}})
	a := mk("a.db", []sf.SpamRow{{MsgID: "<b@x>", Key: "b", Group: "g", ArtNum: 2, Stage: sf.StageModel, Reason: "p=0.99"}})
	if err := compare([]string{"-before", b, "-after", a}); err != nil {
		t.Fatal(err)
	}
	if err := labelFlagged([]string{"-db", b, "-class", "model", "-dry"}); err != nil {
		t.Fatal(err)
	}
}
