package spamfilter

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHistoryHash(t *testing.T) {
	for msgid, want := range map[string]string{
		"<AbC@Example.COM>":        "3D8173D6CDC621D87B2EB8AC6BAE0CDB", // local part keeps its case
		"<PostMaster@Example.COM>": "C679D34180D07337F830F22313745635", // postmaster is case-insensitive
		"<NoAt-Here>":              "B865E8944403667620D9EAB8AF0B77B5",
	} {
		if got := HistoryHash(msgid); got != want {
			t.Errorf("%s: %s, want %s", msgid, got, want)
		}
	}
	if l := HistoryLine("<AbC@Example.COM>", 1700000000, 1056475812); l != "[3D8173D6CDC621D87B2EB8AC6BAE0CDB]\t1700000000~-~1056475812\n" {
		t.Errorf("line %q", l)
	}
	if l := HistoryLine("<AbC@Example.COM>", 1700000000, 0); l != "[3D8173D6CDC621D87B2EB8AC6BAE0CDB]\t1700000000~-\n" {
		t.Errorf("line without posted %q", l)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetGroupRange("de.test", 1, 100); err != nil {
		t.Fatal(err)
	}
	if err := st.GroupProgress("de.test", 50, 40, 3); err != nil {
		t.Fatal(err)
	}
	g, ok, err := st.Group("de.test")
	if err != nil || !ok || g.Done != 50 || g.Articles != 40 || g.SpamCount != 3 {
		t.Fatalf("group %+v %v %v", g, ok, err)
	}
	st.SetGroupRange("de.test", 1, 200) // keeps progress
	if g, _, _ = st.Group("de.test"); g.Done != 50 || g.High != 200 {
		t.Errorf("after new range: %+v", g)
	}
	arts := []Article{{Key: "k1", Subject: "MAKE MONEY", MsgID: "<1@x>"}, {Key: "k2", Subject: "hi"}}
	if err := st.PutVerdicts(arts, []Verdict{{Key: "k1", Label: Spam, Stage: StageLLM, Reason: "spam:mmf"}, {Key: "k2"}}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.HasVerdict("k1"); !ok {
		t.Error("k1 not stored")
	}
	if v, ok, err := st.Verdict("k1"); err != nil || !ok || v.Label != Spam || v.Reason != "spam:mmf" {
		t.Errorf("Verdict(k1) = %+v %v %v", v, ok, err)
	}
	if ok, _ := st.HasVerdict("k2"); ok {
		t.Error("an empty verdict was stored")
	}
	rows := []SpamRow{{MsgID: "<1@x>", Key: "k1", Group: "de.test", ArtNum: 7, Posted: 5, Stage: "rules", Reason: "subj:mmf"}}
	if err := st.AddSpam(append(rows, rows...)); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	n, err := WriteHistory(&b, st, 9, nil)
	if err != nil || n != 1 || b.String() != HistoryLine("<1@x>", 9, 5) {
		t.Errorf("history %d %q %v", n, b.String(), err)
	}
	st.AddSpend("m", Usage{Requests: 1, Input: 1000}, 0.5)
	st.AddSpend("m", Usage{Requests: 1, Input: 1000}, 0.25)
	if usd, _ := st.Spent(); usd != 0.75 {
		t.Errorf("spent %v", usd)
	}
}

func TestTrainSeparates(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	spamSubj := []string{"MAKE MONEY FAST %d", "cheap replica watches %d", "$$$ earn cash now %d", "paid surveys online %d"}
	hamSubj := []string{"Re: question about %d", "Wie konfiguriere ich %d", "help with compiler error %d", "meeting notes %d"}
	var ex []Example
	for i := 0; i < 2000; i++ {
		spam := rng.IntN(4) == 0
		s := hamSubj[rng.IntN(4)]
		from := fmt.Sprintf("user%d@uni%d.example.edu", i, i%7)
		if spam {
			s = spamSubj[rng.IntN(4)]
			from = fmt.Sprintf("deals%d@bulk-mail.example", i)
		}
		ex = append(ex, Example{A: Article{Subject: fmt.Sprintf(s, i), From: from, Newsgroups: "misc.test", Groups: 1, Lines: 10}, Spam: spam})
	}
	m, rep, err := Train(ex, 18, 4, 0.98, 0.98, 1)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Precision < 0.98 || rep.Recall < 0.9 || rep.HamPrecision < 0.98 {
		t.Errorf("report %+v", rep)
	}
	if l, _ := m.Decide(Article{Subject: "MAKE MONEY FAST 99999", From: "deals99999@bulk-mail.example", Newsgroups: "misc.test", Groups: 1, Lines: 10}); l != Spam {
		t.Errorf("obvious spam: %q", l)
	}
	path := filepath.Join(t.TempDir(), "m")
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	m2, err := LoadModel(path)
	if err != nil {
		t.Fatal(err)
	}
	a := ex[0].A
	if m.Logit(a) != m2.Logit(a) || m2.SpamAt != m.SpamAt {
		t.Error("loaded model differs")
	}
}

func TestBreidbartPasses(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenBIWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	spam := Article{Key: "k-spam", Lines: 10, Groups: 4, Date: 1056475812}
	faq := Article{Key: "k-faq", Lines: 50, Groups: 9}
	reply := Article{Key: "k-re", Lines: 10, Groups: 1, Reply: true, Date: 1056475812}
	short := Article{Key: "k-short", Lines: 1, Groups: 1}
	if _, ok := BIKey(reply, 3); ok {
		t.Error("reply counted")
	}
	if _, ok := BIKey(short, 3); ok {
		t.Error("short article counted")
	}
	ks, _ := BIKey(spam, 3)
	// 12 copies to 4 groups (index 24) in one month, spread over 3 chunks;
	// chunk 2 is written twice, as after a stopped run, and counts once
	for c, n := range []int{4, 4, 4} {
		if err := w.Add(uint32(c), map[uint64]float32{ks: float32(n) * 2}); err != nil {
			t.Fatal(err)
		}
	}
	w.Add(2, map[uint64]float32{ks: 8})
	// a monthly FAQ to 9 groups (3 each): one copy per month never adds up
	for m := 0; m < 24; m++ {
		a := faq
		a.Date = time.Date(2000, time.Month(1+m), 15, 0, 0, 0, 0, time.UTC).Unix()
		k, _ := BIKey(a, 3)
		w.Add(uint32(100+m), map[uint64]float32{k: 3})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	keys, st, err := AggregateBI(dir, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[ks] != 24 || st.Keys != 25 {
		t.Errorf("keys %v, stats %+v", keys, st)
	}
	p := filepath.Join(dir, "keys")
	if err := SaveBIKeys(p, keys); err != nil {
		t.Fatal(err)
	}
	back, err := LoadBIKeys(p)
	if err != nil || len(back) != 1 || back[ks] != 24 {
		t.Errorf("loaded %v %v", back, err)
	}
	// pass 2 reads only the spam's chunks 0-2, not the FAQ's
	if len(st.Chunks) != 3 || !st.Chunks[0] || !st.Chunks[1] || !st.Chunks[2] {
		t.Errorf("chunks %v", st.Chunks)
	}
	cp := filepath.Join(dir, "chunks")
	if err := SaveBIChunks(cp, st.Chunks); err != nil {
		t.Fatal(err)
	}
	if cs, err := LoadBIChunks(cp); err != nil || len(cs) != 3 || !cs[2] {
		t.Errorf("loaded chunks %v %v", cs, err)
	}
}

func TestNocemInHistoryAndSet(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ns := []Notice{
		{Issuer: "bot", Type: "spam", ID: "n1", Entries: []NoticeEntry{{MsgID: "<a@x>", Groups: "g1", Subject: "BUY NOW", Date: "Tue, 23 Nov 2010 16:35:21 -0800"}, {MsgID: "<b@x>"}}},
		{Issuer: "bot", Type: "binary", ID: "n2", Entries: []NoticeEntry{{MsgID: "<c@x>"}}},
		{Issuer: "other", Type: "spam", ID: "n3", Entries: []NoticeEntry{{MsgID: "<a@x>"}}}, // listed again
	}
	added, err := st.AddNotices(ns)
	if err != nil || added != 3 {
		t.Fatalf("added %d, %v", added, err)
	}
	set, err := LoadNocemSet(st, DefaultNocemTypes)
	if err != nil || len(set) != 2 || !set.Has("<a@x>") || !set.Has("<b@x>") || set.Has("<c@x>") {
		t.Errorf("set %v %v", set, err)
	}
	// <a@x> is flagged by the scan as well: it must appear once
	st.AddSpam([]SpamRow{{MsgID: "<a@x>", Key: "k", Group: "g1", ArtNum: 1, Posted: 5, Stage: StageNocem, Reason: "nocem"}})
	var b strings.Builder
	n, err := WriteHistory(&b, st, 9, DefaultNocemTypes)
	if err != nil || n != 2 || strings.Count(b.String(), "\n") != 2 || !strings.Contains(b.String(), HistoryHash("<b@x>")) {
		t.Errorf("history %d %q %v", n, b.String(), err)
	}
	var subj []string
	st.NocemEntries([]string{"spam"}, func(_ string, e NoticeEntry) error { subj = append(subj, e.Subject); return nil })
	if len(subj) != 1 || subj[0] != "BUY NOW" {
		t.Errorf("entries with a subject: %v", subj)
	}
}

func TestSplitKeepsExtraInTrain(t *testing.T) {
	var ex []Example
	for i := 0; i < 300; i++ {
		ex = append(ex, Example{A: Article{MsgID: fmt.Sprintf("<l%d@x>", i)}, Spam: i%2 == 0})
	}
	for i := 0; i < 500; i++ {
		ex = append(ex, Example{A: Article{MsgID: fmt.Sprintf("<e%d@x>", i)}, Spam: true, Extra: true})
	}
	train, val, test, err := splitExamples(ex, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(val) != 30 || len(test) != 30 || len(train) != 740 {
		t.Fatalf("split %d/%d/%d", len(train), len(val), len(test))
	}
	for _, e := range append(val, test...) {
		if e.Extra {
			t.Fatalf("extra example %s outside train", e.A.MsgID)
		}
	}
}

func TestNoticeEntryHeldOut(t *testing.T) {
	n := 0
	for i := 0; i < 10000; i++ {
		if (NoticeEntry{Sender: "a@b", Subject: fmt.Sprint("s", i)}).HeldOut() {
			n++
		}
	}
	if n < 800 || n > 1200 {
		t.Fatalf("%d of 10000 held out", n)
	}
	if (NoticeEntry{}).Article().Lines != -1 {
		t.Fatal("NoCeM article should have an unknown line count")
	}
}

func TestSumBIKeys(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenBIWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	w.Add(1, map[uint64]float32{10: 2, 11: 1})
	w.Add(2, map[uint64]float32{10: 3})
	w.Add(2, map[uint64]float32{10: 3}) // chunk 2 again: counted once
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	want := map[uint64]float32{10: 99, 12: 99}
	if _, err := SumBIKeys(dir, want); err != nil {
		t.Fatal(err)
	}
	if want[10] != 5 || want[12] != 0 || len(want) != 2 {
		t.Fatalf("sums %v", want)
	}
}

func TestCandidatesCutShort(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenCandWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := w.Write([]Candidate{{Article: Article{MsgID: fmt.Sprintf("<%d@x>", i), Key: "k"}, Kind: CandUnsure}}); err != nil {
			t.Fatal(err)
		}
	}
	// killed: no gzip trailer, and the last bytes cut off
	name := w.f.Name()
	w.f.Close()
	b, _ := os.ReadFile(name)
	os.WriteFile(name, b[:len(b)-3], 0o644)
	n := 0
	if err := ReadCandidates(dir, func(i int, c Candidate) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Fatalf("read %d candidates of a file cut short, want at least 2", n)
	}
}
