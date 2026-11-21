package spamfilter

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func TestNewArticleHeaders(t *testing.T) {
	head := []string{
		"From: =?ISO-8859-1?Q?J=F6rg_M=FCller?= <j@example.de>",
		"Newsgroups: de.comm.internet.misc, de.comm.internet.commerce,",
		" de.etc.finanz.misc",
		"Subject: =?UTF-8?B?R3LDvMOfZQ==?=",
		"Date: Tue, 24 Jun 2003 19:30:12 +0200",
		"Message-ID: <abc$1@example.de> (comment)",
		"Organization: Example",
	}
	a := NewArticle(head, []string{"Hallo."}, -1)
	if a.From != "Jörg Müller <j@example.de>" {
		t.Errorf("From = %q", a.From)
	}
	if a.Subject != "Grüße" {
		t.Errorf("Subject = %q", a.Subject)
	}
	if a.Groups != 3 {
		t.Errorf("Groups = %d, want 3 (continuation line joined)", a.Groups)
	}
	if a.MsgID != "<abc$1@example.de>" {
		t.Errorf("MsgID = %q", a.MsgID)
	}
	if want := time.Date(2003, 6, 24, 17, 30, 12, 0, time.UTC).Unix(); a.Date != want {
		t.Errorf("Date = %d, want %d", a.Date, want)
	}
}

func TestOldDate(t *testing.T) {
	a := NewArticle([]string{"Date: Fri, 13 Jan 95 10:00:00 GMT"}, nil, -1)
	if a.Date == 0 {
		t.Error("two-digit year date not parsed")
	}
}

func TestSnippetSkipsQuotesAndSignature(t *testing.T) {
	body := []string{
		"In article <x@y>, someone wrote:",
		"> quoted spam text",
		"",
		"My own answer.",
		"Second line.",
		"-- ",
		"signature",
	}
	a := NewArticle(nil, body, -1)
	if a.Snippet != "My own answer.\nSecond line." {
		t.Errorf("Snippet = %q", a.Snippet)
	}
}

func TestSnippetLimit(t *testing.T) {
	var body []string
	for i := 0; i < 100; i++ {
		body = append(body, strings.Repeat("x", 100))
	}
	a := NewArticle(nil, body, -1)
	if len(a.Snippet) > SnippetBytes {
		t.Errorf("snippet is %d bytes", len(a.Snippet))
	}
	if n := strings.Count(a.Snippet, "\n") + 1; n > SnippetLines {
		t.Errorf("snippet has %d lines", n)
	}
}

func TestBodyHashIgnoresLineEndsAndBlankLines(t *testing.T) {
	long := strings.Repeat("Buy now, cheap, best offer ", 4)
	a := NewArticle(nil, []string{long + "\r", "", "cheap  ", ""}, -1)
	b := NewArticle(nil, []string{long, "cheap"}, -1)
	if a.BodyHash == "" || a.BodyHash != b.BodyHash {
		t.Errorf("same text: hashes %q and %q", a.BodyHash, b.BodyHash)
	}
	c := NewArticle(nil, []string{long, "dear"}, -1)
	if a.BodyHash == c.BodyHash {
		t.Error("different text, same hash")
	}
	if d := NewArticle(nil, []string{"test"}, -1); d.BodyHash != "" {
		t.Error("a short body got a hash")
	}
}

func TestQuotedPrintableLatin1(t *testing.T) {
	head := []string{
		"Content-Type: text/plain; charset=ISO-8859-1",
		"Content-Transfer-Encoding: quoted-printable",
	}
	a := NewArticle(head, []string{"Gr=FC=DFe aus K=F6ln"}, -1)
	if a.Snippet != "Grüße aus Köln" {
		t.Errorf("Snippet = %q", a.Snippet)
	}
}

func TestBase64(t *testing.T) {
	head := []string{"Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: base64"}
	a := NewArticle(head, []string{"TWFrZSBtb25leSBmYXN0"}, -1)
	if a.Snippet != "Make money fast" {
		t.Errorf("Snippet = %q", a.Snippet)
	}
}

func TestKOI8R(t *testing.T) {
	head := []string{"Content-Type: text/plain; charset=koi8-r", "Subject: \xf0\xd2\xc9\xd7\xc5\xd4"}
	a := NewArticle(head, []string{"\xf0\xd2\xc9\xd7\xc5\xd4"}, -1)
	if a.Snippet != "Привет" || a.Subject != "Привет" {
		t.Errorf("Subject = %q, Snippet = %q", a.Subject, a.Snippet)
	}
}

func TestMultipartPrefersPlainThenHTML(t *testing.T) {
	head := []string{`Content-Type: multipart/alternative; boundary="XX"`}
	body := strings.Split(`--XX
Content-Type: text/html

<html><body><p>HTML version</p></body></html>
--XX
Content-Type: text/plain

Plain version
--XX--`, "\n")
	if a := NewArticle(head, body, -1); a.Snippet != "Plain version" {
		t.Errorf("Snippet = %q", a.Snippet)
	}
	htmlOnly := strings.Split(`--XX
Content-Type: text/html; charset=utf-8

<html><head><title>T</title></head><body><p>Buy &amp; save</p><a href="http://spam.example/x">here</a></body></html>
--XX--`, "\n")
	a := NewArticle(head, htmlOnly, -1)
	if !strings.Contains(a.Snippet, "Buy & save") || !strings.Contains(a.Snippet, "[http://spam.example/x]") || strings.Contains(a.Snippet, "<") {
		t.Errorf("Snippet = %q", a.Snippet)
	}
}

func TestReadMboxUnquotesOnlyMarked(t *testing.T) {
	mbox := "From nobody Thu Dec  8 12:55:04 2016\n" +
		"Message-ID: <1@x>\nSubject: a\nX-Mbox2nntp-Format: mboxrd\n\n" +
		">From the start\n\n" +
		"From nobody Thu Dec  8 12:55:05 2016\n" +
		"Message-ID: <2@x>\nSubject: b\n\n" +
		">From the start\n"
	var got []Article
	if err := ReadMbox(strings.NewReader(mbox), func(a Article) error { got = append(got, a); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("read %d articles, want 2", len(got))
	}
	if got[0].Snippet != "From the start" {
		t.Errorf("marked article: Snippet = %q, want the quote removed", got[0].Snippet)
	}
	if got[1].Snippet != "" { // ">From" counts as a quote line in an unmarked archive
		t.Errorf("unmarked article: Snippet = %q", got[1].Snippet)
	}
}

func TestBreidbart(t *testing.T) {
	day := int64(24 * 3600)
	// 4 copies to 4 groups each on one day: 4 * 2 = 8
	var c []Copy
	for i := 0; i < 4; i++ {
		c = append(c, Copy{Date: 1000, Groups: 4})
	}
	if bi := Breidbart(c, 45*24*time.Hour); bi != 8 {
		t.Errorf("bi = %v, want 8", bi)
	}
	// a monthly FAQ to 9 groups for 10 years: never more than 2 copies in 45 days
	c = nil
	for i := int64(0); i < 120; i++ {
		c = append(c, Copy{Date: i * 30 * day, Groups: 9})
	}
	if bi := Breidbart(c, 45*24*time.Hour); bi > 6.01 {
		t.Errorf("monthly FAQ bi = %v, want at most 6", bi)
	}
	if bi := Breidbart(nil, time.Hour); bi != 0 {
		t.Errorf("no copies: bi = %v", bi)
	}
	if bi := Breidbart([]Copy{{Date: 0, Groups: 0}}, time.Hour); math.Abs(bi-1) > 1e-9 {
		t.Errorf("zero groups counts as one: bi = %v", bi)
	}
}

func TestRules(t *testing.T) {
	r := DefaultRules
	long := Article{Key: "k", Lines: 20, Subject: "hello"}
	if v, ok := r.Decide(long, 25); !ok || v.Reason != "bi=25.0" || v.Label != Spam || v.Key != "k" {
		t.Errorf("bi 25: %+v %v", v, ok)
	}
	short := Article{Key: "k", Lines: 1, Subject: "test"}
	if _, ok := r.Decide(short, 25); ok {
		t.Error("short article judged by the Breidbart index")
	}
	for subj, want := range map[string]string{
		"MAKE MONEY FAST":                  "subj:mmf",
		"$$$PAYPAL$$$ MONEY":               "", // left to the model since 2026-11-03
		"MMF Report 2006-05-09 @@NCM":      "",
		"Earn $500 to $700 per Week":       "subj:earn",
		"Work from home doing surveys":     "subj:home-income",
		"BEST for paid surveys":            "subj:surveys",
		"Buy CHEAP Viagra Online":          "subj:pharma",
		"Greatest Replica Watches":         "subj:replica",
		"Re: Work from home doing surveys": "",
		"AW: Make money fast":              "",
		"Finger weg von Paypal":            "",
		"Wer kennt einen Shop für Uhren?":  "",
	} {
		v, ok := r.Decide(Article{Subject: subj}, 0)
		if got := map[bool]string{true: v.Reason}[ok]; got != want {
			t.Errorf("%q: reason %q, want %q", subj, got, want)
		}
	} // spam subjects quoted in the anti-spam groups go to the model
	if _, ok := r.Decide(Article{Subject: "Buy CHEAP Viagra Online", Newsgroups: "news.admin.net-abuse.sightings"}, 0); ok {
		t.Error("subject rule fired in news.admin.net-abuse.sightings")
	}
}

func TestParseLabels(t *testing.T) {
	m := ParseLabels("1m\n2d\n3. u\n2j\nnoise\n4: N\n5Q is it\n6#\n")
	want := map[int]labelLine{1: {"spam", "mmf"}, 2: {"ham", "discussion"}, 3: {"unsure", "ambiguous"}, 4: {"ham", "news"}, 5: {"ham", "question"}}
	if len(m) != len(want) {
		t.Fatalf("got %v", m)
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%d: %v, want %v", k, m[k], v)
		}
	}
	m = ParseLabels("1d 2q 3m, 4-z; 5:u 10s\n")
	if len(m) != 6 || m[3] != (labelLine{"spam", "mmf"}) || m[4] != (labelLine{"ham", "spamcomplaint"}) || m[10] != (labelLine{"spam", "shop"}) {
		t.Errorf("answers on one line: %v", m)
	}
	if len(codes) != 26 {
		t.Errorf("%d codes, want one per letter", len(codes))
	}
}

func TestCleanfeedRule(t *testing.T) {
	for _, c := range []struct {
		v          Verdict
		rule, code string
	}{
		{Verdict{Stage: StageRules, Reason: "bi=22.1"}, "emp.md5", "CF-EMP-MD5"},
		{Verdict{Stage: StageRules, Reason: "subj:mmf"}, "header.subject", "CF-BAD-SUBJECT"},
		{Verdict{Stage: StageLLM, Label: Spam}, "llm.spam", "CF-LLM.SPAM"},
		{Verdict{Stage: StageModel, Label: Spam}, "model.spam", "CF-MODEL.SPAM"},
	} {
		if r, code := c.v.CleanfeedRule(); r != c.rule || code != c.code {
			t.Errorf("%+v: %s %s, want %s %s", c.v, r, code, c.rule, c.code)
		}
	}
}

func TestFormatBatch(t *testing.T) {
	s := FormatBatch([]Article{{Subject: "a\nb", Snippet: "text", Lines: 4}, {Subject: "c"}, {Subject: "d", NoBody: true, Reply: true}})
	if !strings.Contains(s, "=== 1\nSubject: a b\nLines: 4\n\ntext\n") ||
		!strings.Contains(s, "=== 2\nSubject: c\nLines: 0\n\n(no text") ||
		!strings.Contains(s, "=== 3\nSubject: d\nLines: 0\nReply: yes\n\n(body not fetched)") {
		t.Errorf("mixed batch = %q", s)
	}
	s = FormatBatch([]Article{{Subject: "x", NoBody: true}, {Subject: "y", NoBody: true}})
	if !strings.Contains(s, "headers only, body not fetched.\n") || strings.Contains(s, "(body not fetched)") ||
		!strings.Contains(s, "=== 1\nSubject: x\nLines: 0\n\n=== 2") {
		t.Errorf("headers-only batch = %q", s)
	}
}

func TestFSLKeySameFromMboxAndOverview(t *testing.T) {
	head := []string{
		"From: =?ISO-8859-1?Q?J=F6rg?= <j@example.de>",
		"Subject: A long subject that was",
		"\tfolded in the header",
		"Message-ID: <1@x>",
		"References: <0@x>",
	}
	body := []string{"one", "", "three"}
	a := NewArticle(head, body, -1)
	ov, err := NewOverview([]string{"Subject:", "From:", "Date:", "Message-ID:", "References:", ":bytes", ":lines", "Xref:full"})
	if err != nil {
		t.Fatal(err)
	}
	// INN joins folded lines and turns the tab into a space
	line := "42\tA long subject that was folded in the header\t=?ISO-8859-1?Q?J=F6rg?= <j@example.de>\tThu, 1 Jan 2004 00:00:00 GMT\t<1@x>\t<0@x>\t999\t3\tXref: srv de.test:42 de.misc:7"
	o, err := ov.Parse(line, "de.test")
	if err != nil {
		t.Fatal(err)
	}
	if a.Key != o.Key {
		t.Errorf("keys differ: mbox %s, overview %s", a.Key, o.Key)
	}
	if o.Groups != 2 || o.Newsgroups != "de.test,de.misc" || !o.Reply || !o.NoBody || o.Source != "de.test:42" || o.Bytes != 999 {
		t.Errorf("overview article: %+v", o)
	}
	if o.From != "Jörg <j@example.de>" {
		t.Errorf("From = %q", o.From)
	}
}

func TestLineCountLikeINN(t *testing.T) {
	for _, c := range []struct {
		body  string
		lines int
	}{
		{"l1\nl2\n\n", 2},       // the mbox separator line is not counted
		{"l1\n\nl3\n", 3},       // an empty line inside counts
		{"l1\r\nl2\r\n\r\n", 2}, // CRLF
		{"m1", 1},               // no final newline
		{"", 0},
		{"\n\n", 0},
	} {
		body, n, err := readBody(strings.NewReader(c.body))
		if err != nil {
			t.Fatal(err)
		}
		if n != c.lines || len(body) != c.lines {
			t.Errorf("%q: %d lines, %d kept, want %d", c.body, n, len(body), c.lines)
		}
	}
	big := strings.Repeat("0123456789012345678901234567890123456789\n", MaxBody/41+100)
	body, n, err := readBody(strings.NewReader(big + "\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := MaxBody/41 + 100; n != want || len(body) >= want {
		t.Errorf("big body: %d lines counted (want %d), %d kept", n, want, len(body))
	}
}

func TestClusters(t *testing.T) {
	c := NewClusters()
	for i := 0; i < 25; i++ {
		c.Add("k1", "", 1000, 1, false) // a multipost: same From, Subject, lines
	}
	for i := 0; i < 25; i++ {
		c.Add("k2", "", 1000, 1, true) // replies don't count by key
	}
	for i := 0; i < 25; i++ {
		c.Add(fmt.Sprintf("v%d", i), "body", 1000, 1, false) // same body, varying subject
	}
	w := 45 * 24 * time.Hour
	if bi := c.Index("k1", w); bi != 25 {
		t.Errorf("k1: %v", bi)
	}
	if bi := c.Index("k2", w); bi != 0 {
		t.Errorf("k2 (replies): %v", bi)
	}
	if bi := c.Index("v3", w); bi != 25 {
		t.Errorf("v3 (by body): %v", bi)
	}
}
