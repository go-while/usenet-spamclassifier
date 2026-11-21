package spamfilter

import "testing"

func TestChmurkaRules(t *testing.T) {
	r := DefaultRules
	cases := []struct {
		a      Article
		reason string // "" = no rule
	}{
		{Article{From: "Rosie Cole <Rosie.C.Cole@gmail.com>", Subject: "Re: Find Local Singles", Lines: 5}, "from:known"},
		{Article{From: "rosie.c.cole@gmail.com", Subject: "x", Newsgroups: "news.admin.net-abuse.sightings", Lines: 5}, "from:known"},
		{Article{From: "xrosie.c.cole@gmail.community", Subject: "x", Lines: 5}, ""},
		{Article{From: "a@b.c", Subject: "[Get] KINDLE PDF EBOOK EPUB A Christmas Eve Tale", Lines: 5}, "subj:ebook"},
		{Article{From: "a@b.c", Subject: "[Get] kindle pdf ebook epub", Lines: 5}, "subj:ebook"},
		{Article{From: "a@b.c", Subject: "Converting EPUB to PDF for my Kindle?", Lines: 5}, ""},
		{Article{From: "a@b.c", Subject: "Re: KINDLE PDF EBOOK EPUB", Lines: 5}, ""},
	}
	for _, c := range cases {
		v, ok := r.Decide(c.a, 0)
		if got := map[bool]string{true: v.Reason}[ok]; got != c.reason {
			t.Errorf("%q / %q: got %q, want %q", c.a.From, c.a.Subject, got, c.reason)
		}
	}
	if rule, code := (Verdict{Stage: StageRules, Reason: "from:known"}).CleanfeedRule(); rule != "header.from" || code != "CF-BAD-FROM" {
		t.Errorf("cleanfeed rule %s %s", rule, code)
	}
}
