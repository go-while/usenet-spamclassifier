package spamfilter

import (
	"os"
	"strings"
	"testing"
)

func readTestBody(t *testing.T, name string) []string {
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(string(b), "\n")
}

func TestParseNoticeBleachbot(t *testing.T) {
	n, ok := ParseNotice(readTestBody(t, "nocem-300000.txt"))
	if !ok || n.Issuer != "bleachbot@httrack.com" || n.Type != "site" || n.Action != "hide" || n.ID != "88c5f829692cd577" {
		t.Fatalf("headers: %+v %v", n, ok)
	}
	if len(n.Entries) != 128 {
		t.Errorf("%d entries, want 128 (Count)", len(n.Entries))
	}
	e := n.Entries[0]
	if e.MsgID != "<e086479b.b3b1fcbf@mchsi.com>" || e.Groups != "news.admin.net-abuse.email" ||
		e.Sender != "Edward.Wanta@mchsi.com" || e.Subject != "Penny will smash Latif Al Omari" {
		t.Errorf("first entry %+v", e)
	}
	a := e.Article()
	if a.Subject != e.Subject || a.Groups != 1 || a.Date == 0 || !a.NoBody {
		t.Errorf("article %+v", a)
	}
}

func TestParseNoticeSpamOne(t *testing.T) {
	n, ok := ParseNotice(readTestBody(t, "nocem-1100000.txt"))
	if !ok || n.Type != "spam" || len(n.Entries) != 1 || n.Entries[0].Subject != "See Susmitha dating secrets Sex Videos" ||
		n.Entries[0].Groups != "rec.aviation.military" {
		t.Errorf("%+v %v", n, ok)
	}
}

func TestParseNoticeOthers(t *testing.T) {
	for _, f := range []string{"nocem-1.txt", "nocem-1900000.txt"} {
		n, ok := ParseNotice(readTestBody(t, f))
		t.Logf("%s: ok=%v issuer=%q type=%q entries=%d", f, ok, n.Issuer, n.Type, len(n.Entries))
		if ok && len(n.Entries) == 0 {
			t.Errorf("%s: NCM block without entries", f)
		}
		for _, e := range n.Entries {
			if !strings.HasPrefix(e.MsgID, "<") || !strings.HasSuffix(e.MsgID, ">") {
				t.Errorf("%s: bad msgid %q", f, e.MsgID)
			}
		}
	}
}
