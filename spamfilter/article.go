// Package spamfilter labels Usenet articles as spam, ham or unsure.
//
// It is a cascade: cheap rules first (the Breidbart index over all copies of
// an article, a few subject patterns), then a Claude model on a sample of
// what the rules leave open. Articles come from mbox files or from a news
// server's overview (OVER); both give the same Article, keyed the same way,
// so one verdict covers every copy whichever source it came from.
package spamfilter

import (
	"crypto/sha256"
	"encoding/hex"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Article is what the filter keeps of one article.
//
// Key is the FSL key (From, Subject, line count; cleanfeed's FSL idea). It
// is computed the same way from an mbox article and from an overview line,
// so it is the key verdicts are stored under. BodyHash is the hash of the
// body text, known only for mbox articles; it is a second way copies
// cluster for the Breidbart index.
type Article struct {
	MsgID        string `json:"msgid"`
	Date         int64  `json:"date,omitempty"` // unix seconds, 0 if unknown
	Newsgroups   string `json:"newsgroups,omitempty"`
	Groups       int    `json:"groups"` // number of groups posted to
	From         string `json:"from,omitempty"`
	Organization string `json:"organization,omitempty"`
	Subject      string `json:"subject,omitempty"`
	Lines        int    `json:"lines"`
	Bytes        int64  `json:"bytes,omitempty"` // overview :bytes; differs between sources
	Reply        bool   `json:"reply,omitempty"` // has References
	Snippet      string `json:"snippet,omitempty"`
	NoBody       bool   `json:"nobody,omitempty"` // from the overview: the body was not fetched
	Key          string `json:"key"`
	BodyHash     string `json:"hash,omitempty"`
	Source       string `json:"source,omitempty"` // mbox file, or group:number on the server
}

// Snippet limits: the first SnippetLines body lines that are not quotes,
// attributions or blank, at most SnippetBytes in all.
const (
	SnippetLines   = 15
	SnippetBytes   = 600
	snippetLineMax = 160
	headerValueMax = 200
)

// FSLKey hashes From, Subject and the body line count. From and Subject are
// the raw header values (not MIME-decoded) with every run of whitespace made
// one space, which is how they come out of a news server's overview too.
// :bytes is left out: it differs between the mbox and the server.
func FSLKey(rawFrom, rawSubject string, lines int) string {
	s := sha256.New()
	s.Write([]byte(normSpace(rawFrom)))
	s.Write([]byte{0})
	s.Write([]byte(normSpace(rawSubject)))
	s.Write([]byte{0})
	s.Write([]byte(strconv.Itoa(lines)))
	return hex.EncodeToString(s.Sum(nil)[:12])
}

func normSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

// NewArticle builds an Article from header lines (as the mbox parser
// returns them, continuation lines separate) and the body lines, with
// trailing empty lines already removed. lines is the body's full line count
// when body was cut short, or -1 to use len(body).
func NewArticle(head, body []string, lines int) Article {
	h := unfold(head)
	cs := bodyCharset(h)
	if lines < 0 {
		lines = len(body)
	}
	a := Article{
		MsgID:        msgID(h.get("Message-ID")),
		Newsgroups:   clip(normSpace(h.get("Newsgroups")), headerValueMax),
		From:         clip(decodeHeader(h.get("From"), cs), headerValueMax),
		Organization: clip(decodeHeader(h.get("Organization"), cs), headerValueMax),
		Subject:      clip(decodeHeader(h.get("Subject"), cs), headerValueMax),
		Lines:        lines,
		Reply:        strings.TrimSpace(h.get("References")) != "",
		Key:          FSLKey(h.get("From"), h.get("Subject"), lines),
	}
	a.Groups = countGroups(h.get("Newsgroups"))
	a.Date = parseDate(h.get("Date"))
	text := decodeBody(h, body)
	a.BodyHash = bodyHash(text)
	a.Snippet = snippet(text)
	return a
}

func parseDate(v string) int64 {
	if t, err := mail.ParseDate(v); err == nil {
		return t.Unix()
	}
	if t, ok := parseOldDate(v); ok {
		return t.Unix()
	}
	return 0
}

type headers []struct{ name, value string }

func (h headers) get(name string) string {
	for _, f := range h {
		if strings.EqualFold(f.name, name) {
			return f.value
		}
	}
	return ""
}

// unfold joins continuation lines to their field.
func unfold(head []string) headers {
	var h headers
	for _, l := range head {
		l = strings.TrimRight(l, "\r")
		if (strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t")) && len(h) > 0 {
			h[len(h)-1].value += " " + strings.TrimSpace(l)
			continue
		}
		name, value, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		h = append(h, struct{ name, value string }{strings.TrimSpace(name), strings.TrimSpace(value)})
	}
	return h
}

func msgID(v string) string {
	if i := strings.IndexByte(v, '<'); i >= 0 {
		if j := strings.IndexByte(v[i:], '>'); j > 0 {
			return v[i : i+j+1]
		}
	}
	return strings.TrimSpace(v)
}

func countGroups(v string) int {
	n := 0
	for _, g := range strings.Split(v, ",") {
		if strings.TrimSpace(g) != "" {
			n++
		}
	}
	return n
}

// parseOldDate tries a few date shapes net/mail rejects, seen in old
// archives ("Tue, 24 Jun 03 19:30:12 GMT", missing weekday comma, ...).
func parseOldDate(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, '('); i > 0 {
		v = strings.TrimSpace(v[:i])
	}
	for _, layout := range []string{
		"Mon, 2 Jan 06 15:04:05 MST",
		"Mon, 2 Jan 06 15:04:05 -0700",
		"2 Jan 06 15:04:05 MST",
		"2 Jan 06 15:04:05 -0700",
		"Mon 2 Jan 2006 15:04:05 MST",
		"Mon 2 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04 MST",
		"Mon Jan 2 15:04:05 2006",
		"Mon Jan 2 15:04:05 MST 2006",
	} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// bodyHash hashes the body with line ends, trailing blanks and blank lines
// removed, so the same text posted from different software still matches.
// Bodies under 64 bytes ("test", "+1") get no hash: they would cluster
// unrelated posts.
func bodyHash(text []string) string {
	s := sha256.New()
	n := 0
	for _, l := range text {
		l = strings.TrimRight(l, " \t\r")
		if l == "" {
			continue
		}
		s.Write([]byte(l))
		s.Write([]byte{'\n'})
		n += len(l) + 1
	}
	if n < 64 {
		return ""
	}
	return hex.EncodeToString(s.Sum(nil)[:12])
}

// snippet picks the first lines a reader would see as the poster's own text.
func snippet(text []string) string {
	var b strings.Builder
	lines := 0
	for _, l := range text {
		l = strings.TrimSpace(strings.TrimRight(l, "\r"))
		if l == "--" { // signature
			break
		}
		if l == "" || isQuote(l) || isAttribution(l) {
			continue
		}
		l = clip(l, snippetLineMax)
		if b.Len()+len(l)+1 > SnippetBytes {
			if b.Len() == 0 {
				b.WriteString(clip(l, SnippetBytes))
			}
			break
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(l)
		if lines++; lines == SnippetLines {
			break
		}
	}
	return b.String()
}

func isQuote(l string) bool {
	return strings.HasPrefix(l, ">") || strings.HasPrefix(l, "|") || strings.HasPrefix(l, ":")
}

func isAttribution(l string) bool {
	low := strings.ToLower(l)
	if strings.HasPrefix(low, "in article <") {
		return true
	}
	for _, end := range []string{"wrote:", "writes:", "schrieb:", "a écrit :", "a écrit:", "said:"} {
		if strings.HasSuffix(low, end) {
			return true
		}
	}
	return false
}

// clip cuts s to at most n bytes at a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
