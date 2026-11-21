package spamfilter

import (
	"bytes"
	"encoding/base64"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"
)

var wordDecoder = &mime.WordDecoder{CharsetReader: charsetReader}

// charsetReader converts encoded words to UTF-8 (see toUTF8).
func charsetReader(charset string, in io.Reader) (io.Reader, error) {
	b, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}
	return strings.NewReader(toUTF8(b, charset)), nil
}

// decodeHeader decodes RFC 2047 encoded words. Raw 8-bit text is read in
// the article's body charset, which is what posting software used.
func decodeHeader(v, bodyCharset string) string {
	if d, err := wordDecoder.DecodeHeader(v); err == nil {
		v = d
	}
	return toUTF8([]byte(v), bodyCharset)
}

// bodyCharset is the charset parameter of the article's Content-Type.
func bodyCharset(h headers) string {
	_, params, _ := mime.ParseMediaType(h.get("Content-Type"))
	return params["charset"]
}

// toUTF8 converts text to UTF-8. Valid UTF-8 is kept as it is, whatever
// the declared charset (8-bit text almost never happens to be valid UTF-8).
// Otherwise the declared charset is used when it is known (koi8-r,
// windows-1251, iso-8859-2, ...), and anything else is read as Latin-1 with
// windows-1252 for its printable 0x80-0x9f range: that is what unlabelled
// 8-bit Usenet text nearly always is.
func toUTF8(b []byte, charset string) string {
	if utf8.Valid(b) {
		return string(b)
	}
	if cs := strings.ToLower(strings.Trim(charset, ` "'`)); cs != "" && cs != "us-ascii" && cs != "utf-8" {
		if enc, err := htmlindex.Get(cs); err == nil {
			if d, err := enc.NewDecoder().Bytes(b); err == nil && utf8.Valid(d) {
				return string(d)
			}
		}
	}
	var sb strings.Builder
	sb.Grow(len(b) + len(b)/8)
	for _, c := range b {
		if c >= 0x80 && c < 0xa0 {
			if r := cp1252[c-0x80]; r != 0 {
				sb.WriteRune(r)
				continue
			}
		}
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

var cp1252 = [32]rune{
	'€', 0, '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', 0, 'Ž', 0,
	0, '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', 0, 'ž', 'Ÿ',
}

// decodeBody returns the readable text of the body: the transfer encoding
// undone, the first text/plain part of a multipart body, UTF-8.
func decodeBody(h headers, body []string) []string {
	ctype := h.get("Content-Type")
	cte := h.get("Content-Transfer-Encoding")
	raw := strings.Join(body, "\n")
	text, ok := decodePart(ctype, cte, raw, 0)
	if !ok {
		_, params, _ := mime.ParseMediaType(ctype)
		text = toUTF8([]byte(raw), params["charset"])
	}
	return strings.Split(text, "\n")
}

func decodePart(ctype, cte, raw string, depth int) (string, bool) {
	mt, params, err := mime.ParseMediaType(ctype)
	if ctype == "" || err != nil {
		mt, params = "text/plain", map[string]string{}
	}
	if strings.HasPrefix(mt, "multipart/") && params["boundary"] != "" && depth < 3 {
		// the first text/plain part; failing that, the first text/html part
		mr := multipart.NewReader(strings.NewReader(raw), params["boundary"])
		var htmlText string
		haveHTML := false
		for {
			p, err := mr.NextRawPart()
			if err != nil {
				return htmlText, haveHTML
			}
			b, err := io.ReadAll(io.LimitReader(p, 1<<20))
			if err != nil {
				return htmlText, haveHTML
			}
			pt := p.Header.Get("Content-Type")
			lpt := strings.ToLower(pt)
			cte := p.Header.Get("Content-Transfer-Encoding")
			switch {
			case pt == "" || strings.HasPrefix(lpt, "text/plain") || strings.HasPrefix(lpt, "multipart/"):
				if s, ok := decodePart(pt, cte, string(b), depth+1); ok {
					return s, true
				}
			case strings.HasPrefix(lpt, "text/html") && !haveHTML:
				htmlText, haveHTML = decodePart(pt, cte, string(b), depth+1)
			}
		}
	}
	if !strings.HasPrefix(mt, "text/") {
		return "", false
	}
	var b []byte
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "quoted-printable":
		b, err = io.ReadAll(quotedprintable.NewReader(strings.NewReader(raw)))
		if err != nil && len(b) == 0 {
			b = []byte(raw)
		}
	case "base64":
		b, err = base64.StdEncoding.DecodeString(strings.Map(dropSpace, raw))
		if err != nil {
			b = []byte(raw)
		}
	default:
		b = []byte(raw)
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	text := toUTF8(b, params["charset"])
	if mt == "text/html" || looksHTML(text) {
		text = stripHTML(text)
	}
	return text, true
}

var (
	htmlStart   = regexp.MustCompile(`(?i)<\s*(html|body|head|div|p|br|table|font|meta)\b`)
	htmlDrop    = regexp.MustCompile(`(?is)<\s*(script|style|head)\b.*?<\s*/\s*(script|style|head)\s*>|<!--.*?-->`)
	htmlBreak   = regexp.MustCompile(`(?i)<\s*(br|/p|/div|/tr|/h\d|/li)\b[^>]*>`)
	htmlTag     = regexp.MustCompile(`(?s)<[^>]*>`)
	htmlHref    = regexp.MustCompile(`(?i)<\s*a\b[^>]*\bhref\s*=\s*["']?([^"'\s>]+)[^>]*>`)
	blankRunsRE = regexp.MustCompile(`\n[ \t]*(\n[ \t]*)+`)
)

// looksHTML reports text whose first kilobyte has HTML markup in it.
func looksHTML(s string) bool {
	return htmlStart.MatchString(clip(s, 1024))
}

// stripHTML turns HTML into the text a reader would see. Link targets are
// kept in brackets: in spam they are often the only telling part.
func stripHTML(s string) string {
	s = htmlDrop.ReplaceAllString(s, "")
	s = htmlHref.ReplaceAllString(s, " [$1] ")
	s = htmlBreak.ReplaceAllString(s, "\n")
	s = htmlTag.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	s = strings.ReplaceAll(s, "\u00a0", " ")
	return strings.TrimSpace(blankRunsRE.ReplaceAllString(s, "\n"))
}

func dropSpace(r rune) rune {
	switch r {
	case ' ', '\t', '\r', '\n':
		return -1
	}
	return r
}
