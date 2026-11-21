package spamfilter

import (
	"fmt"
	"strconv"
	"strings"
)

// Overview parses OVER lines given the server's LIST OVERVIEW.FMT.
type Overview struct {
	subject, from, date, msgid, refs, bytes, lines, xref int // field index, -1 if absent
	fullXref                                             bool
}

// NewOverview takes the LIST OVERVIEW.FMT lines ("Subject:", ":bytes",
// "Xref:full", ...). The first OVER field, the article number, is not in it.
func NewOverview(format []string) (*Overview, error) {
	o := &Overview{-1, -1, -1, -1, -1, -1, -1, -1, false}
	for i, f := range format {
		f = strings.ToLower(strings.TrimSpace(f))
		idx := i + 1 // after the article number
		switch {
		case f == "subject:":
			o.subject = idx
		case f == "from:":
			o.from = idx
		case f == "date:":
			o.date = idx
		case f == "message-id:":
			o.msgid = idx
		case f == "references:":
			o.refs = idx
		case f == ":bytes" || f == "bytes:":
			o.bytes = idx
		case f == ":lines" || f == "lines:":
			o.lines = idx
		case strings.HasPrefix(f, "xref:"):
			o.xref, o.fullXref = idx, strings.HasSuffix(f, ":full")
		}
	}
	if o.subject < 0 || o.from < 0 || o.msgid < 0 || o.lines < 0 {
		return nil, fmt.Errorf("overview format lacks Subject, From, Message-ID or :lines: %q", format)
	}
	return o, nil
}

// Parse turns one OVER line into an Article. group names the group the line
// was fetched from, for Source and for articles without Xref.
func (o *Overview) Parse(line, group string) (Article, error) {
	f := strings.Split(line, "\t")
	get := func(i int) string {
		if i < 0 || i >= len(f) {
			return ""
		}
		return f[i]
	}
	lines, err := strconv.Atoi(strings.TrimSpace(get(o.lines)))
	if err != nil {
		return Article{}, fmt.Errorf("bad :lines in %q", clip(line, 200))
	}
	rawFrom, rawSubject := get(o.from), get(o.subject)
	a := Article{
		MsgID:   msgID(get(o.msgid)),
		From:    clip(decodeHeader(rawFrom, ""), headerValueMax),
		Subject: clip(decodeHeader(rawSubject, ""), headerValueMax),
		Lines:   lines,
		NoBody:  true,
		Reply:   strings.TrimSpace(get(o.refs)) != "",
		Key:     FSLKey(rawFrom, rawSubject, lines),
		Date:    parseDate(get(o.date)),
		Source:  group + ":" + get(0),
	}
	a.Bytes, _ = strconv.ParseInt(strings.TrimSpace(get(o.bytes)), 10, 64)
	groups := xrefGroups(get(o.xref), o.fullXref)
	if len(groups) == 0 {
		groups = []string{group}
	}
	a.Groups = len(groups)
	a.Newsgroups = clip(strings.Join(groups, ","), headerValueMax)
	return a, nil
}

// xrefGroups reads "Xref: host group:num group:num" (the full form has the
// header name) and returns the groups.
func xrefGroups(v string, full bool) []string {
	fs := strings.Fields(v)
	if full && len(fs) > 0 && strings.EqualFold(fs[0], "Xref:") {
		fs = fs[1:]
	}
	if len(fs) > 0 {
		fs = fs[1:] // the server name
	}
	var gs []string
	for _, x := range fs {
		if g, _, ok := strings.Cut(x, ":"); ok && g != "" {
			gs = append(gs, g)
		}
	}
	return gs
}
