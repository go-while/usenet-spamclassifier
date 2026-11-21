package spamfilter

import (
	"fmt"
	"hash/fnv"
	"slices"
	"strings"
)

// StageNocem marks verdicts taken from NoCeM notices.
const StageNocem = "nocem"

// DefaultNocemSkip are the issuers whose listings are ignored. A spot check
// on 2026-11-03 (Haiku and Sonnet with the article body) found most of
// what they list under spam to be ordinary postings: UltraHippo 71% (1,077
// of 1,523, and 44.8M listings), robot@pasdenom.info 27 of 28,
// nocem-fr@alphanet.ch 49 of 83. A second check (2026-11-04) added
// i2pn2-nocem@i2pn2.org: 83 of 305 ham, mostly in de.*.
var DefaultNocemSkip = []string{"UltraHippo", "robot@pasdenom.info", "nocem-fr@alphanet.ch", "i2pn2-nocem@i2pn2.org"}

// DefaultNocemSkipIn are issuers ignored only in one hierarchy, as
// "HIER=ISSUER": a NoCeM listing is ignored when the article's home group
// (the first group of its Xref) is in HIER. A cross-check on 2026-11-20
// (Claude Haiku with the article body, on articles gpt-6-luna had checked)
// found these issuers' listings there to be mostly ordinary postings:
// eternal-september in de.* 31 of 536 spam, arcor 81 of 195, dorfdsl 2 of
// 29, Adri Verhoef's nl-cancel in nl.* 27 of 175. eternal-september's
// listings elsewhere (comp.* and others) held up.
var DefaultNocemSkipIn = []string{
	"de=nocem@eternal-september.org",
	"de=nocem@arcor.de",
	"de=mm+nocem@dorfdsl.de",
	"nl=Adri Verhoef <nl-cancel@a3.xs4all.nl>",
}

// NocemScoped holds, per hierarchy, the Message-IDs listed by the issuers
// ignored in that hierarchy.
type NocemScoped map[string]IDSet

// Skip reports whether a's NoCeM listing is ignored: an issuer skipped in
// the hierarchy of a's home group listed it.
func (n NocemScoped) Skip(a Article) bool {
	if len(n) == 0 {
		return false
	}
	g, _, _ := strings.Cut(a.Newsgroups, ",")
	if g == "" {
		g, _, _ = strings.Cut(a.Source, ":")
	}
	s := n[Hierarchy(g)]
	return s != nil && s.Has(a.MsgID)
}

// ParseNocemSkipIn reads "HIER=ISSUER" entries into the hierarchies per
// issuer.
func ParseNocemSkipIn(list []string) (map[string][]string, error) {
	m := map[string][]string{}
	for _, e := range list {
		h, issuer, ok := strings.Cut(e, "=")
		h, issuer = strings.TrimSpace(h), strings.TrimSpace(issuer)
		if !ok || h == "" || issuer == "" || strings.Contains(h, ".") {
			return nil, fmt.Errorf("bad NoCeM skip %q (want HIER=ISSUER, e.g. de=nocem@example.org)", e)
		}
		m[issuer] = append(m[issuer], h)
	}
	return m, nil
}

// LoadNocemScoped reads the listings (of the types) of the issuers that
// skipIn ignores in some hierarchy.
func LoadNocemScoped(st *Store, types, skipIn []string) (NocemScoped, error) {
	byIssuer, err := ParseNocemSkipIn(skipIn)
	if err != nil || len(byIssuer) == 0 {
		return nil, err
	}
	var issuers []string
	for i := range byIssuer {
		issuers = append(issuers, i)
	}
	ids := map[string][]uint64{}
	err = st.NocemIssuerIDs(issuers, types, func(id, issuer string) error {
		for _, h := range byIssuer[issuer] {
			ids[h] = append(ids[h], idHash(id))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := NocemScoped{}
	for h, l := range ids {
		out[h] = NewIDSet(l)
	}
	return out, nil
}

// DefaultNocemTypes are the notice types counted as spam: spam and its
// numbered and per-site variants, make-money-fast, spew and floods, the Thai
// floods (chmurka.net), excessive multi-posting (emp) and HipCrime forgeries.
// Policy types are left out unless asked for: binary and misplaced_binary,
// off-topic, velveeta (crossposts), multipost, site, bot, killfile,
// retromod, content-based (per-poster killfiles) and the like.
var DefaultNocemTypes = []string{
	"spam", "spam2", "spam3", "spam4", "general-spam", "aioe-spam",
	"mmf", "spew", "flood", "thai", "emp", "cleanfeed-emp", "hipcrime",
}

// IDSet is a compact set of Message-IDs: sorted 64-bit hashes, 8 bytes each.
type IDSet []uint64

func idHash(msgid string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(msgid))
	return h.Sum64()
}

// NewIDSet builds a set from Message-IDs.
func NewIDSet(ids []uint64) IDSet {
	slices.Sort(ids)
	return IDSet(slices.Compact(ids))
}

func (s IDSet) Has(msgid string) bool {
	_, ok := slices.BinarySearch(s, idHash(msgid))
	return ok
}

// LoadNocemSet reads the Message-IDs listed under the types into a set.
func LoadNocemSet(st *Store, types []string) (IDSet, error) {
	var ids []uint64
	err := st.NocemIDs(types, func(id, _ string) error {
		ids = append(ids, idHash(id))
		return nil
	})
	return NewIDSet(ids), err
}

// NoCeM notices (news.lists.filters, alt.nocem.misc) list articles that an
// issuer judged spam, binaries in text groups, off-topic and so on, by
// Message-ID with the article's groups. Some issuers (bleachbot) also give
// each article's Sender, Subject and Date in comment lines, which makes the
// entries usable as labelled examples without asking a model.
//
//	@@BEGIN NCM HEADERS
//	Issuer: bleachbot@httrack.com
//	Type: spam
//	Action: hide
//	Notice-ID: 89e13e2817c00757
//	@@BEGIN NCM BODY
//	#	Sender: Hot Hot <x@gmail.com>
//	#	Subject: See ... Sex Videos
//	<msgid@host>	rec.aviation.military
//	@@END NCM BODY
//
// The PGP signatures are not checked: the archive keeps the notices as
// posted, and Issuer is recorded so a user can drop issuers they distrust.

// Notice is one parsed NoCeM notice.
type Notice struct {
	Issuer, Type, Action, ID string
	Entries                  []NoticeEntry
}

// NoticeEntry is one listed article.
type NoticeEntry struct {
	MsgID, Groups         string
	Sender, Subject, Date string // from comment lines, when the issuer gives them
}

// ParseNotice reads a notice from an article's body lines. ok is false when
// the body holds no NCM block.
func ParseNotice(body []string) (n Notice, ok bool) {
	state := 0 // 0 before, 1 headers, 2 body
	var pending NoticeEntry
	for _, l := range body {
		l = strings.TrimRight(l, "\r")
		if strings.HasPrefix(l, "- ") { // PGP dash-escaping
			l = l[2:]
		}
		switch {
		case strings.HasPrefix(l, "@@BEGIN NCM HEADERS"):
			state, ok = 1, true
			continue
		case strings.HasPrefix(l, "@@BEGIN NCM BODY"):
			state = 2
			continue
		case strings.HasPrefix(l, "@@END NCM BODY"):
			return n, ok
		}
		switch state {
		case 1:
			k, v, found := strings.Cut(l, ":")
			if !found {
				continue
			}
			v = strings.TrimSpace(v)
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "issuer":
				n.Issuer = v
			case "type":
				n.Type = strings.ToLower(v)
			case "action":
				n.Action = strings.ToLower(v)
			case "notice-id":
				n.ID = v
			}
		case 2:
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "#") {
				k, v, found := strings.Cut(strings.TrimSpace(strings.TrimPrefix(t, "#")), ":")
				if !found {
					continue
				}
				v = strings.TrimSpace(v)
				switch strings.ToLower(strings.TrimSpace(k)) {
				case "sender", "from":
					pending.Sender = v
				case "subject":
					pending.Subject = v
				case "date":
					pending.Date = v
				}
				continue
			}
			if !strings.HasPrefix(t, "<") {
				continue
			}
			f := strings.Fields(t)
			if !strings.HasSuffix(f[0], ">") {
				continue
			}
			e := pending
			e.MsgID = f[0]
			e.Groups = strings.Join(f[1:], ",")
			n.Entries = append(n.Entries, e)
			pending = NoticeEntry{}
		}
	}
	return n, ok
}

// Article turns an entry into an Article for training and scoring: the
// headers the issuer gave, no body.
func (e NoticeEntry) Article() Article {
	groups := strings.FieldsFunc(e.Groups, func(r rune) bool { return r == ',' || r == ' ' })
	return Article{
		MsgID:      e.MsgID,
		From:       clip(decodeHeader(e.Sender, ""), headerValueMax),
		Subject:    clip(decodeHeader(e.Subject, ""), headerValueMax),
		Newsgroups: clip(strings.Join(groups, ","), headerValueMax),
		Groups:     len(groups),
		Date:       parseDate(e.Date),
		Lines:      -1, // unknown: the model must not learn "no line count" as spam
		Reply:      isReply(e.Subject),
		NoBody:     true,
	}
}

// Key is the entry's From+Subject key: entries that share it are copies of
// one posting.
func (e NoticeEntry) Key() string { return FSLKey(e.Sender, e.Subject, -1) }

// HeldOut reports whether training leaves the entry out (one key in ten),
// so nocem-eval can measure the model on postings it never saw.
func (e NoticeEntry) HeldOut() bool { return idHash(e.Key())%10 == 0 }
