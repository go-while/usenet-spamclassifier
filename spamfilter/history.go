package spamfilter

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// HistoryHash is INN's HashMessageID (lib/hash.c): the MD5 of the
// Message-ID with its domain part (after the '@') lower-cased, as upper-case
// hex. In "<postmaster@...>" the local part is case-insensitive too, so
// everything after the '<' is lower-cased.
func HistoryHash(msgid string) string {
	s := msgid
	if at := strings.IndexByte(s, '@'); at >= 0 {
		from := at
		if at == 11 && strings.EqualFold(s[1:at], "postmaster") {
			from = 0
		}
		// ASCII only, like C's tolower in the "C" locale
		b := []byte(s)
		for i := from + 1; i < len(b); i++ {
			if 'A' <= b[i] && b[i] <= 'Z' {
				b[i] += 'a' - 'A'
			}
		}
		s = string(b)
	}
	sum := md5.Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// HistoryLine is an INN history (hisv6) line that only remembers a
// Message-ID, with no stored article: "[HASH]\tarrived~-~posted\n". A news
// server with this line in its history refuses the article as a duplicate.
// expire drops such lines after the /remember/ days of expire.ctl, counted
// from arrived.
func HistoryLine(msgid string, arrived, posted int64) string {
	if posted <= 0 {
		return fmt.Sprintf("[%s]\t%d~-\n", HistoryHash(msgid), arrived)
	}
	return fmt.Sprintf("[%s]\t%d~-~%d\n", HistoryHash(msgid), arrived, posted)
}

// WriteHistory writes one history line per spam Message-ID: the ones the
// scan flagged, then those NoCeM notices list under nocemTypes that the
// scan did not flag. It returns the number of lines.
func WriteHistory(w io.Writer, s *Store, arrived int64, nocemTypes []string) (int, error) {
	n := 0
	var seen []uint64
	err := s.EachSpam(func(r SpamRow) error {
		n++
		seen = append(seen, idHash(r.MsgID))
		_, err := io.WriteString(w, HistoryLine(r.MsgID, arrived, r.Posted))
		return err
	})
	if err != nil || len(nocemTypes) == 0 {
		return n, err
	}
	flagged := NewIDSet(seen)
	err = s.NocemPosted(nocemTypes, func(msgid string, posted int64) error {
		if flagged.Has(msgid) {
			return nil
		}
		n++
		_, err := io.WriteString(w, HistoryLine(msgid, arrived, posted))
		return err
	})
	return n, err
}
