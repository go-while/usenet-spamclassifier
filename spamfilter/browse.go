package spamfilter

import (
	"database/sql"
	"net/url"
	"strings"
)

// Read-only queries for the web view (spamfilter serve).

// OpenStoreRO opens an existing database read-only, so a viewer can run
// next to a scan that writes it.
func OpenStoreRO(path string) (*Store, error) {
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() + "?mode=ro&_pragma=busy_timeout(10000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, NocemSkip: DefaultNocemSkip}, nil
}

// SpamByID returns the spam row of a Message-ID.
func (s *Store) SpamByID(msgid string) (r SpamRow, ok bool, err error) {
	err = s.db.QueryRow(`SELECT msgid, key, grp, artnum, posted, stage, reason FROM spam WHERE msgid = ?`, msgid).
		Scan(&r.MsgID, &r.Key, &r.Group, &r.ArtNum, &r.Posted, &r.Stage, &r.Reason)
	if err == sql.ErrNoRows {
		return r, false, nil
	}
	return r, err == nil, err
}

// NocemRow is a Message-ID's entry from the NoCeM notices.
type NocemRow struct {
	MsgID, Type, Issuer, Notice, Groups, Sender, Subject string
	Posted                                               int64
}

// NocemByID returns the NoCeM entry of a Message-ID.
func (s *Store) NocemByID(msgid string) (r NocemRow, ok bool, err error) {
	err = s.db.QueryRow(`SELECT msgid, type, issuer, notice, COALESCE(groups, ''), COALESCE(sender, ''),
		COALESCE(subject, ''), COALESCE(posted, 0) FROM nocem WHERE msgid = ?`, msgid).
		Scan(&r.MsgID, &r.Type, &r.Issuer, &r.Notice, &r.Groups, &r.Sender, &r.Subject, &r.Posted)
	if err == sql.ErrNoRows {
		return r, false, nil
	}
	return r, err == nil, err
}

// Groups returns every group's row, ordered by name. With prefix, only the
// groups whose name starts with it.
func (s *Store) Groups(prefix string, limit int) ([]GroupState, error) {
	q := `SELECT name, low, high, done, sampled, articles, spam FROM groups`
	var args []any
	if prefix != "" {
		q += ` WHERE name >= ? AND name < ?`
		args = append(args, prefix, prefix+"\xff")
	}
	q += ` ORDER BY name`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupState
	for rows.Next() {
		var g GroupState
		var sampled int
		if err := rows.Scan(&g.Name, &g.Low, &g.High, &g.Done, &sampled, &g.Articles, &g.SpamCount); err != nil {
			return nil, err
		}
		g.Sampled = sampled != 0
		out = append(out, g)
	}
	return out, rows.Err()
}

// SpamCount is a count of spam rows by stage and reason.
type SpamCount struct {
	Stage, Reason string
	N             int64
}

// SpamCounts counts the spam rows by stage, and by reason for the rules
// (Breidbart pass-2 flags as one "bi" reason) and the model API labels.
// It reads the whole table: about a minute for 50 million rows.
func (s *Store) SpamCounts() ([]SpamCount, error) {
	rows, err := s.db.Query(`SELECT stage,
		CASE WHEN reason LIKE 'bi=%' THEN 'bi' WHEN stage IN ('rules', 'llm') THEN reason ELSE '' END AS r,
		COUNT(*) FROM spam GROUP BY stage, r ORDER BY 3 DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SpamCount
	for rows.Next() {
		var c SpamCount
		if err := rows.Scan(&c.Stage, &c.Reason, &c.N); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LabelRow is one labelled item, as the model API or NoCeM labelled it.
type LabelRow struct {
	A       Article
	V       Verdict
	At      string
	RowID   int64
	Snippet string
}

// Labels returns labelled items, newest first, before the row id before
// (0 = from the newest). label filters (spam, ham, unsure; "" = all),
// stage too (llm, nocem; "" = all).
func (s *Store) Labels(label, stage string, before int64, limit int) ([]LabelRow, error) {
	q := `SELECT rowid, key, label, stage, reason, COALESCE(model, ''), at, COALESCE(msgid, ''),
		COALESCE(newsgroups, ''), COALESCE(ngroups, 0), COALESCE(from_, ''), COALESCE(subject, ''),
		COALESCE(lines, 0), COALESCE(reply, 0) FROM verdicts WHERE 1`
	var args []any
	if label != "" {
		q += ` AND label = ?`
		args = append(args, label)
	}
	if stage != "" {
		q += ` AND stage = ?`
		args = append(args, stage)
	}
	if before > 0 {
		q += ` AND rowid < ?`
		args = append(args, before)
	}
	q += ` ORDER BY rowid DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LabelRow
	for rows.Next() {
		var r LabelRow
		var reply int
		if err := rows.Scan(&r.RowID, &r.V.Key, &r.V.Label, &r.V.Stage, &r.V.Reason, &r.V.Model, &r.At, &r.A.MsgID,
			&r.A.Newsgroups, &r.A.Groups, &r.A.From, &r.A.Subject, &r.A.Lines, &reply); err != nil {
			return nil, err
		}
		r.A.Key, r.A.Reply = r.V.Key, reply != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// LabelCounts counts the labelled items by stage and label.
func (s *Store) LabelCounts() (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT stage, label, COUNT(*) FROM verdicts GROUP BY stage, label`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]int64{}
	for rows.Next() {
		var st, l string
		var n int64
		if err := rows.Scan(&st, &l, &n); err != nil {
			return nil, err
		}
		m[st+"/"+l] = n
	}
	return m, rows.Err()
}

// Hierarchy is the first component of a group name.
func Hierarchy(group string) string {
	h, _, _ := strings.Cut(group, ".")
	return h
}
