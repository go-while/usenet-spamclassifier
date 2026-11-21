package spamfilter

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure Go, no C compiler needed
)

// Store is the SQLite database of an automated run: per-group progress, the
// labelled items (training data for the local model), the spam Message-IDs
// (for the INN history export) and the API spend.
type Store struct {
	db *sql.DB
	// NocemSkip are NoCeM issuers whose listings are ignored: for flagging,
	// training and the history file (default DefaultNocemSkip)
	NocemSkip []string
}

const schema = `
CREATE TABLE IF NOT EXISTS groups (
	name     TEXT PRIMARY KEY,
	low      INTEGER NOT NULL DEFAULT 0,
	high     INTEGER NOT NULL DEFAULT 0,
	done     INTEGER NOT NULL DEFAULT 0, -- full scan: last article number processed
	sampled  INTEGER NOT NULL DEFAULT 0, -- sample mode: 1 once sampled
	articles INTEGER NOT NULL DEFAULT 0, -- articles processed in this group (home copies)
	spam     INTEGER NOT NULL DEFAULT 0,
	updated  TEXT
);
CREATE TABLE IF NOT EXISTS verdicts (
	key        TEXT PRIMARY KEY,
	label      TEXT NOT NULL,
	stage      TEXT NOT NULL,
	reason     TEXT NOT NULL,
	model      TEXT,
	at         TEXT NOT NULL,
	msgid      TEXT,
	newsgroups TEXT,
	ngroups    INTEGER,
	from_      TEXT,
	subject    TEXT,
	lines      INTEGER,
	reply      INTEGER
);
CREATE TABLE IF NOT EXISTS spam (
	msgid  TEXT PRIMARY KEY,
	key    TEXT NOT NULL,
	grp    TEXT NOT NULL,
	artnum INTEGER NOT NULL,
	posted INTEGER NOT NULL,
	stage  TEXT NOT NULL,
	reason TEXT NOT NULL,
	at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bi_progress (
	name TEXT PRIMARY KEY,
	done INTEGER NOT NULL -- Breidbart pass 2: last article number processed
);
CREATE TABLE IF NOT EXISTS nocem (
	msgid   TEXT PRIMARY KEY,
	type    TEXT NOT NULL, -- spam, binary, site, off-topic, ...
	issuer  TEXT NOT NULL,
	notice  TEXT NOT NULL, -- Notice-ID
	groups  TEXT,
	sender  TEXT,
	subject TEXT,
	posted  INTEGER        -- the listed article's date, when given
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS nocem_progress (
	name TEXT PRIMARY KEY,
	done INTEGER NOT NULL -- last notice article number read
);
CREATE TABLE IF NOT EXISTS pass_progress (
	pass TEXT NOT NULL,    -- e.g. unsure
	name TEXT NOT NULL,    -- group
	done INTEGER NOT NULL, -- last article number processed
	PRIMARY KEY (pass, name)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS audit (
	msgid  TEXT NOT NULL,
	kind   TEXT NOT NULL, -- flagged: from the spam table; clean: judged ham by the scan
	grp    TEXT NOT NULL,
	artnum INTEGER NOT NULL,
	stage  TEXT NOT NULL, -- what flagged it (flagged) or "" (clean)
	reason TEXT NOT NULL,
	label  TEXT NOT NULL, -- the model API's label
	why    TEXT NOT NULL, -- its reason code
	model  TEXT NOT NULL,
	at     TEXT NOT NULL,
	PRIMARY KEY (msgid, kind)
);
CREATE TABLE IF NOT EXISTS spend (
	model       TEXT PRIMARY KEY,
	requests    INTEGER NOT NULL DEFAULT 0,
	input       INTEGER NOT NULL DEFAULT 0,
	output      INTEGER NOT NULL DEFAULT 0,
	cache_read  INTEGER NOT NULL DEFAULT 0,
	cache_write INTEGER NOT NULL DEFAULT 0,
	usd         REAL NOT NULL DEFAULT 0
);
`

// OpenStore opens or creates the database.
func OpenStore(path string) (*Store, error) {
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() +
		"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Store{db: db, NocemSkip: DefaultNocemSkip}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// GroupState is a group's row.
type GroupState struct {
	Name                string
	Low, High, Done     int64
	Sampled             bool
	Articles, SpamCount int64
}

// SetGroupRange records the group's current number range from LIST ACTIVE
// or GROUP, keeping its progress.
func (s *Store) SetGroupRange(name string, low, high int64) error {
	_, err := s.db.Exec(`INSERT INTO groups (name, low, high, updated) VALUES (?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET low = excluded.low, high = excluded.high, updated = excluded.updated`,
		name, low, high, now())
	return err
}

// Group returns a group's row; ok is false if there is none.
func (s *Store) Group(name string) (g GroupState, ok bool, err error) {
	var sampled int
	err = s.db.QueryRow(`SELECT name, low, high, done, sampled, articles, spam FROM groups WHERE name = ?`, name).
		Scan(&g.Name, &g.Low, &g.High, &g.Done, &sampled, &g.Articles, &g.SpamCount)
	if err == sql.ErrNoRows {
		return g, false, nil
	}
	g.Sampled = sampled != 0
	return g, err == nil, err
}

// GroupProgress records the full scan's progress in a group.
func (s *Store) GroupProgress(name string, done, articles, spam int64) error {
	_, err := s.db.Exec(`UPDATE groups SET done = ?, articles = articles + ?, spam = spam + ?, updated = ? WHERE name = ?`,
		done, articles, spam, now(), name)
	return err
}

// BIDone returns how far the Breidbart pass 2 got in a group.
func (s *Store) BIDone(name string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT done FROM bi_progress WHERE name = ?`, name).Scan(&n)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return n, err
}

// SetBIDone records the Breidbart pass 2 progress in a group.
func (s *Store) SetBIDone(name string, done int64) error {
	_, err := s.db.Exec(`INSERT INTO bi_progress (name, done) VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET done = excluded.done`, name, done)
	return err
}

// AddNotices stores NoCeM entries; a Message-ID listed before keeps its
// first entry. It returns how many were new.
func (s *Store) AddNotices(ns []Notice) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	st, err := tx.Prepare(`INSERT OR IGNORE INTO nocem (msgid, type, issuer, notice, groups, sender, subject, posted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	defer st.Close()
	var added int64
	for _, n := range ns {
		for _, e := range n.Entries {
			r, err := st.Exec(e.MsgID, n.Type, n.Issuer, n.ID, e.Groups, e.Sender, e.Subject, parseDate(e.Date))
			if err != nil {
				tx.Rollback()
				return 0, err
			}
			if k, _ := r.RowsAffected(); k > 0 {
				added++
			}
		}
	}
	return added, tx.Commit()
}

// nocemWhere selects the listings of the types, without the skipped issuers.
func (s *Store) nocemWhere(types []string) (string, []any) {
	q := `type IN (?` + strings.Repeat(",?", len(types)-1) + `)`
	var args []any
	for _, t := range types {
		args = append(args, t)
	}
	if len(s.NocemSkip) > 0 {
		q += ` AND issuer NOT IN (?` + strings.Repeat(",?", len(s.NocemSkip)-1) + `)`
		for _, i := range s.NocemSkip {
			args = append(args, i)
		}
	}
	return q, args
}

// NocemSkipped reports whether the issuer's listings are ignored.
func (s *Store) NocemSkipped(issuer string) bool {
	for _, i := range s.NocemSkip {
		if i == issuer {
			return true
		}
	}
	return false
}

// SkippedNocemVerdicts returns the keys of the NoCeM examples the full scan
// kept (stage nocem) that only a skipped issuer listed.
func (s *Store) SkippedNocemVerdicts() (map[string]bool, error) {
	m := map[string]bool{}
	if len(s.NocemSkip) == 0 {
		return m, nil
	}
	q := `SELECT v.key FROM verdicts v JOIN nocem n ON n.msgid = v.msgid
		WHERE v.stage = 'nocem' AND n.issuer IN (?` + strings.Repeat(",?", len(s.NocemSkip)-1) + `)`
	var args []any
	for _, i := range s.NocemSkip {
		args = append(args, i)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		m[k] = true
	}
	return m, rows.Err()
}

// AuditKeys returns the keys of the spot-checked articles (their verdicts
// came from the audit): held out of training and of the scan's lookups,
// so that the spot checks measure the scan fairly.
func (s *Store) AuditKeys() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT v.key FROM verdicts v JOIN audit a ON a.msgid = v.msgid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		m[k] = true
	}
	return m, rows.Err()
}

// VerdictLabels returns the spam and ham labels by key, without the NoCeM
// examples (stage nocem) and the unsure ones.
func (s *Store) VerdictLabels() (map[string]Verdict, error) {
	rows, err := s.db.Query(`SELECT key, label, stage, reason FROM verdicts WHERE stage <> 'nocem' AND label IN ('spam', 'ham')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]Verdict{}
	for rows.Next() {
		var v Verdict
		if err := rows.Scan(&v.Key, &v.Label, &v.Stage, &v.Reason); err != nil {
			return nil, err
		}
		m[v.Key] = v
	}
	return m, rows.Err()
}

// NocemIDs calls fn with every Message-ID listed under one of the types.
func (s *Store) NocemIDs(types []string, fn func(msgid, typ string) error) error {
	if len(types) == 0 {
		return nil
	}
	where, args := s.nocemWhere(types)
	rows, err := s.db.Query(`SELECT msgid, type FROM nocem WHERE `+where, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, t string
		if err := rows.Scan(&id, &t); err != nil {
			return err
		}
		if err := fn(id, t); err != nil {
			return err
		}
	}
	return rows.Err()
}

// NocemIssuerIDs calls fn with every Message-ID one of the issuers listed
// under one of the types (the skip list does not apply).
func (s *Store) NocemIssuerIDs(issuers, types []string, fn func(msgid, issuer string) error) error {
	if len(issuers) == 0 || len(types) == 0 {
		return nil
	}
	q := `SELECT msgid, issuer FROM nocem WHERE issuer IN (?` + strings.Repeat(",?", len(issuers)-1) +
		`) AND type IN (?` + strings.Repeat(",?", len(types)-1) + `)`
	var args []any
	for _, i := range issuers {
		args = append(args, i)
	}
	for _, t := range types {
		args = append(args, t)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, issuer string
		if err := rows.Scan(&id, &issuer); err != nil {
			return err
		}
		if err := fn(id, issuer); err != nil {
			return err
		}
	}
	return rows.Err()
}

// NocemPosted calls fn with every Message-ID listed under one of the types
// and the listed article's date (0 if the notice gave none).
func (s *Store) NocemPosted(types []string, fn func(msgid string, posted int64) error) error {
	if len(types) == 0 {
		return nil
	}
	where, args := s.nocemWhere(types)
	rows, err := s.db.Query(`SELECT msgid, COALESCE(posted, 0) FROM nocem WHERE `+where, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var posted int64
		if err := rows.Scan(&id, &posted); err != nil {
			return err
		}
		if err := fn(id, posted); err != nil {
			return err
		}
	}
	return rows.Err()
}

// NocemEntries calls fn with the listed articles that come with a subject,
// for evaluating or training the local model.
func (s *Store) NocemEntries(types []string, fn func(typ string, e NoticeEntry) error) error {
	if len(types) == 0 {
		return nil
	}
	where, args := s.nocemWhere(types)
	rows, err := s.db.Query(`SELECT msgid, type, COALESCE(groups, ''), COALESCE(sender, ''), COALESCE(subject, '') FROM nocem
		WHERE subject <> '' AND `+where, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var e NoticeEntry
		var t string
		if err := rows.Scan(&e.MsgID, &t, &e.Groups, &e.Sender, &e.Subject); err != nil {
			return err
		}
		if err := fn(t, e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// NocemDone and SetNocemDone keep the progress of reading notice groups.
func (s *Store) NocemDone(name string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT done FROM nocem_progress WHERE name = ?`, name).Scan(&n)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return n, err
}

func (s *Store) SetNocemDone(name string, done int64) error {
	_, err := s.db.Exec(`INSERT INTO nocem_progress (name, done) VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET done = excluded.done`, name, done)
	return err
}

// NocemCounts returns entry counts by type and issuer.
func (s *Store) NocemCounts() (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT type, issuer, COUNT(*) FROM nocem GROUP BY type, issuer`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]int64{}
	for rows.Next() {
		var t, iss string
		var n int64
		if err := rows.Scan(&t, &iss, &n); err != nil {
			return nil, err
		}
		m[t+"\t"+iss] = n
	}
	return m, rows.Err()
}

// GroupSampled marks a group as sampled.
func (s *Store) GroupSampled(name string) error {
	_, err := s.db.Exec(`UPDATE groups SET sampled = 1, updated = ? WHERE name = ?`, now(), name)
	return err
}

// HasVerdict reports whether a key is labelled.
func (s *Store) HasVerdict(key string) (bool, error) {
	var x int
	err := s.db.QueryRow(`SELECT 1 FROM verdicts WHERE key = ?`, key).Scan(&x)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// Verdict returns the stored verdict for a key; ok is false if there is none.
func (s *Store) Verdict(key string) (v Verdict, ok bool, err error) {
	var model sql.NullString
	err = s.db.QueryRow(`SELECT key, label, stage, reason, model FROM verdicts WHERE key = ?`, key).
		Scan(&v.Key, &v.Label, &v.Stage, &v.Reason, &model)
	if err == sql.ErrNoRows {
		return v, false, nil
	}
	v.Model = model.String
	return v, err == nil, err
}

// PutVerdicts stores labelled items; a later verdict for a key replaces
// the earlier one (escalation).
func (s *Store) PutVerdicts(items []Article, vs []Verdict) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	st, err := tx.Prepare(`INSERT OR REPLACE INTO verdicts
		(key, label, stage, reason, model, at, msgid, newsgroups, ngroups, from_, subject, lines, reply)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer st.Close()
	t := now()
	for i, v := range vs {
		if v.Label == "" {
			continue
		}
		a := items[i]
		if _, err := st.Exec(v.Key, v.Label, v.Stage, v.Reason, v.Model, t, a.MsgID, a.Newsgroups, a.Groups,
			a.From, a.Subject, a.Lines, boolInt(a.Reply)); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// SpamRow is one spam Message-ID.
type SpamRow struct {
	MsgID, Key, Group string
	ArtNum, Posted    int64
	Stage, Reason     string
}

// AddSpam stores spam Message-IDs; one already stored is kept.
func (s *Store) AddSpam(rows []SpamRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	st, err := tx.Prepare(`INSERT OR IGNORE INTO spam (msgid, key, grp, artnum, posted, stage, reason, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer st.Close()
	t := now()
	for _, r := range rows {
		if _, err := st.Exec(r.MsgID, r.Key, r.Group, r.ArtNum, r.Posted, r.Stage, r.Reason, t); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// EachSpam calls fn for every spam Message-ID, in insertion order.
func (s *Store) EachSpam(fn func(SpamRow) error) error {
	rows, err := s.db.Query(`SELECT msgid, key, grp, artnum, posted, stage, reason FROM spam ORDER BY rowid`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r SpamRow
		if err := rows.Scan(&r.MsgID, &r.Key, &r.Group, &r.ArtNum, &r.Posted, &r.Stage, &r.Reason); err != nil {
			return err
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

// EachVerdict calls fn for every labelled item.
func (s *Store) EachVerdict(fn func(Article, Verdict) error) error {
	rows, err := s.db.Query(`SELECT key, label, stage, reason, COALESCE(model, ''), at, COALESCE(msgid, ''),
		COALESCE(newsgroups, ''), COALESCE(ngroups, 0), COALESCE(from_, ''), COALESCE(subject, ''),
		COALESCE(lines, 0), COALESCE(reply, 0) FROM verdicts ORDER BY rowid`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var a Article
		var v Verdict
		var reply int
		if err := rows.Scan(&v.Key, &v.Label, &v.Stage, &v.Reason, &v.Model, &v.At, &a.MsgID, &a.Newsgroups,
			&a.Groups, &a.From, &a.Subject, &a.Lines, &reply); err != nil {
			return err
		}
		a.Key, a.Reply, a.NoBody = v.Key, reply != 0, true
		if err := fn(a, v); err != nil {
			return err
		}
	}
	return rows.Err()
}

// AddSpend adds one model's usage and its cost in dollars.
func (s *Store) AddSpend(model string, u Usage, usd float64) error {
	_, err := s.db.Exec(`INSERT INTO spend (model, requests, input, output, cache_read, cache_write, usd)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(model) DO UPDATE SET requests = requests + excluded.requests, input = input + excluded.input,
		output = output + excluded.output, cache_read = cache_read + excluded.cache_read,
		cache_write = cache_write + excluded.cache_write, usd = usd + excluded.usd`,
		model, u.Requests, u.Input, u.Output, u.CacheRead, u.CacheWrite, usd)
	return err
}

// Spent returns the dollars spent on the API so far, all models.
func (s *Store) Spent() (float64, error) {
	var usd float64
	err := s.db.QueryRow(`SELECT COALESCE(SUM(usd), 0) FROM spend`).Scan(&usd)
	return usd, err
}

// VerdictCount returns the number of labelled items (the verdicts table
// only, so it stays cheap while the spam table grows).
func (s *Store) VerdictCount() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM verdicts`).Scan(&n)
	return n, err
}

// Counts returns row counts for a status line.
func (s *Store) Counts() (groups, sampled, verdicts, spam int64, err error) {
	err = s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM groups), (SELECT COUNT(*) FROM groups WHERE sampled = 1),
		(SELECT COUNT(*) FROM verdicts), (SELECT COUNT(*) FROM spam)`).Scan(&groups, &sampled, &verdicts, &spam)
	return
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// PassDone returns how far a named pass got in a group.
func (s *Store) PassDone(pass, name string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT done FROM pass_progress WHERE pass = ? AND name = ?`, pass, name).Scan(&n)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return n, err
}

// SetPassDone records a named pass's progress in a group.
func (s *Store) SetPassDone(pass, name string, done int64) error {
	_, err := s.db.Exec(`INSERT INTO pass_progress (pass, name, done) VALUES (?, ?, ?)
		ON CONFLICT(pass, name) DO UPDATE SET done = excluded.done`, pass, name, done)
	return err
}

// VerdictKeys returns the keys of all labelled items.
func (s *Store) VerdictKeys() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT key FROM verdicts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		m[k] = true
	}
	return m, rows.Err()
}

// SampleSpam returns about n spam rows picked at random (by row id, so it
// does not read the whole table); group, if set, limits them to one group
// (that one reads the table).
func (s *Store) SampleSpam(n int, group string, rnd func(int64) int64) ([]SpamRow, error) {
	cols := `SELECT msgid, key, grp, artnum, posted, stage, reason FROM spam`
	scan := func(rows *sql.Rows) ([]SpamRow, error) {
		defer rows.Close()
		var out []SpamRow
		for rows.Next() {
			var r SpamRow
			if err := rows.Scan(&r.MsgID, &r.Key, &r.Group, &r.ArtNum, &r.Posted, &r.Stage, &r.Reason); err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, rows.Err()
	}
	if group != "" {
		rows, err := s.db.Query(cols+` WHERE grp = ? ORDER BY random() LIMIT ?`, group, n)
		if err != nil {
			return nil, err
		}
		return scan(rows)
	}
	var maxID int64
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(rowid), 0) FROM spam`).Scan(&maxID); err != nil || maxID == 0 {
		return nil, err
	}
	seen := map[int64]bool{}
	var out []SpamRow
	for tries := 0; len(out) < n && tries < 3*n; tries++ {
		id := 1 + rnd(maxID)
		if seen[id] {
			continue
		}
		seen[id] = true
		rows, err := s.db.Query(cols+` WHERE rowid = ?`, id)
		if err != nil {
			return nil, err
		}
		rs, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, nil
}

// AuditRow is one spot-checked article.
type AuditRow struct {
	MsgID, Kind, Group string
	ArtNum             int64
	Stage, Reason      string // what flagged it
	Label, Why, Model  string // the model API's answer
}

// AddAudit stores spot-check results; a later check of the same article
// replaces the earlier one.
func (s *Store) AddAudit(rows []AuditRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	st, err := tx.Prepare(`INSERT OR REPLACE INTO audit (msgid, kind, grp, artnum, stage, reason, label, why, model, at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer st.Close()
	t := now()
	for _, r := range rows {
		if _, err := st.Exec(r.MsgID, r.Kind, r.Group, r.ArtNum, r.Stage, r.Reason, r.Label, r.Why, r.Model, t); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// EachAudit calls fn for every spot-check result.
func (s *Store) EachAudit(fn func(AuditRow) error) error {
	rows, err := s.db.Query(`SELECT msgid, kind, grp, artnum, stage, reason, label, why, model FROM audit ORDER BY rowid`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.MsgID, &r.Kind, &r.Group, &r.ArtNum, &r.Stage, &r.Reason, &r.Label, &r.Why, &r.Model); err != nil {
			return err
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

// VerdictArticle is a stored verdict with the overview fields it was
// stored with.
type VerdictArticle struct {
	Article
	Label, Stage, Reason, Model, At string
}

// EachVerdictArticle calls fn for every verdict with this label and stage.
func (s *Store) EachVerdictArticle(label, stage string, fn func(VerdictArticle) error) error {
	rows, err := s.db.Query(`SELECT key, label, stage, reason, COALESCE(model,''), at, COALESCE(msgid,''),
		COALESCE(newsgroups,''), COALESCE(ngroups,0), COALESCE(from_,''), COALESCE(subject,''), COALESCE(lines,0), COALESCE(reply,0)
		FROM verdicts WHERE label = ? AND stage = ?`, label, stage)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var v VerdictArticle
		var reply int
		if err := rows.Scan(&v.Key, &v.Label, &v.Stage, &v.Reason, &v.Model, &v.At, &v.MsgID,
			&v.Newsgroups, &v.Groups, &v.From, &v.Subject, &v.Lines, &reply); err != nil {
			return err
		}
		v.Reply = reply != 0
		if err := fn(v); err != nil {
			return err
		}
	}
	return rows.Err()
}

// SpamLocation returns "group:number" of each of the Message-IDs that is in
// the spam table.
func (s *Store) SpamLocation(msgids []string) (map[string]string, error) {
	out := make(map[string]string, len(msgids))
	st, err := s.db.Prepare(`SELECT grp, artnum FROM spam WHERE msgid = ?`)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	for _, m := range msgids {
		var g string
		var n int64
		switch err := st.QueryRow(m).Scan(&g, &n); err {
		case nil:
			out[m] = fmt.Sprintf("%s:%d", g, n)
		case sql.ErrNoRows:
		default:
			return nil, err
		}
	}
	return out, nil
}

// GroupRange is a group's article number range as the server gave it.
type GroupRange struct {
	Name      string
	Low, High int64
}

// GroupRanges returns the range of every group with articles.
func (s *Store) GroupRanges() ([]GroupRange, error) {
	rows, err := s.db.Query(`SELECT name, low, high FROM groups WHERE high >= low AND high > 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupRange
	for rows.Next() {
		var g GroupRange
		if err := rows.Scan(&g.Name, &g.Low, &g.High); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
