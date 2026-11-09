package main

import (
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

// ---- serve: a read-only web view of the database, with live lookups on
// the news server to show what the filter does with any group's articles

type server struct {
	st     *sf.Store
	model  *sf.Model
	rules  sf.Rules
	match  func(string) bool
	biKeys map[uint64]float32
	types  map[string]bool // NoCeM types counted as spam
	addr   string
	tmpl   *template.Template

	nntpMu  sync.Mutex
	nntp    *sf.NNTP
	ov      *sf.Overview
	timeout time.Duration

	statMu   sync.Mutex
	spam     []sf.SpamCount
	nocem    []kv
	labels   map[string]int64
	statAt   time.Time
	groups   []sf.GroupState
	groupsAt time.Time
}

type kv struct {
	K string
	N int64
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dbPath := fs.String("db", "spamfilter.db", "SQLite database (opened read-only)")
	listen := fs.String("listen", "127.0.0.1:8099", "address to serve on; keep it on localhost and use an SSH tunnel")
	srv := fs.String("server", "", "news server for the live views, HOST:PORT")
	modelPath := fs.String("model-file", "spamfilter.model", "local model")
	biDir := fs.String("bi-dir", "", "Breidbart directory (default: the database path + \".bi\")")
	groups := fs.String("groups", "*,!control,!control.*,!junk,!to.*", "the -groups of the scan: decides each article's home group")
	types := fs.String("nocem-types", strings.Join(sf.DefaultNocemTypes, ","), "NoCeM types counted as spam")
	timeout := fs.Duration("timeout", time.Minute, "network timeout")
	nocemSkip := fs.String("nocem-skip", strings.Join(sf.DefaultNocemSkip, ","), "NoCeM issuers whose listings are ignored (\"\" = none)")
	fs.Parse(args)
	st, err := sf.OpenStoreRO(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	st.NocemSkip = splitList(*nocemSkip)
	m, err := sf.LoadModel(*modelPath)
	if err != nil {
		return err
	}
	match, err := wildmat(*groups)
	if err != nil {
		return err
	}
	if *biDir == "" {
		*biDir = *dbPath + ".bi"
	}
	s := &server{st: st, model: m, rules: sf.DefaultRules, match: match, addr: *srv, timeout: *timeout, types: map[string]bool{}}
	for _, t := range splitList(*types) {
		s.types[t] = true
	}
	if s.biKeys, err = sf.LoadBIKeys(filepath.Join(*biDir, biKeysFile)); err != nil {
		log.Printf("serve: no Breidbart keys (%v); the live view won't show them", err)
	}
	s.tmpl = newTemplates()
	go s.refreshStats()
	log.Printf("serve: http://%s/ (from your machine: ssh -L 8099:%s root@THIS-HOST, then open http://localhost:8099/)", *listen, *listen)
	return http.ListenAndServe(*listen, s.handler())
}

func newTemplates() *template.Template {
	return template.Must(template.New("").Funcs(template.FuncMap{
		"pct": func(a, b int64) string {
			if b == 0 {
				return "-"
			}
			return fmt.Sprintf("%.1f%%", 100*float64(a)/float64(b))
		},
		"num": func(n int64) string {
			s := strconv.FormatInt(n, 10)
			for i := len(s) - 3; i > 0; i -= 3 {
				s = s[:i] + "," + s[i:]
			}
			return s
		},
		"split": func(k string) []string {
			a, b, _ := strings.Cut(k, "/")
			return []string{a, b}
		},
		"date": func(t int64) string {
			if t <= 0 {
				return ""
			}
			return time.Unix(t, 0).UTC().Format("2006-01-02")
		},
	}).Parse(pages))
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /groups", s.groupList)
	mux.HandleFunc("GET /g", s.group)
	mux.HandleFunc("GET /a", s.article)
	mux.HandleFunc("GET /m", s.msgid)
	mux.HandleFunc("GET /labels", s.labelList)
	mux.HandleFunc("GET /nocem", s.nocemPage)
	return mux
}

// refreshStats counts the big tables in the background: each count reads a
// whole table, about a minute for 50 million rows.
func (s *server) refreshStats() {
	for {
		t0 := time.Now()
		sp, err := s.st.SpamCounts()
		if err != nil {
			log.Printf("serve: counting spam: %v", err)
		}
		lc, err := s.st.LabelCounts()
		if err != nil {
			log.Printf("serve: counting labels: %v", err)
		}
		nc, err := s.st.NocemCounts()
		if err != nil {
			log.Printf("serve: counting NoCeM: %v", err)
		}
		var nl []kv
		for k, n := range nc {
			nl = append(nl, kv{k, n})
		}
		sort.Slice(nl, func(i, j int) bool { return nl[i].N > nl[j].N })
		s.statMu.Lock()
		s.spam, s.labels, s.nocem, s.statAt = sp, lc, nl, time.Now()
		s.statMu.Unlock()
		log.Printf("serve: counted the tables in %s", time.Since(t0).Round(time.Second))
		time.Sleep(30 * time.Minute)
	}
}

func (s *server) allGroups() ([]sf.GroupState, error) {
	s.statMu.Lock()
	defer s.statMu.Unlock()
	if time.Since(s.groupsAt) < time.Minute {
		return s.groups, nil
	}
	g, err := s.st.Groups("", 0)
	if err != nil {
		return nil, err
	}
	s.groups, s.groupsAt = g, time.Now()
	return g, nil
}

func (s *server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("serve: %s: %v", name, err)
	}
}

func fail(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

type groupRow struct {
	Name           string
	Articles, Spam int64
	Groups         int64
}

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	gs, err := s.allGroups()
	if err != nil {
		fail(w, err)
		return
	}
	var tot groupRow
	hier := map[string]*groupRow{}
	var rows []groupRow
	for _, g := range gs {
		tot.Articles += g.Articles
		tot.Spam += g.SpamCount
		h := sf.Hierarchy(g.Name)
		if hier[h] == nil {
			hier[h] = &groupRow{Name: h}
		}
		hier[h].Articles += g.Articles
		hier[h].Spam += g.SpamCount
		hier[h].Groups++
		rows = append(rows, groupRow{Name: g.Name, Articles: g.Articles, Spam: g.SpamCount})
	}
	var hl []groupRow
	for _, h := range hier {
		hl = append(hl, *h)
	}
	sort.Slice(hl, func(i, j int) bool { return hl[i].Articles > hl[j].Articles })
	byCount := slices.Clone(rows)
	sort.Slice(byCount, func(i, j int) bool { return byCount[i].Spam > byCount[j].Spam })
	var byShare []groupRow
	for _, g := range rows {
		if g.Articles >= 5000 {
			byShare = append(byShare, g)
		}
	}
	share := func(g groupRow) float64 { return float64(g.Spam) / float64(g.Articles) }
	sort.Slice(byShare, func(i, j int) bool { return share(byShare[i]) > share(byShare[j]) })
	s.statMu.Lock()
	spam, labels, at := s.spam, s.labels, s.statAt
	s.statMu.Unlock()
	var spamTotal int64
	for _, c := range spam {
		spamTotal += c.N
	}
	s.render(w, "index", map[string]any{
		"Total": tot, "Groups": int64(len(gs)), "Hier": hl[:min(40, len(hl))],
		"ByCount": byCount[:min(30, len(byCount))], "ByShare": byShare[:min(30, len(byShare))],
		"Spam": spam, "SpamTotal": spamTotal, "Labels": labels, "StatAt": at,
	})
}

func (s *server) groupList(w http.ResponseWriter, r *http.Request) {
	prefix := strings.TrimSpace(r.URL.Query().Get("prefix"))
	gs, err := s.st.Groups(prefix, 2000)
	if err != nil {
		fail(w, err)
		return
	}
	s.render(w, "groups", map[string]any{"Prefix": prefix, "Groups": gs})
}

// liveRow is one article of the live view, with what the filter does.
type liveRow struct {
	Num                  int64
	A                    sf.Article
	Home                 string // judged in this group instead (crosspost)
	Label, Stage, Reason string // live decision
	BI                   float32
	Stored               *sf.SpamRow
	Nocem                *sf.NocemRow
	InFilter             bool
	Class                string // spam, ham, unsure
}

func (s *server) conn() (*sf.NNTP, *sf.Overview, error) {
	if s.addr == "" {
		return nil, nil, errors.New("no news server: start serve with -server HOST:PORT")
	}
	if s.nntp != nil {
		return s.nntp, s.ov, nil
	}
	c, err := sf.DialNNTP(s.addr, s.timeout)
	if err != nil {
		return nil, nil, err
	}
	c.ModeReader()
	if err := compressOn(c, true); err != nil {
		c.Quit()
		return nil, nil, err
	}
	format, err := c.OverviewFormat()
	if err != nil {
		c.Quit()
		return nil, nil, err
	}
	ov, err := sf.NewOverview(format)
	if err != nil {
		c.Quit()
		return nil, nil, err
	}
	s.nntp, s.ov = c, ov
	return c, ov, nil
}

// withConn runs fn on the news server connection, once more on a fresh
// connection if the old one failed (servers drop idle readers).
func (s *server) withConn(fn func(c *sf.NNTP, ov *sf.Overview) error) error {
	s.nntpMu.Lock()
	defer s.nntpMu.Unlock()
	for try := 0; ; try++ {
		c, ov, err := s.conn()
		if err != nil {
			return err
		}
		err = fn(c, ov)
		if err == nil || try > 0 {
			return err
		}
		var nerr interface{ Timeout() bool }
		if !errors.As(err, &nerr) && !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "broken pipe") &&
			!strings.Contains(err.Error(), "reset") {
			return err
		}
		c.Quit()
		s.nntp = nil
	}
}

func (s *server) nocemSpam(msgid string) bool {
	n, ok, err := s.st.NocemByID(msgid)
	return err == nil && ok && s.types[n.Type] && !s.st.NocemSkipped(n.Issuer)
}

func (s *server) decide(a sf.Article, group string) liveRow {
	row := liveRow{A: a}
	row.Label, row.Stage, row.Reason = judge(a, s.nocemSpam, s.rules, s.model)
	for _, g := range strings.Split(a.Newsgroups, ",") {
		if s.match(g) {
			if g != group {
				row.Home = g
			}
			break
		}
	}
	if k, ok := sf.BIKey(a, s.rules.MinLines); ok && s.biKeys != nil {
		row.BI = s.biKeys[k]
	}
	if sr, ok, err := s.st.SpamByID(a.MsgID); err == nil && ok {
		row.Stored = &sr
	}
	if n, ok, err := s.st.NocemByID(a.MsgID); err == nil && ok {
		row.Nocem = &n
	}
	row.InFilter = row.Label == sf.Spam || row.BI > 0 || row.Stored != nil
	switch {
	case row.InFilter:
		row.Class = "spam"
	case row.Label == sf.Ham:
		row.Class = "ham"
	default:
		row.Class = "unsure"
	}
	return row
}

func (s *server) group(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := strings.TrimSpace(q.Get("name"))
	n, _ := strconv.ParseInt(q.Get("n"), 10, 64)
	if n <= 0 || n > 2000 {
		n = 200
	}
	to, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	show := q.Get("show")
	var low, high, from int64
	var rows []liveRow
	err := s.withConn(func(c *sf.NNTP, ov *sf.Overview) error {
		var err error
		rows = rows[:0]
		if _, low, high, err = c.Group(name); err != nil {
			return err
		}
		if to <= 0 || to > high {
			to = high
		}
		from = max(low, to-n+1)
		return c.OverFunc(from, to, func(line string) error {
			numStr, _, _ := strings.Cut(line, "\t")
			num, _ := strconv.ParseInt(numStr, 10, 64)
			a, err := ov.Parse(line, name)
			if err != nil || a.MsgID == "" {
				return nil
			}
			rows = append(rows, liveRow{Num: num, A: a})
			return nil
		})
	})
	if err != nil {
		fail(w, err)
		return
	}
	counts := map[string]int{}
	var out []liveRow
	for i := len(rows) - 1; i >= 0; i-- { // newest first
		row := s.decide(rows[i].A, name)
		row.Num = rows[i].Num
		counts[row.Class]++
		if show == "" || show == row.Class {
			out = append(out, row)
		}
	}
	g, _, _ := s.st.Group(name)
	s.render(w, "group", map[string]any{
		"Name": name, "Rows": out, "Counts": counts, "Low": low, "High": high, "From": from, "To": to, "N": n,
		"Show": show, "Older": from - 1, "Newer": min(high, to+n), "G": g,
	})
}

func (s *server) article(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := q.Get("g")
	num, _ := strconv.ParseInt(q.Get("n"), 10, 64)
	var head, body []string
	err := s.withConn(func(c *sf.NNTP, ov *sf.Overview) error {
		if _, _, _, err := c.Group(name); err != nil {
			return err
		}
		return c.Articles([]int64{num}, 1, func(_ int64, h, b []string) error {
			head, body = h, b
			return nil
		})
	})
	if err != nil {
		fail(w, err)
		return
	}
	if head == nil {
		http.Error(w, "no such article", http.StatusNotFound)
		return
	}
	a := sf.NewArticle(head, body, -1)
	row := s.decide(a, name)
	row.Num = num
	cut := len(body) > 3000
	if cut {
		body = body[:3000]
	}
	s.render(w, "article", map[string]any{"Group": name, "Row": row, "Head": strings.Join(head, "\n"),
		"Body": strings.Join(body, "\n"), "Cut": cut})
}

func (s *server) msgid(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id != "" && !strings.HasPrefix(id, "<") {
		id = "<" + id + ">"
	}
	data := map[string]any{"ID": id}
	if sr, ok, err := s.st.SpamByID(id); err != nil {
		fail(w, err)
		return
	} else if ok {
		data["Spam"] = sr
	}
	if n, ok, err := s.st.NocemByID(id); err != nil {
		fail(w, err)
		return
	} else if ok {
		data["Nocem"] = n
		data["NocemSpam"] = s.types[n.Type] && !s.st.NocemSkipped(n.Issuer)
	}
	s.render(w, "msgid", data)
}

func (s *server) labelList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	label, stage := q.Get("label"), q.Get("stage")
	rows, err := s.st.Labels(label, stage, before, 200)
	if err != nil {
		fail(w, err)
		return
	}
	var next int64
	if len(rows) == 200 {
		next = rows[len(rows)-1].RowID
	}
	s.statMu.Lock()
	counts := s.labels
	s.statMu.Unlock()
	s.render(w, "labels", map[string]any{"Rows": rows, "Label": label, "Stage": stage, "Next": next, "Counts": counts})
}

func (s *server) nocemPage(w http.ResponseWriter, r *http.Request) {
	s.statMu.Lock()
	nl, at := s.nocem, s.statAt
	s.statMu.Unlock()
	type row struct {
		Type, Issuer string
		N            int64
		Spam         bool
	}
	var rows []row
	var total, spam int64
	for _, e := range nl {
		t, iss, _ := strings.Cut(e.K, "\t")
		rows = append(rows, row{t, iss, e.N, s.types[t]})
		total += e.N
		if s.types[t] {
			spam += e.N
		}
	}
	s.render(w, "nocem", map[string]any{"Rows": rows, "Total": total, "Spam": spam, "StatAt": at})
}

const pages = `
{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Spamfilter</title>
<style>
:root{--bg:#fbfbfa;--fg:#1d1d1b;--muted:#6b6b66;--line:#e3e2dd;--card:#fff;--link:#2456b3;
--spam:#fde8e6;--spam-fg:#a3261b;--ham:#e8f5ea;--ham-fg:#1e6b32;--unsure:#fdf3dc;--unsure-fg:#8a5a00}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#161615;--fg:#e8e7e3;--muted:#9a9a94;
--line:#2e2e2b;--card:#1f1f1d;--link:#8ab0ff;--spam:#3a1d1a;--spam-fg:#ff9b8f;--ham:#17301d;--ham-fg:#8fdba3;
--unsure:#33290f;--unsure-fg:#f0c66b}}
:root[data-theme="dark"]{--bg:#161615;--fg:#e8e7e3;--muted:#9a9a94;--line:#2e2e2b;--card:#1f1f1d;--link:#8ab0ff;
--spam:#3a1d1a;--spam-fg:#ff9b8f;--ham:#17301d;--ham-fg:#8fdba3;--unsure:#33290f;--unsure-fg:#f0c66b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif}
main{max-width:1400px;margin:0 auto;padding:16px}a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
nav{display:flex;gap:16px;flex-wrap:wrap;align-items:center;padding:10px 16px;border-bottom:1px solid var(--line);background:var(--card)}
nav b{margin-right:8px}nav form{margin-left:auto;display:flex;gap:6px}
input,select,button{font:inherit;padding:4px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
h1{font-size:20px;margin:8px 0 12px}h2{font-size:16px;margin:24px 0 8px}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;background:var(--card)}
th,td{padding:4px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-weight:600;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.03em}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:16px}
.muted{color:var(--muted)}.small{font-size:12px}
tr.spam td:first-child{border-left:4px solid var(--spam-fg)}tr.ham td:first-child{border-left:4px solid var(--ham-fg)}
tr.unsure td:first-child{border-left:4px solid var(--unsure-fg)}
.tag{display:inline-block;padding:0 6px;border-radius:4px;font-size:12px;white-space:nowrap}
.tag.spam{background:var(--spam);color:var(--spam-fg)}.tag.ham{background:var(--ham);color:var(--ham-fg)}
.tag.unsure{background:var(--unsure);color:var(--unsure-fg)}
.subj{max-width:520px;overflow-wrap:anywhere}.from{max-width:260px;overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--card);border:1px solid var(--line);padding:12px;border-radius:6px;font-size:13px}
.bar{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin:8px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px}
.stat b{display:block;font-size:20px;font-variant-numeric:tabular-nums}
</style></head><body>
<nav><b>Spamfilter</b><a href="/">Overview</a><a href="/groups">Groups</a><a href="/labels">Labels</a><a href="/nocem">NoCeM</a>
<form action="/m"><input name="id" placeholder="&lt;message-id&gt;" size="28"><button>Look up</button></form>
<form action="/g"><input name="name" placeholder="group name" size="24"><button>Browse</button></form></nav><main>
{{end}}
{{define "foot"}}</main></body></html>{{end}}

{{define "index"}}{{template "head"}}
<h1>What the filter holds</h1>
<div class="bar">
<div class="stat"><span class="muted small">Groups</span><b>{{num .Groups}}</b></div>
<div class="stat"><span class="muted small">Articles scanned (home copies)</span><b>{{num .Total.Articles}}</b></div>
<div class="stat"><span class="muted small">Flagged by the full scan</span><b>{{num .Total.Spam}}</b><span class="muted small">{{pct .Total.Spam .Total.Articles}}</span></div>
<div class="stat"><span class="muted small">Spam Message-IDs stored</span><b>{{if .Spam}}{{num .SpamTotal}}{{else}}counting…{{end}}</b></div>
</div>
<div class="grid">
<div><h2>Spam Message-IDs by how they were caught</h2>
{{if .Spam}}<div class="wrap"><table><tr><th>Stage</th><th>Reason</th><th class="n">Message-IDs</th><th class="n">Share</th></tr>
{{range .Spam}}<tr><td>{{.Stage}}</td><td>{{.Reason}}</td><td class="n">{{num .N}}</td><td class="n">{{pct .N $.SpamTotal}}</td></tr>{{end}}
</table></div><p class="muted small">Counted {{.StatAt.Format "2006-01-02 15:04"}} UTC. bi = flagged by the Breidbart pass (copies of one posting in many groups).</p>
{{else}}<p class="muted">Counting the spam table, about a minute after start. Reload then.</p>{{end}}
<h2>Labelled items (training data)</h2>
{{if .Labels}}<div class="wrap"><table><tr><th>Source/label</th><th class="n">Items</th></tr>
{{range $k, $v := .Labels}}<tr><td><a href="/labels?stage={{index (split $k) 0}}&label={{index (split $k) 1}}">{{$k}}</a></td><td class="n">{{num $v}}</td></tr>{{end}}
</table></div>{{end}}
</div>
<div><h2>Hierarchies</h2><div class="wrap"><table><tr><th>Hierarchy</th><th class="n">Groups</th><th class="n">Articles</th><th class="n">Flagged</th><th class="n">Share</th></tr>
{{range .Hier}}<tr><td><a href="/groups?prefix={{.Name}}.">{{.Name}}</a></td><td class="n">{{num .Groups}}</td><td class="n">{{num .Articles}}</td><td class="n">{{num .Spam}}</td><td class="n">{{pct .Spam .Articles}}</td></tr>{{end}}
</table></div></div>
<div><h2>Most flagged groups</h2><div class="wrap"><table><tr><th>Group</th><th class="n">Articles</th><th class="n">Flagged</th><th class="n">Share</th></tr>
{{range .ByCount}}<tr><td><a href="/g?name={{.Name}}">{{.Name}}</a></td><td class="n">{{num .Articles}}</td><td class="n">{{num .Spam}}</td><td class="n">{{pct .Spam .Articles}}</td></tr>{{end}}
</table></div></div>
<div><h2>Highest spam share (groups with 5,000+ articles)</h2><div class="wrap"><table><tr><th>Group</th><th class="n">Articles</th><th class="n">Flagged</th><th class="n">Share</th></tr>
{{range .ByShare}}<tr><td><a href="/g?name={{.Name}}">{{.Name}}</a></td><td class="n">{{num .Articles}}</td><td class="n">{{num .Spam}}</td><td class="n">{{pct .Spam .Articles}}</td></tr>{{end}}
</table></div></div>
</div>
<p class="muted small">"Flagged by the full scan" counts per group come from the scan's progress; the Breidbart pass and the NoCeM IDs the scan never saw are not in them.</p>
{{template "foot"}}{{end}}

{{define "groups"}}{{template "head"}}
<h1>Groups{{if .Prefix}} starting with {{.Prefix}}{{end}}</h1>
<form action="/groups" class="bar"><input name="prefix" value="{{.Prefix}}" placeholder="prefix, e.g. comp.lang."><button>Filter</button></form>
<div class="wrap"><table><tr><th>Group</th><th class="n">Low</th><th class="n">High</th><th class="n">Articles</th><th class="n">Flagged</th><th class="n">Share</th></tr>
{{range .Groups}}<tr><td><a href="/g?name={{.Name}}">{{.Name}}</a></td><td class="n">{{.Low}}</td><td class="n">{{.High}}</td><td class="n">{{num .Articles}}</td><td class="n">{{num .SpamCount}}</td><td class="n">{{pct .SpamCount .Articles}}</td></tr>{{end}}
</table></div><p class="muted small">At most 2,000 groups.</p>
{{template "foot"}}{{end}}

{{define "verdict"}}{{if .InFilter}}<span class="tag spam">in filter</span>{{else if eq .Class "ham"}}<span class="tag ham">clean</span>{{else}}<span class="tag unsure">unsure</span>{{end}}
<span class="small">{{if .Stored}}stored: {{.Stored.Stage}} {{.Stored.Reason}}{{if ne .Stored.Group ""}} ({{.Stored.Group}}){{end}}{{else}}now: {{.Stage}} {{.Reason}}{{end}}{{if .BI}} · bi={{printf "%.0f" .BI}}{{end}}{{if .Nocem}} · NoCeM {{.Nocem.Type}} by {{.Nocem.Issuer}}{{end}}{{if .Home}} · judged in {{.Home}}{{end}}</span>{{end}}

{{define "group"}}{{template "head"}}
<h1>{{.Name}}</h1>
<p class="muted">Articles {{.From}}–{{.To}} of {{.Low}}–{{.High}}, read live from the news server and judged now; "stored" is what the database holds.
{{if .G.Articles}}Full scan: {{num .G.Articles}} articles, {{num .G.SpamCount}} flagged ({{pct .G.SpamCount .G.Articles}}).{{end}}</p>
<div class="bar">
<a href="/g?name={{.Name}}&n={{.N}}&to={{.To}}">all</a>
<a href="/g?name={{.Name}}&n={{.N}}&to={{.To}}&show=spam"><span class="tag spam">in filter {{index .Counts "spam"}}</span></a>
<a href="/g?name={{.Name}}&n={{.N}}&to={{.To}}&show=unsure"><span class="tag unsure">unsure {{index .Counts "unsure"}}</span></a>
<a href="/g?name={{.Name}}&n={{.N}}&to={{.To}}&show=ham"><span class="tag ham">clean {{index .Counts "ham"}}</span></a>
<span class="muted">·</span>
{{if gt .To .Low}}<a href="/g?name={{.Name}}&n={{.N}}&to={{.Older}}&show={{.Show}}">← older</a>{{end}}
{{if lt .To .High}}<a href="/g?name={{.Name}}&n={{.N}}&to={{.Newer}}&show={{.Show}}">newer →</a>{{end}}
<form action="/g" style="display:flex;gap:6px"><input type="hidden" name="name" value="{{.Name}}"><input type="hidden" name="show" value="{{.Show}}">
<input name="to" placeholder="up to article #" size="12"><select name="n"><option>100</option><option selected>200</option><option>500</option><option>1000</option></select><button>Go</button></form>
</div>
<div class="wrap"><table><tr><th class="n">#</th><th>Date</th><th>From</th><th>Subject</th><th class="n">Grps</th><th class="n">Lines</th><th>Filter</th></tr>
{{range .Rows}}<tr class="{{.Class}}"><td class="n"><a href="/a?g={{$.Name}}&n={{.Num}}">{{.Num}}</a></td><td class="small">{{date .A.Date}}</td>
<td class="from small">{{.A.From}}</td><td class="subj">{{.A.Subject}}</td><td class="n">{{.A.Groups}}</td><td class="n">{{.A.Lines}}</td>
<td>{{template "verdict" .}}</td></tr>{{end}}
</table></div>
{{template "foot"}}{{end}}

{{define "article"}}{{template "head"}}
<h1>{{.Row.A.Subject}}</h1>
<p><a href="/g?name={{.Group}}&to={{.Row.Num}}">{{.Group}}</a> #{{.Row.Num}} · <a href="/m?id={{.Row.A.MsgID}}">{{.Row.A.MsgID}}</a></p>
<p>{{template "verdict" .Row}}</p>
<p class="muted small">Judged from these headers as the scan would (the scan sees the overview; the body is shown only for you).</p>
<pre>{{.Head}}</pre><pre>{{.Body}}</pre>{{if .Cut}}<p class="muted">Body cut after 3,000 lines.</p>{{end}}
{{template "foot"}}{{end}}

{{define "msgid"}}{{template "head"}}
<h1>{{.ID}}</h1>
{{with .Spam}}<p><span class="tag spam">in filter</span> {{.Stage}} {{.Reason}}, in <a href="/a?g={{.Group}}&n={{.ArtNum}}">{{.Group}} #{{.ArtNum}}</a>, posted {{date .Posted}}</p>
{{else}}<p>Not in the spam table.</p>{{end}}
{{with .Nocem}}<p>NoCeM: type <b>{{.Type}}</b> by {{.Issuer}} (notice {{.Notice}}){{if $.NocemSpam}} <span class="tag spam">counted as spam: goes into the history file</span>{{else}} <span class="tag unsure">not counted as spam (type, or an issuer in -nocem-skip)</span>{{end}}</p>
<p class="small">Groups: {{.Groups}}{{if .Sender}}<br>From: {{.Sender}}{{end}}{{if .Subject}}<br>Subject: {{.Subject}}{{end}}</p>
{{else}}<p>Not listed in the NoCeM notices.</p>{{end}}
{{template "foot"}}{{end}}

{{define "labels"}}{{template "head"}}
<h1>Labelled items</h1>
<div class="bar">
<form action="/labels" style="display:flex;gap:6px">
<select name="stage"><option value="">all sources</option><option value="llm" {{if eq .Stage "llm"}}selected{{end}}>model API (llm)</option><option value="nocem" {{if eq .Stage "nocem"}}selected{{end}}>NoCeM</option></select>
<select name="label"><option value="">all labels</option><option {{if eq .Label "spam"}}selected{{end}}>spam</option><option {{if eq .Label "ham"}}selected{{end}}>ham</option><option {{if eq .Label "unsure"}}selected{{end}}>unsure</option></select>
<button>Show</button></form></div>
<div class="wrap"><table><tr><th>Label</th><th>Reason</th><th>Model</th><th>From</th><th>Subject</th><th>Groups</th><th class="n">Lines</th></tr>
{{range .Rows}}<tr class="{{if eq .V.Label "spam"}}spam{{else if eq .V.Label "ham"}}ham{{else}}unsure{{end}}">
<td><span class="tag {{if eq .V.Label "spam"}}spam{{else if eq .V.Label "ham"}}ham{{else}}unsure{{end}}">{{.V.Label}}</span></td>
<td class="small">{{.V.Reason}}</td><td class="small muted">{{.V.Model}}</td><td class="from small">{{.A.From}}</td>
<td class="subj">{{if .A.MsgID}}<a href="/m?id={{.A.MsgID}}">{{.A.Subject}}</a>{{else}}{{.A.Subject}}{{end}}</td>
<td class="small">{{.A.Newsgroups}}</td><td class="n">{{.A.Lines}}</td></tr>{{end}}
</table></div>
{{if .Next}}<p><a href="/labels?stage={{.Stage}}&label={{.Label}}&before={{.Next}}">older →</a></p>{{end}}
{{template "foot"}}{{end}}

{{define "nocem"}}{{template "head"}}
<h1>NoCeM notices</h1>
{{if .Rows}}<p>{{num .Total}} Message-IDs listed; {{num .Spam}} of them under types counted as spam (they go into the history file).</p>
<div class="wrap"><table><tr><th>Type</th><th>Issuer</th><th class="n">Message-IDs</th><th>Counted as spam</th></tr>
{{range .Rows}}<tr class="{{if .Spam}}spam{{else}}ham{{end}}"><td>{{.Type}}</td><td>{{.Issuer}}</td><td class="n">{{num .N}}</td><td>{{if .Spam}}yes{{else}}no{{end}}</td></tr>{{end}}
</table></div>
{{else}}<p class="muted">Counting, about two minutes after start. Reload then.</p>{{end}}
{{template "foot"}}{{end}}
`
