package spamfilter

import (
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Labels.
const (
	Spam   = "spam"
	Ham    = "ham"
	Unsure = "unsure"
)

// Stages.
const (
	StageRules = "rules"
	StageLLM   = "llm"
	StageModel = "model" // the local model (see Model)
)

// Verdict is the label for one key (see Article.Key), or for one article
// once exported.
type Verdict struct {
	MsgID  string `json:"msgid,omitempty"`
	Key    string `json:"key,omitempty"`
	Label  string `json:"label"`
	Stage  string `json:"stage"`
	Reason string `json:"reason"`
	Model  string `json:"model,omitempty"`
	At     string `json:"at,omitempty"` // when it was stored (RFC 3339, UTC)
}

// CleanfeedRule maps a verdict onto cleanfeed-ng's stable rule names and
// CF-* codes (cleanfeed-ng docs/REASON-CODES.md), so its audit tools can
// compare. The Breidbart index is the corpus-wide form of cleanfeed's
// duplicate-body EMP check; subject rules are its bad-subject check. Model
// labels have no cleanfeed rule: they become llm.<label>, and the code is
// built the way cleanfeed's reject_code() builds one for an unknown rule.
func (v Verdict) CleanfeedRule() (rule, code string) {
	switch {
	case v.Stage == StageRules && strings.HasPrefix(v.Reason, "bi="):
		return "emp.md5", "CF-EMP-MD5"
	case v.Stage == StageRules && strings.HasPrefix(v.Reason, "subj:"):
		return "header.subject", "CF-BAD-SUBJECT"
	case v.Stage == StageRules && strings.HasPrefix(v.Reason, "from:"):
		return "header.from", "CF-BAD-FROM"
	case v.Stage == StageLLM:
		rule = "llm." + v.Label
	case v.Stage == StageModel:
		rule = "model." + v.Label
	case v.Stage == StageNocem:
		rule = "nocem." + v.Label
	default:
		rule = "other"
	}
	return rule, "CF-" + strings.ToUpper(rule)
}

// Copy is one posting of a body: when, and to how many groups.
type Copy struct {
	Date   int64
	Groups int
}

// Breidbart returns the highest Breidbart index of the copies inside any
// window of the given length: the sum of the square roots of each copy's
// group count. Usenet spam was cancelled at 20 over 45 days. Copies without
// a date (0) all fall into one window at the start.
func Breidbart(copies []Copy, window time.Duration) float64 {
	if len(copies) == 0 {
		return 0
	}
	c := append([]Copy(nil), copies...)
	sort.Slice(c, func(i, j int) bool { return c[i].Date < c[j].Date })
	w := int64(window / time.Second)
	best, sum := 0.0, 0.0
	lo := 0
	for hi := range c {
		sum += math.Sqrt(float64(max(c[hi].Groups, 1)))
		for c[hi].Date-c[lo].Date > w {
			sum -= math.Sqrt(float64(max(c[lo].Groups, 1)))
			lo++
		}
		best = max(best, sum)
	}
	return best
}

// Clusters collects the copies of articles for the Breidbart index. Copies
// cluster two ways: by FSL key (both sources; replies are left out, since a
// prolific poster's replies in one thread can share From, Subject and line
// count), and by body hash (mbox articles only). An article's index is the
// higher of the two.
type Clusters struct {
	byKey    map[string][]Copy
	byBody   map[string][]Copy
	bodiesOf map[string][]string // FSL key -> body hashes seen with it
}

func NewClusters() *Clusters {
	return &Clusters{byKey: map[string][]Copy{}, byBody: map[string][]Copy{}, bodiesOf: map[string][]string{}}
}

// Add records one copy (one Message-ID).
func (c *Clusters) Add(key, bodyHash string, date int64, groups int, reply bool) {
	cp := Copy{Date: date, Groups: groups}
	if !reply {
		c.byKey[key] = append(c.byKey[key], cp)
	}
	if bodyHash != "" {
		c.byBody[bodyHash] = append(c.byBody[bodyHash], cp)
		if !slices.Contains(c.bodiesOf[key], bodyHash) {
			c.bodiesOf[key] = append(c.bodiesOf[key], bodyHash)
		}
	}
}

// Index returns the Breidbart index for the articles with this FSL key.
func (c *Clusters) Index(key string, window time.Duration) float64 {
	bi := Breidbart(c.byKey[key], window)
	for _, h := range c.bodiesOf[key] {
		bi = max(bi, Breidbart(c.byBody[h], window))
	}
	return bi
}

// Rules decides the clear cases without a model. Every rule labels spam;
// nothing is labelled ham by rule, so a miss only costs a model call.
type Rules struct {
	BIThreshold float64       // Breidbart index at which an article is spam (20)
	Window      time.Duration // window for the index (45 days)
	MinLines    int           // shorter articles ("test", "+1") are not judged by the index
}

// DefaultRules are the classic Usenet cancel thresholds.
var DefaultRules = Rules{BIThreshold: 20, Window: 45 * 24 * time.Hour, MinLines: 3}

// subjectRules are high-precision spam subjects. Keep each one specific:
// a rule that fires on legitimate posts makes the rules stage worse than
// sending the article to the model. Spot checks (2026-11-03, the body read
// by the model API) removed two: "$$$" (498 spam, 261 ham: ISO-2022-JP
// subjects show "$B...(B", and jobs and for-sale posts use it) and a bare
// "MMF" (31 spam, 51 ham: NoCeM's own "MMF Report" notices).
var subjectRules = []struct {
	name string
	re   *regexp.Regexp
}{
	{"mmf", regexp.MustCompile(`(?i)make\s+(big\s+)?money\s+fast`)},
	{"earn", regexp.MustCompile(`(?i)\b(earn|make)\s+(up\s+to\s+)?\$\s?\d[\d,.]*\s*(k\b)?.{0,20}\b(a|per|each|every)\s+(day|week|month)`)},
	{"home-income", regexp.MustCompile(`(?i)\b(work|earn|money|cash|income)\s+(from|at)\s+home\b`)},
	{"get-rich", regexp.MustCompile(`(?i)get\s+rich\s+quick|financial\s+freedom|cash\s+gifting|free\s+cash\b`)},
	{"surveys", regexp.MustCompile(`(?i)\bpaid\s+(online\s+)?surveys?\b|\bget\s+paid\s+(to|for)\b`)},
	{"pharma", regexp.MustCompile(`(?i)\b(viagra|cialis|levitra|xanax|valium|phentermine|tramadol)\b`)},
	{"replica", regexp.MustCompile(`(?i)\breplica\s+(watch|watches|bags?|handbags?|rolex)|\bcheap\s+(rolex|replica|handbags|jerseys)\b`)},
}

// ebookWords all in one subject mark the e-book download spam (the
// "Kindle" rule of the chmurka.net filter; 145 of 145 labelled spam).
var ebookWords = []string{"KINDLE", "PDF", "EBOOK", "EPUB"}

// chmurkaRules switches the From blacklist and the e-book rule; a build can
// turn them off with -ldflags "-X github.com/go-while/usenet-spamclassifier/spamfilter.chmurkaRules=off".
var chmurkaRules = "on"

var addrRe = regexp.MustCompile(`[a-z0-9._%+-]+@[a-z0-9.-]+`)

// knownSpamFrom reports whether the From header holds a known spammer
// address (see knownSpamFroms).
func knownSpamFrom(from string) bool {
	for _, a := range addrRe.FindAllString(strings.ToLower(from), -1) {
		if knownSpamFroms[a] {
			return true
		}
	}
	return false
}

// Decide applies the rules to an article whose body has Breidbart index bi
// across the corpus. ok is false when no rule fires.
func (r Rules) Decide(a Article, bi float64) (v Verdict, ok bool) {
	if a.Lines >= r.MinLines && bi >= r.BIThreshold {
		return Verdict{Key: a.Key, Label: Spam, Stage: StageRules, Reason: fmt.Sprintf("bi=%.1f", bi)}, true
	}
	if chmurkaRules == "on" && knownSpamFrom(a.From) {
		// before the reply check: this dating spam posts as "Re: ..."
		return Verdict{Key: a.Key, Label: Spam, Stage: StageRules, Reason: "from:known"}, true
	}
	if isReply(a.Subject) || inAntiSpamGroup(a.Newsgroups) {
		// a reply under a spam subject is as often a complaint about the
		// spam as more of it, and the anti-spam groups quote spam subjects
		// in reports and complaints: the model tells them apart
		return Verdict{}, false
	}
	for _, sr := range subjectRules {
		if sr.re.MatchString(a.Subject) {
			return Verdict{Key: a.Key, Label: Spam, Stage: StageRules, Reason: "subj:" + sr.name}, true
		}
	}
	if up := strings.ToUpper(a.Subject); chmurkaRules == "on" && !slices.ContainsFunc(ebookWords, func(w string) bool { return !strings.Contains(up, w) }) {
		return Verdict{Key: a.Key, Label: Spam, Stage: StageRules, Reason: "subj:ebook"}, true
	}
	return Verdict{}, false
}

// antiSpamGroups are where spam is reported and discussed (prefixes).
var antiSpamGroups = []string{"news.admin.net-abuse.", "news.lists.filters", "alt.nocem.misc", "alt.spam",
	"de.admin.net-abuse.", "fr.usenet.abus.", "news.admin.spam"}

func inAntiSpamGroup(newsgroups string) bool {
	for _, g := range strings.Split(newsgroups, ",") {
		g = strings.TrimSpace(g)
		for _, p := range antiSpamGroups {
			if strings.HasPrefix(g, p) {
				return true
			}
		}
	}
	return false
}

var replyRE = regexp.MustCompile(`(?i)^\s*(re|aw|sv|antw|odp)\s*(\[\d+\])?\s*:`)

func isReply(subject string) bool { return replyRE.MatchString(subject) }

// InAntiSpamGroup reports whether any of the groups is one where spam is
// reported and discussed.
func InAntiSpamGroup(newsgroups string) bool { return inAntiSpamGroup(newsgroups) }
