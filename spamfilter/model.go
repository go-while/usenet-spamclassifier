package spamfilter

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"math/rand/v2"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Model is a logistic regression over hashed features of the overview
// fields (subject text, From, groups, crosspost count, lines, reply). It is
// trained on the model-labelled sample and scores every other article
// locally, so the API is needed only for a sample and the uncertain cases.
type Model struct {
	Bits    uint8     // feature space is 1<<Bits
	W       []float32 // weights
	Bias    float32
	SpamAt  float32 // logit at or above which an article is spam
	HamAt   float32 // logit at or below which it is ham; between: uncertain
	Trained int     // examples used
}

// Logit returns the model's raw score for an article; the spam
// probability is 1/(1+e^-logit). Thresholds compare logits: probabilities
// round to 1.0 for many articles, and a tie can't be cut.
func (m *Model) Logit(a Article) float64 {
	z := float64(m.Bias)
	mask := uint32(len(m.W) - 1)
	for _, f := range Features(a) {
		z += float64(m.W[f&mask])
	}
	return z
}

// Score returns the spam probability of an article.
func (m *Model) Score(a Article) float32 {
	return float32(sigmoid(m.Logit(a)))
}

func sigmoid(z float64) float64 { return 1 / (1 + math.Exp(-z)) }

// Decide labels an article: spam, ham, or "" when its logit falls between
// the thresholds. p is the spam probability.
func (m *Model) Decide(a Article) (label string, p float32) {
	z := m.Logit(a)
	p = float32(sigmoid(z))
	switch {
	case z >= float64(m.SpamAt):
		return Spam, p
	case z <= float64(m.HamAt):
		return Ham, p
	}
	return "", p
}

var (
	wordRE   = regexp.MustCompile(`[\p{L}\p{N}$€£%]+`)
	addrRE   = regexp.MustCompile(`[^\s<>()"]+@[^\s<>()"]+`)
	numRunRE = regexp.MustCompile(`\d+`)
)

// Features hashes an article's features. Digits are folded so campaign
// serial numbers ("FREE hosting 8170") look alike.
func Features(a Article) []uint32 {
	var fs []uint32
	add := func(kind, v string) {
		h := fnv.New32a()
		h.Write([]byte(kind))
		h.Write([]byte{0})
		h.Write([]byte(v))
		fs = append(fs, h.Sum32())
	}
	subj := strings.ToLower(replyRE.ReplaceAllString(a.Subject, ""))
	subj = numRunRE.ReplaceAllString(subj, "0")
	for _, w := range wordRE.FindAllString(subj, -1) {
		add("sw", w)
	}
	rs := []rune(" " + normSpace(clip(subj, 200)) + " ")
	for n := 3; n <= 5; n++ {
		for i := 0; i+n <= len(rs); i++ {
			add("s"+strconv.Itoa(n), string(rs[i:i+n]))
		}
	}
	add("caps", bucket(capsRatio(a.Subject), []float64{0.2, 0.5, 0.8}))
	add("bang", bucket(float64(strings.Count(a.Subject, "!")), []float64{1, 3}))
	add("dollar", bucket(float64(strings.Count(a.Subject, "$")), []float64{1, 3}))
	add("slen", bucket(float64(len(a.Subject)), []float64{10, 30, 60, 100}))

	from := strings.ToLower(a.From)
	if addr := addrRE.FindString(from); addr != "" {
		local, domain, _ := strings.Cut(addr, "@")
		add("fd", domain)
		if parts := strings.Split(domain, "."); len(parts) >= 2 {
			add("fd2", strings.Join(parts[len(parts)-2:], "."))
		}
		add("fl", numRunRE.ReplaceAllString(local, "0"))
		from = strings.Replace(from, addr, " ", 1)
	} else {
		add("fnoaddr", "1")
	}
	for _, w := range wordRE.FindAllString(from, -1) {
		add("fn", w)
	}

	groups := strings.Split(a.Newsgroups, ",")
	for _, g := range groups {
		g = strings.TrimSpace(strings.ToLower(g))
		if g == "" {
			continue
		}
		add("g", g)
		parts := strings.Split(g, ".")
		add("h", parts[0])
		if len(parts) > 1 {
			add("h2", parts[0]+"."+parts[1])
		}
	}
	add("ng", bucket(float64(a.Groups), []float64{1, 2, 4, 8, 16}))
	if a.Lines >= 0 {
		add("ln", bucket(float64(a.Lines), []float64{0, 2, 5, 15, 40, 100, 400}))
	}
	add("re", strconv.FormatBool(a.Reply))
	// each feature counts once: "hhhhhhhh" must not add the same n-gram's
	// weight dozens of times
	slices.Sort(fs)
	return slices.Compact(fs)
}

func capsRatio(s string) float64 {
	var up, letters int
	for _, r := range s {
		if unicode.IsLetter(r) {
			letters++
			if unicode.IsUpper(r) {
				up++
			}
		}
	}
	if letters < 5 {
		return 0
	}
	return float64(up) / float64(letters)
}

func bucket(v float64, edges []float64) string {
	for i, e := range edges {
		if v <= e {
			return strconv.Itoa(i)
		}
	}
	return strconv.Itoa(len(edges))
}

// Example is one labelled article for training.
type Example struct {
	A    Article
	Spam bool
	// Extra examples (from NoCeM notices) are only learned from: the
	// thresholds and the report come from the labelled examples alone.
	Extra bool
}

// TrainReport says how the model did on the held-out examples.
type TrainReport struct {
	Train, Test             int
	SpamAt, HamAt           float32
	Precision, Recall       float64 // of the spam label, on the test set, at SpamAt
	HamPrecision, HamRecall float64 // of the ham label, at HamAt
	Uncertain               float64 // share of test examples between the thresholds
	TestSpam, TestHam       int
}

// Train fits a model. The examples are split 80/10/10: the model learns
// from the first part, the thresholds come from the second (SpamAt is the
// lowest score at which the spam label still has spamPrec there, HamAt
// the highest at which the ham label has hamPrec), and the report is
// measured on the third, which played no part in either.
func Train(ex []Example, bits uint8, epochs int, spamPrec, hamPrec float64, seed uint64) (*Model, TrainReport, error) {
	train, val, test, err := splitExamples(ex, seed)
	if err != nil {
		return nil, TrainReport{}, err
	}
	m, err := fit(train, bits, epochs, seed)
	if err != nil {
		return nil, TrainReport{}, err
	}
	m.setThresholds(val, spamPrec, hamPrec)
	return m, m.evaluate(test, len(train)), nil
}

// LearningCurve trains on growing shares of the training part (same
// validation and test parts each time) and reports each. If the scores
// still rise at the full share, more labelled data will help.
func LearningCurve(ex []Example, shares []float64, bits uint8, epochs int, spamPrec, hamPrec float64, seed uint64) ([]TrainReport, error) {
	train, val, test, err := splitExamples(ex, seed)
	if err != nil {
		return nil, err
	}
	var out []TrainReport
	for _, sh := range shares {
		n := int(float64(len(train)) * sh)
		if n < 50 {
			continue
		}
		m, err := fit(train[:n], bits, epochs, seed)
		if err != nil {
			return nil, err
		}
		m.setThresholds(val, spamPrec, hamPrec)
		out = append(out, m.evaluate(test, n))
	}
	return out, nil
}

func splitExamples(ex []Example, seed uint64) (train, val, test []Example, err error) {
	if len(ex) < 200 {
		return nil, nil, nil, fmt.Errorf("only %d labelled examples; need at least 200", len(ex))
	}
	var labelled, extra []Example
	for _, e := range ex {
		if e.Extra {
			extra = append(extra, e)
		} else {
			labelled = append(labelled, e)
		}
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x5bd1e995))
	n := len(labelled) / 10
	if n < 20 {
		return nil, nil, nil, fmt.Errorf("only %d labelled examples besides the extra ones; need at least 200", len(labelled))
	}
	rng.Shuffle(len(labelled), func(i, j int) { labelled[i], labelled[j] = labelled[j], labelled[i] })
	train = append(append([]Example(nil), labelled[2*n:]...), extra...)
	// mix the extra examples in, so a learning curve's shares hold both kinds
	rng.Shuffle(len(train), func(i, j int) { train[i], train[j] = train[j], train[i] })
	return train, labelled[:n], labelled[n : 2*n], nil
}

// fit learns the weights: logistic regression with AdaGrad, the classes
// weighted evenly.
func fit(train []Example, bits uint8, epochs int, seed uint64) (*Model, error) {
	rng := rand.New(rand.NewPCG(seed^0x9e37, seed))
	m := &Model{Bits: bits, W: make([]float32, 1<<bits)}
	mask := uint32(len(m.W) - 1)
	// AdaGrad keeps rare features (a spam domain seen twice) learning fast
	g2 := make([]float32, len(m.W))
	var bg2 float32
	const lr, l2 = 0.3, 1e-6
	feats := make([][]uint32, len(train))
	var nSpam int
	for i, e := range train {
		feats[i] = Features(e.A)
		for j := range feats[i] {
			feats[i][j] &= mask
		}
		if e.Spam {
			nSpam++
		}
	}
	if nSpam == 0 || nSpam == len(train) {
		return nil, errors.New("training data has only one class")
	}
	wSpam := float32(len(train)) / float32(2*nSpam)
	wHam := float32(len(train)) / float32(2*(len(train)-nSpam))
	order := make([]int, len(train))
	for i := range order {
		order[i] = i
	}
	for ep := 0; ep < epochs; ep++ {
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		for _, i := range order {
			z := float64(m.Bias)
			for _, f := range feats[i] {
				z += float64(m.W[f])
			}
			p := float32(1 / (1 + math.Exp(-z)))
			y, cw := float32(0), wHam
			if train[i].Spam {
				y, cw = 1, wSpam
			}
			g := (p - y) * cw
			for _, f := range feats[i] {
				gf := g + l2*m.W[f]
				g2[f] += gf * gf
				m.W[f] -= lr * gf / float32(math.Sqrt(float64(g2[f]))+1e-6)
			}
			bg2 += g * g
			m.Bias -= lr * g / float32(math.Sqrt(float64(bg2))+1e-6)
		}
	}
	m.Trained = len(train)
	return m, nil
}

type scored struct {
	p    float32 // logit
	spam bool
}

func (m *Model) scoreAll(ex []Example) []scored {
	s := make([]scored, len(ex))
	for i, e := range ex {
		s[i] = scored{float32(m.Logit(e.A)), e.Spam}
	}
	sort.Slice(s, func(i, j int) bool { return s[i].p > s[j].p })
	return s
}

// setThresholds picks SpamAt and HamAt on held-out examples.
func (m *Model) setThresholds(val []Example, spamPrec, hamPrec float64) {
	scores := m.scoreAll(val)
	m.SpamAt = math.MaxFloat32 // nothing is spam unless a threshold qualifies
	tp := 0
	for i, s := range scores {
		if s.spam {
			tp++
		}
		if float64(tp)/float64(i+1) >= spamPrec && (i+1 == len(scores) || scores[i+1].p < s.p) {
			m.SpamAt = s.p
		}
	}
	m.HamAt = -math.MaxFloat32
	tn := 0
	for i := len(scores) - 1; i >= 0; i-- {
		s := scores[i]
		if !s.spam {
			tn++
		}
		k := len(scores) - i
		if float64(tn)/float64(k) >= hamPrec && (i == 0 || scores[i-1].p > s.p) {
			m.HamAt = s.p
		}
	}
	if m.HamAt >= m.SpamAt {
		m.HamAt = m.SpamAt - 1e-3
	}
}

// evaluate measures the model with its thresholds on test examples.
func (m *Model) evaluate(test []Example, trained int) TrainReport {
	r := TrainReport{Train: trained, Test: len(test), SpamAt: m.SpamAt, HamAt: m.HamAt}
	var sp, spOK, hm, hmOK, unc int
	for _, s := range m.scoreAll(test) {
		if s.spam {
			r.TestSpam++
		}
		switch {
		case s.p >= m.SpamAt:
			sp++
			if s.spam {
				spOK++
			}
		case s.p <= m.HamAt:
			hm++
			if !s.spam {
				hmOK++
			}
		default:
			unc++
		}
	}
	r.TestHam = len(test) - r.TestSpam
	r.Precision, r.Recall = ratio(spOK, sp), ratio(spOK, r.TestSpam)
	r.HamPrecision, r.HamRecall = ratio(hmOK, hm), ratio(hmOK, r.TestHam)
	r.Uncertain = ratio(unc, len(test))
	return r
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

const modelMagic = "SFM2" // thresholds are logits

// Save writes the model in a small binary format.
func (m *Model) Save(path string) error {
	f, err := os.Create(path + ".tmp")
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	w.WriteString(modelMagic)
	binary.Write(w, binary.LittleEndian, m.Bits)
	binary.Write(w, binary.LittleEndian, m.Bias)
	binary.Write(w, binary.LittleEndian, m.SpamAt)
	binary.Write(w, binary.LittleEndian, m.HamAt)
	binary.Write(w, binary.LittleEndian, int64(m.Trained))
	if err := binary.Write(w, binary.LittleEndian, m.W); err != nil {
		f.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// LoadModel reads a model written by Save.
func LoadModel(path string) (*Model, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != modelMagic {
		return nil, fmt.Errorf("%s: not a spamfilter model", path)
	}
	m := &Model{}
	var trained int64
	for _, p := range []any{&m.Bits, &m.Bias, &m.SpamAt, &m.HamAt, &trained} {
		if err := binary.Read(r, binary.LittleEndian, p); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if m.Bits < 10 || m.Bits > 28 {
		return nil, fmt.Errorf("%s: bad feature size %d", path, m.Bits)
	}
	m.Trained = int(trained)
	m.W = make([]float32, 1<<m.Bits)
	if err := binary.Read(r, binary.LittleEndian, m.W); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// OutOfFold scores every example with a model that did not see it: the
// examples are split into k folds, and each fold is scored by a model
// trained on the others. A confident score against an example's label
// points at a label worth checking.
func OutOfFold(ex []Example, k int, bits uint8, epochs int, seed uint64) ([]float64, error) {
	if k < 2 || len(ex) < 10*k {
		return nil, fmt.Errorf("need at least %d examples for %d folds", 10*k, k)
	}
	fold := make([]int, len(ex))
	rng := rand.New(rand.NewPCG(seed, seed^0x1f2e3d))
	for i := range fold {
		fold[i] = rng.IntN(k)
	}
	out := make([]float64, len(ex))
	for f := 0; f < k; f++ {
		var train []Example
		for i, e := range ex {
			if fold[i] != f {
				train = append(train, e)
			}
		}
		m, err := fit(train, bits, epochs, seed+uint64(f))
		if err != nil {
			return nil, err
		}
		for i, e := range ex {
			if fold[i] == f {
				out[i] = m.Logit(e.A)
			}
		}
	}
	return out, nil
}
