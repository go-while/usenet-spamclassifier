package spamfilter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// OpenAI classifies articles with an OpenAI model through the Responses
// API, with the same prompt, article format and answer letters as LLM, so
// its labels can be compared with Claude's.
type OpenAI struct {
	Key         string
	Model       string // e.g. "gpt-6-luna"
	Effort      string // reasoning effort: low suits classification
	BatchSize   int    // articles per request
	Concurrency int    // requests in flight
	URL         string // default https://api.openai.com/v1/responses
	HTTP        *http.Client

	in, cached, out    atomic.Int64
	requests, refusals atomic.Int64
}

// Usage is the token count so far. Input counts the uncached input only;
// cached input is in CacheRead, so Cost prices it at a tenth.
func (o *OpenAI) Usage() Usage {
	c := o.cached.Load()
	return Usage{
		Requests: o.requests.Load(), Refusals: o.refusals.Load(),
		Input: o.in.Load() - c, CacheRead: c, Output: o.out.Load(),
	}
}

// Cost is the list price of a usage of this model.
func (o *OpenAI) Cost(u Usage) float64 { return Cost(o.Model, u) }

// Classify labels the articles, BatchSize per request, Concurrency
// requests at a time. A verdict with an empty Label got no usable answer.
func (o *OpenAI) Classify(ctx context.Context, arts []Article) ([]Verdict, error) {
	bs := max(o.BatchSize, 1)
	out := make([]Verdict, len(arts))
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		sem      = make(chan struct{}, max(o.Concurrency, 1))
	)
	for start := 0; start < len(arts); start += bs {
		end := min(start+bs, len(arts))
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return out, ctx.Err()
		}
		mu.Lock()
		stop := firstErr != nil
		mu.Unlock()
		if stop {
			<-sem
			break
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			defer func() { <-sem }()
			vs, err := o.classifyPatient(ctx, arts[start:end])
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			copy(out[start:end], vs)
		}(start, end)
	}
	wg.Wait()
	return out, firstErr
}

// oaiError is an HTTP error reply; retry tells whether waiting may help.
type oaiError struct {
	status int
	msg    string
}

func (e *oaiError) Error() string { return fmt.Sprintf("openai: HTTP %d: %s", e.status, e.msg) }

func (e *oaiError) retry() bool {
	return e.status == 429 || e.status == 408 || e.status >= 500
}

// classifyPatient retries rate limits, server errors and network errors,
// waiting longer each time: a long run should slow down, not stop.
func (o *OpenAI) classifyPatient(ctx context.Context, arts []Article) ([]Verdict, error) {
	wait := 5 * time.Second
	for try := 0; ; try++ {
		vs, err := o.classifyOne(ctx, arts)
		if err == nil || ctx.Err() != nil || try >= 20 {
			return vs, err
		}
		if e, ok := err.(*oaiError); ok && !e.retry() {
			return vs, err
		}
		log.Printf("openai: %v; retry in %v", err, wait)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return vs, ctx.Err()
		}
		wait = min(2*wait, 2*time.Minute)
	}
}

type oaiRequest struct {
	Model           string        `json:"model"`
	Instructions    string        `json:"instructions"`
	Input           string        `json:"input"`
	Reasoning       *oaiReasoning `json:"reasoning,omitempty"`
	MaxOutputTokens int           `json:"max_output_tokens"`
	Store           bool          `json:"store"`
}

type oaiReasoning struct {
	Effort string `json:"effort"`
}

type oaiResponse struct {
	Model             string `json:"model"`
	Status            string `json:"status"`
	IncompleteDetails *struct {
		Reason string `json:"reason"`
	} `json:"incomplete_details"`
	Output []struct {
		Type    string `json:"type"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"output"`
	Usage struct {
		InputTokens        int64 `json:"input_tokens"`
		InputTokensDetails struct {
			CachedTokens int64 `json:"cached_tokens"`
		} `json:"input_tokens_details"`
		OutputTokens int64 `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (o *OpenAI) classifyOne(ctx context.Context, arts []Article) ([]Verdict, error) {
	req := oaiRequest{
		Model:           o.Model,
		Instructions:    systemPrompt,
		Input:           FormatBatch(arts),
		MaxOutputTokens: 16000,
	}
	if o.Effort != "" {
		req.Reasoning = &oaiReasoning{Effort: o.Effort}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	url := o.URL
	if url == "" {
		url = "https://api.openai.com/v1/responses"
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Authorization", "Bearer "+o.Key)
	hc := o.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Minute}
	}
	resp, err := hc.Do(hr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	var r oaiResponse
	jerr := json.Unmarshal(raw, &r)
	if resp.StatusCode != http.StatusOK {
		msg := clip(strings.TrimSpace(string(raw)), 300)
		if jerr == nil && r.Error != nil {
			msg = r.Error.Message
		}
		return nil, &oaiError{status: resp.StatusCode, msg: msg}
	}
	if jerr != nil {
		return nil, fmt.Errorf("openai: bad reply: %v", jerr)
	}
	return o.verdicts(&r, arts), nil
}

// verdicts reads one reply and counts its usage.
func (o *OpenAI) verdicts(r *oaiResponse, arts []Article) []Verdict {
	o.requests.Add(1)
	o.in.Add(r.Usage.InputTokens)
	o.cached.Add(r.Usage.InputTokensDetails.CachedTokens)
	o.out.Add(r.Usage.OutputTokens)

	model := r.Model
	if model == "" {
		model = o.Model
	}
	vs := make([]Verdict, len(arts))
	for i, a := range arts {
		vs[i] = Verdict{Key: a.Key, MsgID: a.MsgID, Stage: StageLLM, Model: model}
	}
	var text strings.Builder
	refused := false
	for _, item := range r.Output {
		if item.Type != "message" {
			continue
		}
		for _, c := range item.Content {
			switch c.Type {
			case "output_text":
				text.WriteString(c.Text)
				text.WriteByte('\n')
			case "refusal":
				refused = true
			}
		}
	}
	if refused && text.Len() == 0 {
		o.refusals.Add(1)
		return vs
	}
	parsed := ParseLabels(text.String())
	if len(parsed) < len(arts)/2 {
		why := r.Status
		if r.IncompleteDetails != nil {
			why += " " + r.IncompleteDetails.Reason
		}
		log.Printf("openai %s: only %d of %d answers readable (%s); reply begins %q", o.Model, len(parsed), len(arts), why, clip(text.String(), 300))
	}
	for n, lv := range parsed {
		if n >= 1 && n <= len(vs) {
			vs[n-1].Label = lv.label
			vs[n-1].Reason = lv.label + ":" + lv.reason
		}
	}
	return vs
}
