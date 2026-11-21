package spamfilter

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Candidates for labelling: what the unsure pass (run -mode unsure) keeps
// of the articles it reads, one JSON line each, gzip-compressed. Each run
// writes a new file in the candidate directory, so a run killed while
// writing cuts short only the end of its own file.

// Candidate kinds.
const (
	CandUnsure = "u" // the local model could not decide
	CandClean  = "h" // judged ham: a sample, for spot checks
)

// Candidate is an article from the overview, with the model's logit.
type Candidate struct {
	Article
	Logit float32 `json:"z"`
	Kind  string  `json:"k"`
}

// CandWriter appends candidates to a file.
type CandWriter struct {
	f  *os.File
	gz *gzip.Writer
	w  *bufio.Writer
}

// OpenCandWriter creates a new file in dir.
func OpenCandWriter(dir string) (*CandWriter, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	name := filepath.Join(dir, "part-"+time.Now().UTC().Format("20060102-150405.000000")+".jsonl.gz")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		return nil, err
	}
	gz := gzip.NewWriter(f)
	return &CandWriter{f: f, gz: gz, w: bufio.NewWriterSize(gz, 1<<20)}, nil
}

// Write adds candidates and flushes them to the file, so what progress
// records as done is on disk.
func (c *CandWriter) Write(cs []Candidate) error {
	enc := json.NewEncoder(c.w)
	for _, x := range cs {
		if err := enc.Encode(x); err != nil {
			return err
		}
	}
	if err := c.w.Flush(); err != nil {
		return err
	}
	return c.gz.Flush()
}

func (c *CandWriter) Close() error {
	err := c.w.Flush()
	if gerr := c.gz.Close(); err == nil {
		err = gerr
	}
	if ferr := c.f.Close(); err == nil {
		err = ferr
	}
	return err
}

// ReadCandidates calls fn for every candidate in the files of dir, in
// order, with a running index. A file cut short at the end (a pass killed
// while writing) ends early without an error.
func ReadCandidates(dir string, fn func(i int, c Candidate) error) error {
	names, err := filepath.Glob(filepath.Join(dir, "part-*.jsonl.gz"))
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("no candidate files in %s (run -mode unsure first)", dir)
	}
	sort.Strings(names)
	i := 0
	for _, name := range names {
		if err := readCandFile(name, &i, fn); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func readCandFile(path string, i *int, fn func(i int, c Candidate) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil // empty, or killed before the first flush
	}
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var c Candidate
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			// a line cut short in the last member
			if _, more := peek(sc); !more {
				return nil
			}
			return err
		}
		if err := fn(*i, c); err != nil {
			return err
		}
		*i++
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	return nil
}

func peek(sc *bufio.Scanner) ([]byte, bool) {
	if sc.Scan() {
		return sc.Bytes(), true
	}
	return nil, false
}
