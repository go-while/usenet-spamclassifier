package spamfilter

import (
	"archive/zip"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	mbox "github.com/go-while/go-lib-mbox2nntp"
)

// MaxBody is how much of a body is read for hash and snippet; the rest is
// skipped (binaries, huge digests).
const MaxBody = 1 << 20

// ReadFile reads every article of an mbox file (plain, .gz, or .zip with
// mbox entries) and calls fn for each. The file is only read.
func ReadFile(path string, fn func(Article) error) error {
	if strings.HasSuffix(path, ".zip") {
		zr, err := zip.OpenReader(path)
		if err != nil {
			return err
		}
		defer zr.Close()
		for _, f := range zr.File {
			if f.FileInfo().IsDir() || strings.HasSuffix(f.Name, ".csv") {
				continue
			}
			r, err := f.Open()
			if err != nil {
				return fmt.Errorf("%s: %s: %w", path, f.Name, err)
			}
			err = ReadMbox(r, withSource(path+"/"+f.Name, fn))
			r.Close()
			if err != nil {
				return fmt.Errorf("%s: %s: %w", path, f.Name, err)
			}
		}
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		defer gz.Close()
		r = gz
	}
	if err := ReadMbox(r, withSource(path, fn)); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func withSource(src string, fn func(Article) error) func(Article) error {
	return func(a Article) error {
		a.Source = src
		return fn(a)
	}
}

// ReadMbox reads articles from an mbox stream. Messages the parser cannot
// frame are skipped, as mbox2nntp does. Articles written by mbox2nntp's
// exporters (marked "X-Mbox2nntp-Format: mboxrd") are unquoted first.
func ReadMbox(r io.Reader, fn func(Article) error) error {
	mr, err := mbox.CreateMboxStream(bufio.NewReaderSize(r, 1<<20))
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	skippedInARow := 0
	for {
		msg, err := mr.ReadMessage()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			// the parser resyncs to the next separator; give up only if it
			// stops moving forward
			if skippedInARow++; skippedInARow > 1000 {
				return fmt.Errorf("mbox parser not advancing: %w", err)
			}
			continue
		}
		skippedInARow = 0
		head := append([]string(nil), msg.Headers()...)
		body, lines, err := readBody(msg.BodyReader())
		if err != nil {
			return err
		}
		if isQuoted(head) {
			for i := range head {
				head[i] = unquote(head[i])
			}
			for i := range body {
				body[i] = unquote(body[i])
			}
		}
		if err := fn(NewArticle(head, body, lines)); err != nil {
			return err
		}
	}
}

// readBody returns the first MaxBody bytes of the body as lines and the
// line count of the whole body. Trailing empty lines are left out, the way
// mbox2nntp drops them before sending, so the count matches the :lines a
// news server reports for the article. The body is read to its end: the
// parser needs that.
func readBody(r io.Reader) ([]string, int, error) {
	var (
		kept    []byte
		buf     = make([]byte, 64<<10)
		n, last int  // lines seen; number of the last non-empty one
		inText  bool // the current line has something besides CR
	)
	for {
		m, err := r.Read(buf)
		if room := MaxBody - len(kept); room > 0 {
			kept = append(kept, buf[:min(m, room)]...)
		}
		for _, ch := range buf[:m] {
			switch ch {
			case '\n':
				n++
				if inText {
					last = n
				}
				inText = false
			case '\r':
			default:
				inText = true
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, err
		}
	}
	if inText {
		last = n + 1
	}
	s := strings.TrimRight(strings.ReplaceAll(string(kept), "\r\n", "\n"), "\n")
	if s == "" {
		return nil, last, nil
	}
	return strings.Split(s, "\n"), last, nil
}

// isQuoted, needsQuote and unquote follow mbox2nntp's internal/mboxout.
func isQuoted(head []string) bool {
	for _, l := range head {
		if name, value, ok := strings.Cut(l, ":"); ok &&
			strings.EqualFold(strings.TrimSpace(name), "X-Mbox2nntp-Format") &&
			strings.EqualFold(strings.TrimSpace(value), "mboxrd") {
			return true
		}
	}
	return false
}

func needsQuote(l string) bool {
	t := strings.TrimLeft(l, ">")
	return strings.HasPrefix(t, "From ") || strings.HasPrefix(t, "#! rnews ")
}

func unquote(l string) string {
	if strings.HasPrefix(l, ">") && needsQuote(l[1:]) {
		return l[1:]
	}
	return l
}
