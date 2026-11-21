package spamfilter

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-while/nntp-testkit/client"
)

// NNTP is a minimal reader client: enough for GROUP and OVER, with
// COMPRESS DEFLATE (RFC 8054) when the server offers it.
type NNTP struct {
	conn    net.Conn
	kc      *client.Conn
	r       *textproto.Reader
	w       *bufio.Writer
	flush   func() error
	Timeout time.Duration
}

// DialNNTP connects and reads the greeting.
func DialNNTP(addr string, timeout time.Duration) (*NNTP, error) {
	return DialNNTPLimited(addr, timeout, nil)
}

// DialNNTPLimited is DialNNTP with reads capped by l, which connections
// can share (nil = no cap).
func DialNNTPLimited(addr string, timeout time.Duration, l *Limiter) (*NNTP, error) {
	raw, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	conn := &wireConn{Conn: raw, l: l}
	// the testkit client holds the socket and its reader, so that Compress
	// can hand the bytes buffered after the 206 to its inflater
	kc := &client.Conn{Conn: conn, R: bufio.NewReaderSize(conn, 1<<16), Deadline: max(timeout, time.Second)}
	c := &NNTP{conn: conn, kc: kc, Timeout: timeout}
	c.r = textproto.NewReader(kc.R)
	c.w = bufio.NewWriter(conn)
	c.flush = c.w.Flush
	c.deadline()
	code, msg, err := c.status()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if code != 200 && code != 201 {
		conn.Close()
		return nil, fmt.Errorf("greeting: %d %s", code, msg)
	}
	return c, nil
}

// WireBytes counts the bytes read from all news server sockets, compressed
// or not: what the download costs.
var WireBytes atomic.Int64

// TextBytes counts the overview text OVER returned, after inflating: with
// WireBytes it gives the compression ratio.
var TextBytes atomic.Int64

// wireConn is the socket: reads are counted and paced by the limiter (the
// sender is held back by TCP flow control while it sleeps).
type wireConn struct {
	net.Conn
	l *Limiter
}

func (w *wireConn) Read(p []byte) (int, error) {
	n, err := w.Conn.Read(p)
	if n > 0 {
		WireBytes.Add(int64(n))
		if w.l != nil {
			w.l.wait(n)
		}
	}
	return n, err
}

func (c *NNTP) deadline() {
	if c.Timeout > 0 {
		c.conn.SetDeadline(time.Now().Add(c.Timeout))
	}
}

func (c *NNTP) status() (int, string, error) {
	line, err := c.r.ReadLine()
	if err != nil {
		return 0, "", err
	}
	if len(line) < 3 {
		return 0, line, fmt.Errorf("short response %q", line)
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, line, fmt.Errorf("bad response %q", line)
	}
	return code, strings.TrimSpace(line[3:]), nil
}

// Cmd sends one command and reads the status line.
func (c *NNTP) Cmd(format string, args ...any) (int, string, error) {
	c.deadline()
	fmt.Fprintf(c.w, format+"\r\n", args...)
	if err := c.flush(); err != nil {
		return 0, "", err
	}
	return c.status()
}

// lines reads a dot-terminated multi-line block.
func (c *NNTP) lines() ([]string, error) {
	return c.r.ReadDotLines()
}

// ModeReader sends MODE READER; servers that don't need it may refuse it.
func (c *NNTP) ModeReader() { c.Cmd("MODE READER") }

// Capabilities lists the server's capability lines, upper-cased.
func (c *NNTP) Capabilities() ([]string, error) {
	code, msg, err := c.Cmd("CAPABILITIES")
	if err != nil {
		return nil, err
	}
	if code != 101 {
		return nil, fmt.Errorf("CAPABILITIES: %d %s", code, msg)
	}
	ls, err := c.lines()
	for i := range ls {
		ls[i] = strings.ToUpper(strings.TrimSpace(ls[i]))
	}
	return ls, err
}

// Compress switches the connection to COMPRESS DEFLATE (RFC 8054) in both
// directions. The inflater is nntp-testkit's: compress/flate's reader holds
// back what nnrpd sends after a Z_PARTIAL_FLUSH until more data comes, so
// every second reply stalled; testkit's passes on each byte it can decode.
func (c *NNTP) Compress() error {
	if c.kc.Compressed() {
		return nil
	}
	code, msg, err := c.Cmd("COMPRESS DEFLATE")
	if err != nil {
		return err
	}
	if code != 206 {
		return fmt.Errorf("COMPRESS DEFLATE: %d %s", code, msg)
	}
	if err := c.kc.StartCompress(); err != nil {
		return err
	}
	// writes are deflated and flushed per Write: one flush per command batch
	c.conn = c.kc.Conn
	c.r = textproto.NewReader(c.kc.R)
	c.w = bufio.NewWriterSize(c.kc.Conn, 1<<16)
	c.flush = c.w.Flush
	return nil
}

// Compressed reports whether Compress switched the connection.
func (c *NNTP) Compressed() bool { return c.kc.Compressed() }

// OverviewFormat returns LIST OVERVIEW.FMT: the fields after the article
// number, e.g. "Subject:", ":bytes", "Xref:full".
func (c *NNTP) OverviewFormat() ([]string, error) {
	code, msg, err := c.Cmd("LIST OVERVIEW.FMT")
	if err != nil {
		return nil, err
	}
	if code != 215 {
		return nil, fmt.Errorf("LIST OVERVIEW.FMT: %d %s", code, msg)
	}
	return c.lines()
}

// Group selects a group and returns its estimated count and number range.
func (c *NNTP) Group(name string) (count, low, high int64, err error) {
	code, msg, err := c.Cmd("GROUP %s", name)
	if err != nil {
		return 0, 0, 0, err
	}
	if code != 211 {
		return 0, 0, 0, fmt.Errorf("GROUP %s: %d %s", name, code, msg)
	}
	f := strings.Fields(msg)
	if len(f) < 3 {
		return 0, 0, 0, fmt.Errorf("GROUP %s: %q", name, msg)
	}
	count, _ = strconv.ParseInt(f[0], 10, 64)
	low, _ = strconv.ParseInt(f[1], 10, 64)
	high, _ = strconv.ParseInt(f[2], 10, 64)
	return count, low, high, nil
}

// Over returns the overview lines of the articles low-high in the current
// group. An empty range (423) is no error.
func (c *NNTP) Over(low, high int64) ([]string, error) {
	code, msg, err := c.Cmd("OVER %d-%d", low, high)
	if err != nil {
		return nil, err
	}
	switch code {
	case 224:
		return c.lines()
	case 423:
		return nil, nil
	}
	return nil, fmt.Errorf("OVER %d-%d: %d %s", low, high, code, msg)
}

// Quit ends the session.
func (c *NNTP) Quit() error {
	c.Cmd("QUIT")
	return c.conn.Close()
}

// OverFunc streams the overview lines of articles low-high in the current
// group to fn, without holding the whole response in memory. An empty
// range (423) is no error. If fn fails, the rest of the response is read
// and dropped so the connection stays usable, and fn's error is returned.
func (c *NNTP) OverFunc(low, high int64, fn func(string) error) error {
	code, msg, err := c.Cmd("OVER %d-%d", low, high)
	if err != nil {
		return err
	}
	switch code {
	case 224:
	case 423:
		return nil
	default:
		return fmt.Errorf("OVER %d-%d: %d %s", low, high, code, msg)
	}
	sc := bufio.NewScanner(c.r.DotReader())
	sc.Buffer(make([]byte, 1<<16), 1<<22)
	var fnErr error
	n, text := 0, int64(0)
	defer func() { TextBytes.Add(text) }()
	for sc.Scan() {
		if n++; n%5000 == 0 {
			c.deadline() // a long response keeps the connection alive
		}
		text += int64(len(sc.Bytes())) + 2
		if fnErr == nil {
			fnErr = fn(sc.Text())
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return fnErr
}

// ActiveGroup is one line of LIST ACTIVE.
type ActiveGroup struct {
	Name      string
	High, Low int64
	Status    string
}

// ListActive returns LIST ACTIVE.
func (c *NNTP) ListActive() ([]ActiveGroup, error) {
	code, msg, err := c.Cmd("LIST ACTIVE")
	if err != nil {
		return nil, err
	}
	if code != 215 {
		return nil, fmt.Errorf("LIST ACTIVE: %d %s", code, msg)
	}
	c.deadline()
	lines, err := c.lines()
	if err != nil {
		return nil, err
	}
	out := make([]ActiveGroup, 0, len(lines))
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		hi, _ := strconv.ParseInt(f[1], 10, 64)
		lo, _ := strconv.ParseInt(f[2], 10, 64)
		out = append(out, ActiveGroup{Name: f[0], High: hi, Low: lo, Status: f[3]})
	}
	return out, nil
}

// Articles fetches whole articles by number, pipelined: batch ARTICLE
// commands go out in one write, then the replies are read in order. A
// missing article (423, 430) is skipped. fn gets the header and body lines.
func (c *NNTP) Articles(nums []int64, batch int, fn func(num int64, head, body []string) error) error {
	return c.articles(len(nums), func(i int) string { return strconv.FormatInt(nums[i], 10) }, batch,
		func(i int, head, body []string) error { return fn(nums[i], head, body) })
}

// ArticlesByID is Articles by Message-ID ("<...>"), so no GROUP is needed;
// fn gets the index into ids.
func (c *NNTP) ArticlesByID(ids []string, batch int, fn func(i int, head, body []string) error) error {
	for _, id := range ids {
		if !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, ">") || strings.ContainsAny(id, " \t\r\n") {
			return fmt.Errorf("not a Message-ID: %q", id)
		}
	}
	return c.articles(len(ids), func(i int) string { return ids[i] }, batch, fn)
}

// articles sends "ARTICLE arg(i)" for i < n, batch at a time, and reads
// the replies in order.
func (c *NNTP) articles(n int, arg func(i int) string, batch int, fn func(i int, head, body []string) error) error {
	batch = max(batch, 1)
	for start := 0; start < n; start += batch {
		end := min(start+batch, n)
		c.deadline()
		for i := start; i < end; i++ {
			fmt.Fprintf(c.w, "ARTICLE %s\r\n", arg(i))
		}
		if err := c.flush(); err != nil {
			return err
		}
		var fnErr error
		for a := start; a < end; a++ {
			c.deadline()
			code, msg, err := c.status()
			if err != nil {
				return err
			}
			switch code {
			case 220:
			case 423, 430:
				continue
			default:
				return fmt.Errorf("ARTICLE %s: %d %s", arg(a), code, msg)
			}
			lines, err := c.lines()
			if err != nil {
				return err
			}
			i := 0
			for i < len(lines) && lines[i] != "" {
				i++
			}
			head := lines[:i]
			var body []string
			if i < len(lines) {
				body = lines[i+1:]
			}
			if fnErr == nil {
				fnErr = fn(a, head, body)
			}
		}
		if fnErr != nil {
			return fnErr
		}
	}
	return nil
}
