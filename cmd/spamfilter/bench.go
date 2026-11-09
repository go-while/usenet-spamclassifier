package main

import (
	"errors"
	"flag"
	"log"
	"time"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

// nntpBench OVERs a range of one group and reports the lines, the bytes
// on the wire and the time: to compare COMPRESS DEFLATE with plain.
func nntpBench(args []string) error {
	fs := flag.NewFlagSet("nntp-bench", flag.ExitOnError)
	server := fs.String("server", "", "news server, HOST:PORT")
	group := fs.String("group", "alt.atheism", "group to read")
	n := fs.Int64("n", 200000, "articles to OVER (from the start of the group)")
	chunk := fs.Int64("chunk", 20000, "articles per OVER command")
	compress := fs.Bool("compress", true, "COMPRESS DEFLATE when the server offers it")
	timeout := fs.Duration("timeout", time.Minute, "network timeout")
	fs.Parse(args)
	if *server == "" {
		return errors.New("need -server HOST:PORT")
	}
	c, err := sf.DialNNTP(*server, *timeout)
	if err != nil {
		return err
	}
	defer c.Quit()
	c.ModeReader()
	if err := compressOn(c, *compress); err != nil {
		return err
	}
	_, low, high, err := c.Group(*group)
	if err != nil {
		return err
	}
	w0, t0 := sf.WireBytes.Load(), time.Now()
	var lines, text int64
	for a := low; a <= min(high, low+*n-1); a += *chunk {
		err := c.OverFunc(a, min(a+*chunk-1, high, low+*n-1), func(l string) error {
			lines++
			text += int64(len(l)) + 2
			return nil
		})
		if err != nil {
			return err
		}
	}
	el := time.Since(t0).Seconds()
	wire := sf.WireBytes.Load() - w0
	log.Printf("nntp-bench: %s, compress %v: %d lines, %.1f MB of text, %.1f MB on the wire (%.1fx), %.1fs, %.0f lines/s, %.1f MB/s of text",
		*group, c.Compressed(), lines, float64(text)/1e6, float64(wire)/1e6, float64(text)/float64(max(wire, 1)), el,
		float64(lines)/el, float64(text)/1e6/el)
	return nil
}
