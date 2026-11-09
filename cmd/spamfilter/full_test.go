package main

import (
	"bufio"
	"compress/flate"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

// fakeServer answers the commands a full scan sends, for groups g0..g(n-1)
// with arts articles each; every 7th article is make-money-fast spam and
// every 5th is crossposted to the next group.
func fakeServer(t *testing.T, n, arts int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	over := func(g, i int) string {
		subj, from := fmt.Sprintf("question %d about gardening", i), fmt.Sprintf("user%d@example.org", i)
		if i%7 == 0 {
			subj, from = "MAKE MONEY FAST $$$ work from home", "winner@cash.example"
		}
		xref := fmt.Sprintf("news g%d:%d", g, i)
		if i%5 == 0 && g+1 < n {
			xref += fmt.Sprintf(" g%d:%d", g+1, i+arts)
		}
		return fmt.Sprintf("%d\t%s\t%s\tMon, 1 Jan 2001 00:00:00 +0000\t<%d.%d@x>\t\t1000\t10\tXref: %s",
			i, subj, from, g, i, xref)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r, w := bufio.NewReader(conn), bufio.NewWriter(conn)
				fmt.Fprint(w, "200 fake\r\n")
				w.Flush()
				flush := w.Flush
				group := -1
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					f := strings.Fields(l)
					switch strings.ToUpper(strings.Join(f[:min(2, len(f))], " ")) {
					case "MODE READER":
						fmt.Fprint(w, "200 ok\r\n")
					case "CAPABILITIES":
						fmt.Fprint(w, "101 caps\r\nVERSION 2\r\nREADER\r\nOVER\r\nCOMPRESS DEFLATE\r\n.\r\n")
					case "COMPRESS DEFLATE":
						fmt.Fprint(w, "206 compressing\r\n")
						w.Flush()
						// from now on both directions are deflated (sync flush
						// per reply; nnrpd's partial flush is covered by
						// nntp-testkit's inflater tests)
						r = bufio.NewReader(flate.NewReader(r))
						zw, _ := flate.NewWriter(conn, flate.BestSpeed)
						w = bufio.NewWriter(zw)
						flush = func() error {
							if err := w.Flush(); err != nil {
								return err
							}
							return zw.Flush()
						}
						continue
					case "LIST OVERVIEW.FMT":
						fmt.Fprint(w, "215 fmt\r\nSubject:\r\nFrom:\r\nDate:\r\nMessage-ID:\r\nReferences:\r\n:bytes\r\n:lines\r\nXref:full\r\n.\r\n")
					case "LIST ACTIVE":
						fmt.Fprint(w, "215 active\r\n")
						for g := 0; g < n; g++ {
							fmt.Fprintf(w, "g%d %d 1 y\r\n", g, arts)
						}
						fmt.Fprint(w, ".\r\n")
					case "QUIT":
						fmt.Fprint(w, "205 bye\r\n")
						flush()
						return
					default:
						switch strings.ToUpper(f[0]) {
						case "GROUP":
							group, _ = strconv.Atoi(strings.TrimPrefix(f[1], "g"))
							fmt.Fprintf(w, "211 %d 1 %d %s\r\n", arts, arts, f[1])
						case "OVER":
							a, b, _ := strings.Cut(f[1], "-")
							lo, _ := strconv.Atoi(a)
							hi, _ := strconv.Atoi(b)
							fmt.Fprint(w, "224 over\r\n")
							for i := lo; i <= min(hi, arts); i++ {
								fmt.Fprint(w, over(group, i)+"\r\n")
							}
							fmt.Fprint(w, ".\r\n")
						case "ARTICLE":
							i, _ := strconv.Atoi(f[1])
							o := strings.Split(over(group, i), "\t")
							fmt.Fprintf(w, "220 %d %s\r\nFrom: %s\r\nSubject: %s\r\nNewsgroups: g%d\r\nMessage-ID: %s\r\nDate: %s\r\n\r\nbody <b>&amp; text\r\n.\r\n",
								i, o[4], o[2], o[1], group, o[4], o[3])
						default:
							fmt.Fprint(w, "500 what\r\n")
						}
					}
					flush()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestFullScanConns(t *testing.T) {
	addr := fakeServer(t, 12, 300)
	dir := t.TempDir()
	// a small model; the subject rules flag the spam anyway
	var ex []sf.Example
	for i := 0; i < 400; i++ {
		a := sf.Article{Subject: fmt.Sprintf("question %d about gardening", i), From: "u@example.org", Newsgroups: "g1", Groups: 1, Lines: 10}
		if i%2 == 0 {
			a.Subject, a.From = "cheap pills online now", "x@spam.example"
		}
		ex = append(ex, sf.Example{A: a, Spam: i%2 == 0})
	}
	m, _, err := sf.Train(ex, 16, 3, 0.9, 0.9, 1)
	if err != nil {
		t.Fatal(err)
	}
	modelPath := filepath.Join(dir, "m.model")
	if err := m.Save(modelPath); err != nil {
		t.Fatal(err)
	}
	counts := map[int]int{}
	for _, conns := range []int{1, 3, -1} { // -1: one connection, no compression
		db := filepath.Join(dir, fmt.Sprintf("c%d.db", conns))
		err := run([]string{"-server", addr, "-db", db, "-mode", "full", "-llm=false", "-model-file", modelPath,
			"-chunk", "70", "-conns", strconv.Itoa(max(conns, 1)), "-compress=" + strconv.FormatBool(conns > 0),
			"-groups", "*", "-nocem-types", ""})
		if err != nil {
			t.Fatalf("conns %d: %v", conns, err)
		}
		st, err := sf.OpenStore(db)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, spam, err := st.Counts()
		st.Close()
		if err != nil {
			t.Fatal(err)
		}
		counts[conns] = int(spam)
	}
	// 12 groups x 42 spam (every 7th of 300), each flagged once in its home group
	if counts[1] != 12*42 || counts[3] != counts[1] || counts[-1] != counts[1] {
		t.Fatalf("spam flagged: 1 connection %d, 3 connections %d, uncompressed %d, want %d", counts[1], counts[3], counts[-1], 12*42)
	}
}
