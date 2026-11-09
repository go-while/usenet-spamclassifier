package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	sf "github.com/go-while/usenet-spamclassifier/spamfilter"
)

// ---- run -mode unsure: find the articles the local model can't decide

// unsurePicked reports whether the unsure pass reads a chunk: a hash of
// the chunk, so a stopped run picks the same chunks again.
func unsurePicked(group string, a0 int64, share float64, salt uint64) bool {
	if share >= 1 {
		return true
	}
	h := (uint64(sf.ChunkID(group, a0))+salt*0x632be59bd9b4e019)*0x9e3779b97f4a7c15 + 0x5bd1e995
	h ^= h >> 29
	return float64(h%1000000) < share*1e6
}

// unsurePass reads -share of the chunks (-chunk articles each) with the
// full scan's judgement, but sends nothing to the API and writes nothing
// to the spam table: it keeps the uncertain items, and a sample of the
// ham, in the candidate files for label-unsure and audit.
func (r *runner) unsurePass(ctx context.Context, groups []sf.ActiveGroup) error {
	pass := "unsure"
	if r.o.salt != 0 {
		pass = fmt.Sprintf("unsure-%d", r.o.salt)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	start := time.Now()
	var tot struct{ chunks, skipped, lines, home, unsure, clean int64 }
	defer func() {
		log.Printf("unsure: read %d chunks, skipped %d; %d lines, %d home, %d uncertain kept, %d ham kept; %s",
			tot.chunks, tot.skipped, tot.lines, tot.home, tot.unsure, tot.clean, time.Since(start).Round(time.Second))
	}()
	return r.eachGroup(ctx, groups, func(ctx context.Context, c *sf.NNTP, ag sf.ActiveGroup) error {
		done, err := r.st.PassDone(pass, ag.Name)
		if err != nil {
			return err
		}
		if done >= ag.High {
			return nil
		}
		// most groups are one chunk: skip them without a GROUP command
		// when LIST ACTIVE's range says none of their chunks is picked
		picked := false
		for a0 := max(ag.Low, done+1); a0 <= ag.High && !picked; a0 += r.o.chunk {
			picked = unsurePicked(ag.Name, a0, r.o.share, r.o.salt)
		}
		if !picked {
			r.mu.Lock()
			tot.skipped++
			err := r.st.SetPassDone(pass, ag.Name, ag.High)
			r.mu.Unlock()
			return err
		}
		_, low, high, err := c.Group(ag.Name)
		if err != nil {
			log.Printf("unsure: %v", err)
			return nil
		}
		for a0 := max(low, done+1); a0 <= high; a0 += r.o.chunk {
			b := min(a0+r.o.chunk-1, high)
			if !unsurePicked(ag.Name, a0, r.o.share, r.o.salt) {
				r.mu.Lock()
				tot.skipped++
				err := r.st.SetPassDone(pass, ag.Name, b)
				r.mu.Unlock()
				if err != nil {
					return err
				}
				continue
			}
			res, err := r.scoreChunk(c, ag.Name, a0, b)
			if err != nil {
				return fmt.Errorf("%s %d-%d: %w", ag.Name, a0, b, err)
			}
			r.mu.Lock()
			err = r.cw.Write(res.cands)
			if err == nil {
				err = r.st.SetPassDone(pass, ag.Name, b)
			}
			if err == nil {
				var nu, nc int64
				for _, x := range res.cands {
					if x.Kind == sf.CandUnsure {
						nu++
					} else {
						nc++
					}
				}
				tot.chunks++
				tot.lines += res.lines
				tot.home += res.home
				tot.unsure += nu
				tot.clean += nc
				log.Printf("unsure: %s %d-%d: %d lines, %d home, %d uncertain; total %d chunks, %d lines, %d uncertain, %d ham kept, %s",
					ag.Name, a0, b, res.lines, res.home, nu, tot.chunks, tot.lines, tot.unsure, tot.clean, time.Since(start).Round(time.Second))
			}
			r.mu.Unlock()
			if err != nil {
				return err
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		return nil
	})
}
