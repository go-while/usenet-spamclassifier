package spamfilter

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// The corpus-wide Breidbart index for a scan that keeps no Message-IDs.
//
// Pass 1 (the full scan) appends one record per chunk and item to 256
// partition files: the item's BIKey, the chunk it came from, and the sum
// of sqrt(groups) of its copies in that chunk. AggregateBI then sums each
// partition in memory and keeps the keys at or above the threshold. Pass 2
// rescans and flags every copy of those keys.
//
// The key is the FSL key plus the month the article was posted: copies
// count only within a calendar month, standing in for the 45-day window,
// so a FAQ posted monthly for years does not add up. A chunk scanned twice
// (a run stopped between writing records and saving progress) is counted
// once: records are unique per (key, chunk).

const biRecSize = 16 // key uint64, chunk uint32, sum float32

// BIKey returns the key an article is counted under, and false for
// articles the index leaves out: replies (a prolific poster's replies share
// From, Subject and length) and articles shorter than minLines.
func BIKey(a Article, minLines int) (uint64, bool) {
	if a.Reply || a.Lines < minLines {
		return 0, false
	}
	month := "0"
	if a.Date > 0 {
		month = time.Unix(a.Date, 0).UTC().Format("200601")
	}
	h := fnv.New64a()
	h.Write([]byte(a.Key))
	h.Write([]byte{0})
	h.Write([]byte(month))
	return h.Sum64(), true
}

// ChunkID names a chunk for de-duplication: group and first article number.
func ChunkID(group string, first int64) uint32 {
	h := fnv.New32a()
	h.Write([]byte(group))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(first, 10)))
	return h.Sum32()
}

// BIWriter appends records to the partition files in dir.
type BIWriter struct {
	dir   string
	files [256]*os.File
	bufs  [256]*bufio.Writer
}

func OpenBIWriter(dir string) (*BIWriter, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return &BIWriter{dir: dir}, nil
}

// Add appends one chunk's sums (key -> sum of sqrt(groups)) and flushes,
// so the records are on disk before the chunk's progress is saved.
func (w *BIWriter) Add(chunk uint32, sums map[uint64]float32) error {
	var rec [biRecSize]byte
	for k, s := range sums {
		p := byte(k >> 56)
		if w.bufs[p] == nil {
			f, err := os.OpenFile(filepath.Join(w.dir, fmt.Sprintf("part-%02x.bin", p)), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
			w.files[p], w.bufs[p] = f, bufio.NewWriterSize(f, 64<<10)
		}
		binary.LittleEndian.PutUint64(rec[0:], k)
		binary.LittleEndian.PutUint32(rec[8:], chunk)
		binary.LittleEndian.PutUint32(rec[12:], math.Float32bits(s))
		if _, err := w.bufs[p].Write(rec[:]); err != nil {
			return err
		}
	}
	for _, b := range w.bufs {
		if b != nil {
			if err := b.Flush(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *BIWriter) Close() error {
	var err error
	for i, f := range w.files {
		if f == nil {
			continue
		}
		if e := w.bufs[i].Flush(); err == nil {
			err = e
		}
		if e := f.Close(); err == nil {
			err = e
		}
	}
	return err
}

// BIStats summarises an aggregation.
type BIStats struct {
	Records, Keys, Over int64
	Max                 float32
	// Chunks are the chunks holding copies of the keys at or above the
	// threshold: pass 2 needs to read only these.
	Chunks map[uint32]bool
}

// AggregateBI sums the partitions in dir and returns the keys whose index
// reaches threshold, with their index. One partition is in memory at a time.
func AggregateBI(dir string, threshold float32) (map[uint64]float32, BIStats, error) {
	over := map[uint64]float32{}
	st := BIStats{Chunks: map[uint32]bool{}}
	type rec struct {
		k     uint64
		chunk uint32
		s     float32
	}
	for p := 0; p < 256; p++ {
		b, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("part-%02x.bin", p)))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, st, err
		}
		n := len(b) / biRecSize // a record cut short at the end is ignored
		rs := make([]rec, n)
		for i := range rs {
			r := b[i*biRecSize:]
			rs[i] = rec{binary.LittleEndian.Uint64(r), binary.LittleEndian.Uint32(r[8:]), math.Float32frombits(binary.LittleEndian.Uint32(r[12:]))}
		}
		b = nil
		st.Records += int64(n)
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].k != rs[j].k {
				return rs[i].k < rs[j].k
			}
			return rs[i].chunk < rs[j].chunk
		})
		for i := 0; i < len(rs); {
			k := rs[i].k
			j := i
			var sum float32
			for ; j < len(rs) && rs[j].k == k; j++ {
				if j == i || rs[j].chunk != rs[j-1].chunk {
					sum += rs[j].s
				}
			}
			st.Keys++
			st.Max = max(st.Max, sum)
			if sum >= threshold {
				over[k] = sum
				for ; i < j; i++ {
					st.Chunks[rs[i].chunk] = true
				}
			}
			i = j
		}
	}
	st.Over = int64(len(over))
	return over, st, nil
}

// SaveBIKeys and LoadBIKeys keep the aggregated keys between the two passes.
func SaveBIKeys(path string, keys map[uint64]float32) error {
	f, err := os.Create(path + ".tmp")
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	var rec [12]byte
	for k, s := range keys {
		binary.LittleEndian.PutUint64(rec[0:], k)
		binary.LittleEndian.PutUint32(rec[8:], math.Float32bits(s))
		w.Write(rec[:])
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

func LoadBIKeys(path string) (map[uint64]float32, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	keys := map[uint64]float32{}
	var rec [12]byte
	for {
		if _, err := io.ReadFull(r, rec[:]); err == io.EOF {
			return keys, nil
		} else if err != nil {
			return nil, err
		}
		keys[binary.LittleEndian.Uint64(rec[0:])] = math.Float32frombits(binary.LittleEndian.Uint32(rec[8:]))
	}
}

// SaveBIChunks and LoadBIChunks keep the chunks pass 2 has to read.
func SaveBIChunks(path string, chunks map[uint32]bool) error {
	b := make([]byte, 0, 4*len(chunks))
	for c := range chunks {
		b = binary.LittleEndian.AppendUint32(b, c)
	}
	if err := os.WriteFile(path+".tmp", b, 0644); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func LoadBIChunks(path string) (map[uint32]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	chunks := make(map[uint32]bool, len(b)/4)
	for i := 0; i+4 <= len(b); i += 4 {
		chunks[binary.LittleEndian.Uint32(b[i:])] = true
	}
	return chunks, nil
}

// SumBIKeys fills in the Breidbart index of the keys in want (their values
// are replaced). Records outside want are skipped, so only the wanted
// keys' records are sorted. A key without records keeps 0.
func SumBIKeys(dir string, want map[uint64]float32) (records int64, err error) {
	type rec struct {
		k     uint64
		chunk uint32
		s     float32
	}
	for k := range want {
		want[k] = 0
	}
	for p := 0; p < 256; p++ {
		b, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("part-%02x.bin", p)))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return records, err
		}
		n := len(b) / biRecSize
		records += int64(n)
		var rs []rec
		for i := 0; i < n; i++ {
			r := b[i*biRecSize:]
			k := binary.LittleEndian.Uint64(r)
			if _, ok := want[k]; ok {
				rs = append(rs, rec{k, binary.LittleEndian.Uint32(r[8:]), math.Float32frombits(binary.LittleEndian.Uint32(r[12:]))})
			}
		}
		b = nil
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].k != rs[j].k {
				return rs[i].k < rs[j].k
			}
			return rs[i].chunk < rs[j].chunk
		})
		for i := range rs {
			if i == 0 || rs[i].k != rs[i-1].k || rs[i].chunk != rs[i-1].chunk {
				want[rs[i].k] += rs[i].s
			}
		}
	}
	return records, nil
}
