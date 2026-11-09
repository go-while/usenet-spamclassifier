# usenet-spamclassifier

`spamfilter` labels Usenet articles as spam, ham or unsure with Claude, cheap
rules and a small local model. Its outputs are:

- an INN history file of spam Message-IDs: a fresh INN loaded with it refuses
  those articles as duplicates;
- JSONL verdicts with cleanfeed-ng rule names and `CF-*` codes, for analysis
  and for deriving cleanfeed-ng `bad_*` lists.

The full archive (archive.usenet.blueworldhosting.com) holds about 1.5
billion article numbers in 54,634 groups. Labelling all of that through the
API would cost thousands of dollars, so the API labels a sample, a local
model learns from it, and only articles the local model is unsure about go
back to the API, under a budget cap.

## Data

The results of the run on archive.usenet.blueworldhosting.com (2026-11-09)
are public under CC0: the current list (35.8M Message-IDs) and a core list
(27.5M, flagged by the last three passes), each also as an INN history
file, the lists of all six passes, the 14.8M labels, the spot checks, the
NoCeM listings, the local models and the whole SQLite database, as 7z
files (about 12 GB). README.txt there describes every file.

- https://archive.org/details/usenet-spamclassifier-bwh-2026-11-09
  (archive.org also offers it as a torrent)
- mirror: https://mbox-mo1.pugleaf.net/usenet-spamclassifier-data/

## Build

```
go build -o spamfilter ./cmd/spamfilter
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o spamfilter-linux-amd64 ./cmd/spamfilter
```

Go 1.27.3 or later. Dependencies: the Anthropic Go SDK, `modernc.org/sqlite`
(pure Go, no C compiler), `golang.org/x/text` (charsets),
`go-lib-mbox2nntp` (mbox parser) and `nntp-testkit` (NNTP client with
COMPRESS DEFLATE).

## The automated run (news server)

```
spamfilter run -mode sample -server HOST:119 -db spamfilter.db -budget 8
spamfilter train -db spamfilter.db -o spamfilter.model
spamfilter run -mode full -server HOST:119 -db spamfilter.db -model-file spamfilter.model -budget 20
spamfilter history -db spamfilter.db -o spam.history
spamfilter status -db spamfilter.db
```

1. **sample**: LIST ACTIVE, then for each group in random order one OVER of a
   random window (1/5000 of the group, 20 to 5000 articles). New items go to
   the model in batches of 50; verdicts land in the `verdicts` table. Stops at
   `-sample-target` items or the budget. Run it again to continue.
2. **train**: logistic regression over hashed features (subject words and
   character n-grams, From address and name, groups and hierarchies,
   crosspost count, lines, reply). A tenth is held out to set the thresholds
   at which the spam and ham labels reach 98% precision; between them an
   article is "uncertain".
3. **full**: every selected group from where it stopped, OVER in chunks of
   200,000; `-conns N` scans N groups at once on separate connections (also
   in `-mode bi`). Each article is judged once, in the first selected group of its
   Xref, so crossposts count once without remembering every Message-ID.
   Subject rules first, then the local model (parsing and scoring run on all
   cores, about 23k lines/s per core; the whole bwh archive, 1.47 billion
   overview lines, took 2h53m with 4 connections at 500 Mbit/s); uncertain articles go to the API while
   the budget lasts. Spam Message-IDs go to the `spam` table.
   Interrupt it (Ctrl-C or SIGTERM) and run it again to continue.
   It also writes Breidbart counts (From+Subject+lines and month, per chunk)
   to `spamfilter.db.bi/`. Then `spamfilter bi` sums them and lists the keys
   at an index of 20 or more and the chunks holding their copies, and
   `run -mode bi` reads those chunks again and flags every copy (same
   `-chunk` as the full scan; `-bi-all` reads everything).
4. **history**: one INN hisv6 line per spam Message-ID that only remembers it
   (no stored article): `[MD5]\tarrived~-~posted`, the hash computed like
   INN's `HashMessageID` (domain part lower-cased). On the new server, add
   the lines to `history`, rebuild the index with `makedbz -i`, and raise
   `/remember/` in `expire.ctl` (default 11 days counted from `arrived`), or
   expire drops them again. A transfer of the whole archive takes longer
   than 11 days: set `/remember/` longer than the transfer, or write the file
   right before it is loaded (`-arrived` defaults to now), or don't run
   expire until the transfer is done.

Options worth knowing:

| option | default | |
|---|---|---|
| `-groups` | `*,!control,!control.*,!junk,!to.*` | wildmat list, last match wins |
| `-budget` | 5 | dollars at list price, all runs in this database together |
| `-model` | `claude-haiku-5-5` | first pass |
| `-thinking` | false | let the first pass think; no accuracy gain measured, roughly 40% more cost |
| `-escalate` | `claude-sonnet-5-5` | for the labels in `-escalate-on`; `-escalate=` turns it off |
| `-escalate-on` | `unsure` | e.g. `unsure,spam` to have the stronger model re-check positives |
| `-key-file` | `/dev/shm/spamfilter_apikey.txt` | API key; else `ANTHROPIC_API_KEY` |
| `-conns` | 1 | groups scanned at once, one connection each (full and bi mode) |
| `-max-mbit` | 0 | cap on the download, all connections together (0 = none) |

Every server connection uses COMPRESS DEFLATE (RFC 8054) when the server
offers it (`-compress=false` turns it off). The inflater is
[nntp-testkit](https://github.com/go-while/nntp-testkit)'s client: Go's `compress/flate` reader holds back what nnrpd
sends after a `Z_PARTIAL_FLUSH` until more data comes, so every second reply
stalled. On bwh (`spamfilter nntp-bench`, 300k overview lines of
alt.atheism): 202 MB of text become 46 MB on the wire (4.4x). One
connection then reads about 25k lines/s instead of 35k: the server's zlib
is the limit (the client inflates with a quarter of a core), so more
connections scale, at about 31 Mbit/s each.

## Files instead of a server

For mbox files (plain, `.gz`, `.zip`; mboxrd-quoted exports of mbox2nntp's
tools are unquoted) and overview lines fetched to disk:

```
spamfilter over   -state DIR -server HOST:119 GROUP...   # raw OVER lines, resumable
spamfilter scan   -state DIR [MBOX|DIR...]               # merge both sources
spamfilter rules  -state DIR                             # Breidbart index + subject rules
spamfilter llm    -state DIR -limit 1000 [-yes]          # without -yes: free token count and cost estimate
spamfilter export -state DIR -o verdicts.jsonl
spamfilter stats  -state DIR
```

Both sources compute the same key per article (FSL: raw From, raw Subject,
body line count as INN counts it), so a Message-ID in both gets one verdict.
mbox articles also have a body hash; copies cluster by either key for the
Breidbart index (45-day window, spam at 20; replies don't count by FSL key).

## Labelling what the scan left open

The full scan leaves about 11% of the articles uncertain (164M on bwh) and
does not remember them. To label them with the article bodies:

```
spamfilter run -mode unsure -server HOST:119 -db spamfilter.db -share 0.1 -chunk 20000 -conns 4 -max-mbit 500
spamfilter label-unsure -db spamfilter.db -dry                     # selection and cost, no API calls
spamfilter label-unsure -db spamfilter.db -server HOST:119 -budget 150 -stop-after 500000
spamfilter train -db spamfilter.db -o spamfilter.model
spamfilter rescore -db spamfilter.db -model-file spamfilter.model
spamfilter audit -db spamfilter.db -server HOST:119                # spot checks; -report prints them again
spamfilter label-flagged -db spamfilter.db -server HOST:119 -class bi
spamfilter compare -before spamfilter-before.db -after spamfilter.db
```

1. **run -mode unsure** reads a tenth of the chunks (picked by hash, the
   same on every run, so it continues where it stopped) with the full
   scan's judgement, sends nothing to the API and writes no spam rows. It
   keeps every uncertain article's overview headers and model logit, and
   one in `-ham-every` (10,000) of the ham, in
   `spamfilter.db.unsure/part-*.jsonl.gz` (one file per run).
2. **label-unsure** takes one candidate per From+Subject+lines key, skips
   keys labelled before and looks up each key's Breidbart index in the full
   scan's counts. Tier 1: keys copied with an index from `-min-bi` (3) up to
   20, most copies first, until `-copies-usd` (40) is spent in this run.
   Tier 2: the rest in a weighted random order where a hierarchy's share
   grows with the square root of its size, so small hierarchies get more
   than their share. It fetches each article (ARTICLE, `-max-mbit` 100),
   adds the start of the body to the overview headers, and Haiku labels it
   (no escalation by default). Verdicts go to the `verdicts` table under the
   overview key, so the next scan and `train` use them. Stops after
   `-stop-after` labels; after Ctrl-C, run it again with `-copies-usd 0`
   once tier 1 is done.
   `-batch-api` sends through the Message Batches API instead: half the
   price, results within 24 hours, its own rate limit. It fetches
   `-batch-articles` (100k) at a time on `-fetch-conns` connections, keeps
   up to `-in-flight` batches waiting, and keeps each submitted batch in
   `spamfilter.db.batches/` until its results are stored, so a restart
   collects them instead of losing what was paid for. `-model-file` limits
   the candidates to those that model cannot decide (6.1M of 15.3M keys for
   the 2026-11-03 model, about $89 with the batch API).
   The organisation's Haiku limit is 2M input tokens a minute: run one
   Messages API labelling job at a time (the labeller waits out a 429).
3. **rescore** shows how a newly trained model decides the candidates,
   without downloading anything: how many of the uncertain are now decided,
   and how many of the ham sample stay ham.
4. **label-flagged** `-class bi` labels one copy of each Breidbart-flagged
   key that has no label yet (most copies first), so the next scan can tell
   repeated spam from repeated ordinary postings.
5. **audit** samples flagged rows from the `spam` table, an even share per
   source (model, nocem, bi, subj, llm), or `-group NAME`, plus `-clean-n`
   of the ham sample. Haiku labels them with the body; Sonnet re-checks
   those where Haiku disagrees with the scan. Results go to the `audit`
   table and print as agreement per source and hierarchy. `train` and the
   full scan leave the spot-checked keys out (`-hold-out-audit`), so they
   stay a fair test.
6. **compare** `-before OLD.db -after NEW.db` counts both scans' flags and
   looks the spot-checked articles up in the new scan: how much of the
   spam stays flagged and how much of the ham is no longer flagged.

### How the full scan judges (since 2026-11-03)

1. A label of the model API for the key (spam or ham; it saw more than the
   headers) decides first.
2. NoCeM listings of the spam types, without the issuers in `-nocem-skip`
   (`DefaultNocemSkip`: UltraHippo, robot@pasdenom.info,
   nocem-fr@alphanet.ch; most of what they list is ordinary postings).
3. The subject rules.
4. The local model; with `-use-bi` (and `-bi=false`, reusing the counts of
   the first scan) a copy of a key at a Breidbart index of 20 or more is
   spam unless the model calls it ham: jobs, tests, weather reports and
   feeds repeat without being spam.

Spot checks of the scan before this change (20,000 flagged, 3,000 clean;
Haiku with the body, Sonnet re-checking disagreements):

| flagged by | spam | ham |
|---|---|---|
| model API labels | 95.8% | 4.0% |
| subject rules | 90.3% | 9.1% |
| local model | 71.8% | 27.6% |
| NoCeM | 64.8% | 34.3% |
| Breidbart copies | 54.5% | 43.0% |
| (clean) | 1.0% | 98.3% |

Before and after (`compare`, 2026-11-03; the after scan with the new
order, the skipped issuers, Breidbart copies checked against the labels
and the model, a model trained on 1.27M labels; 101.7 GB down, 2h38m):

| flagged | before | after |
|---|---|---|
| local model | 33.5M | 24.9M |
| NoCeM | 9.6M | 5.3M |
| Breidbart copies | 6.3M | 3.2M |
| subject rules | 2.5M | 2.5M |
| model API labels | 0.6M | 7.2M |
| total | 52.5M | 43.2M |

By the spot checks, about 15.5M (29.5%) of the 52.5M before were ham. The
after scan keeps about 30.3M of them, about 3.1M (10.3%) ham, and flags
13.0M that before had not (mostly keys labelled spam by the API). Spam
kept per source: model 65%, NoCeM 91%, Breidbart 81%, subject rules 100%
(their 9% ham is unchanged). Of 2,949 clean ham, 6 are flagged after.

Second round (2026-11-04): 6.1M more labels through the Message Batches
API ($76.79) for the keys the new model could not decide, a model trained
on 7.4M labels (spam recall 52.7% at 97.8% precision on the random
sample), and the subject rules without "$$$" and bare "MMF" and not in the
anti-spam groups. Undecided articles fell from 174.7M to 97.2M. A spot
check of this scan's own flags (2,000 per source, `audit -tag after2`):

| flagged by | before: spam | after: spam | after: ham |
|---|---|---|---|
| local model | 71.8% | 84.0% | 11.6% |
| NoCeM | 64.8% | 88.9% | 10.8% |
| Breidbart copies | 54.5% | 81.9% | 16.3% |
| subject rules | 90.3% | 98.3% | 1.6% |
| model API labels | 95.8% | 83.5% | 16.1% |

Weighted by the flag counts: before 52.5M flags, about 37.0M spam and
15.5M ham; after 45.1M flags, about 38.3M spam and 5.6M ham.

Third round (2026-11-04): a second unsure pass with `-salt 1` (other
groups than the first), 5.7M more batch labels (about $70), the
i2pn2 NoCeM issuer skipped (83 of 305 checked were ham), and a model
with `-bits 24` trained on 12.0M labels (spam recall 57.3% at 97.9%
precision, 11.4% of the random sample undecided; `-bits 22` gave 52.6%).
Undecided articles fell to 69.8M. Spot check (`audit -tag after3`):

| flagged by | flags | before: spam | after2: spam | after3: spam | after3: ham |
|---|---|---|---|---|---|
| local model | 25.6M | 71.8% | 84.0% | 87.8% | 10.1% |
| NoCeM | 4.5M | 64.8% | 88.9% | 94.2% | 5.6% |
| Breidbart copies | 3.5M | 54.5% | 81.9% | 85.4% | 13.1% |
| subject rules | 1.9M | 90.3% | 98.3% | 98.7% | 1.4% |
| model API labels | 12.7M | 95.8% | 83.5% | 78.2% | 21.2% |

Weighted: after3 48.1M flags, about 41.5M spam and 6.0M ham. The API
labels are the weak spot: the audit disagrees with about a fifth of the
batch labels, which came from the hardest (undecided) keys.

Fourth round (2026-11-08): the wrong API labels were mostly offers in
groups made for them (job-board ads in *.jobs.offered, classifieds in
*.ogloszenia, relcom.commerce.*) and spam reports in the anti-spam groups.
Decision: an offer that fits its group is ham; it is spam only when also
posted where it does not fit. The prompt says so now. `recheck` labels the
spot-checked articles again without storing anything and compares, which
made trying settings cheap (2,000 articles, offer groups, agreement with
Sonnet given the same prompt):

| first pass | agrees with Sonnet | of its spam, Sonnet says ham | $ per 2,000 |
|---|---|---|---|
| Haiku, no thinking | 71.9% | 59% | 0.06 |
| Haiku, thinking, effort low | 78.1% | 51% | 0.07 |
| Haiku, thinking, effort medium | 89.1% | 16% | 0.10 |
| Haiku, thinking, effort high | 90.4% | 11% | 0.13 |
| Sonnet | (reference) | | 1.26 |

10 instead of 50 articles per request made no difference. So `relabel
-thinking -effort high` sent the stored API spam labels in offer and
anti-spam groups through the batch API again ($0.0364 per 1,000), then the
candidates still undecided, then the other API spam labels as far as the
money went.

```sh
spamfilter recheck -db spamfilter.db -server HOST:119 -kind flagged-after3 -stage llm -thinking -effort high -out x.tsv
spamfilter relabel -db spamfilter.db -server HOST:119 -thinking -effort high -offers -before 2026-11-08T07:48:47Z -budget 380
spamfilter label-unsure ... -batch-api -thinking -effort high -model-file spamfilter-after3-b24.model
```

Relabel stores new times, and `train` took the labels stored before
`-picked-since` (2026-11-03) as the random sample for thresholds and the
test. After the relabel the sample's spam labels counted as picked: the
first after4 model saw 19 spam in its test set and flagged nothing.
`train -sample-db spamfilter-after3-2026-11-08.db` takes the sample's keys
from a snapshot made before the relabel, and `train` now refuses to write a
model with fewer than 200 spam in the test set.

Results (2026-11-09; model on 13.8M examples, spam recall 40.3% at 98.2%
precision, 9.2% of the random sample undecided; the chmurka.net From
blacklist and e-book subject rule added as `from:known` and `subj:ebook`;
spot check `audit -tag after4b`, 2,000 per source):

| flagged by | flags | after3: spam | after4: spam | after4: ham |
|---|---|---|---|---|
| local model | 12.9M | 87.8% | 95.2% | 1.9% |
| NoCeM | 4.5M | 94.2% | 93.8% | 6.0% |
| Breidbart copies | 2.4M | 85.4% | 95.8% | 3.9% |
| subject rules, From | 2.0M | 98.7% | 98.7% | 1.3% |
| model API labels | 7.4M | 78.2% | 92.9% | 6.6% |

Weighted: 29.2M flags, about 27.6M spam and 1.1M ham (after3: 48.1M,
41.5M and 6.0M); 23.6M undecided (after3: 69.8M). `from:known` flagged
74k (67 of 70 checked spam), `subj:ebook` 6.9k (6 of 6). The stricter
labels cost recall: the model flags half as much at 98% precision.
Outside the offer groups thinking Haiku still calls 92.8% of Sonnet's
spam spam, so the loss comes from the threshold, not from the relabel
letting spam through. API spend $378.00. The scan read 605.8 GB of
overview text as 101.7 GB on the wire (5.96x), 2h25m.

Round 4d wins recall back without the API. `train -ham-precision` sets the
ham threshold apart from `-precision`, so a looser spam threshold keeps an
undecided band (copy counts only flag what the model doesn't call ham):

| -precision / -ham-precision | spam threshold | test recall | test precision | undecided |
|---|---|---|---|---|
| 0.98 / 0.98 (after4) | 6.58 | 40.3% | 98.2% | 9.2% |
| 0.97 / 0.98 (after4d) | 4.18 | 66.0% | 96.5% | 5.2% |
| 0.95 / 0.98 | 3.10 | 74.8% | 94.3% | 3.5% |
| 0.95 / 0.95 | 3.10 | 74.8% | 94.3% | 0.0% |
| 0.90 / 0.90 | 1.53 | 85.3% | 89.5% | 0.0% |

On the test labels the 98→97 band is about 94% spam, 97→95 about 80%,
95→90 about 66%. `rescore` on the 15.3M candidate keys: spam 2.8% (after4),
5.3% (97/98), 7.1% (95/98), 10.0% (90/90).

```sh
spamfilter train -db spamfilter.db -sample-db spamfilter-after3-2026-11-08.db -o spamfilter-after4-s97.model -bits 24 -curve=false -precision 0.97 -ham-precision 0.98
```

after4d scan (snapshot of after4: spamfilter-after4-2026-11-09.db): 35.8M
flags (model 19.5M, NoCeM 4.5M, copies 2.5M, subject/From 2.0M, API
labels 7.3M), 17.8M undecided, 2h35m. Against the first pass's spot checks
the first-pass flags still flagged rose from 21.2M (0.5M ham) to 24.3M
(0.7M ham); none of the 2,949 clean-sample ham became flagged. Not
spot-checked yet (API budget at $378 of $380); estimated about 33.7M spam
and 1.6M ham.

## Web view

```
spamfilter serve -db spamfilter.db -server HOST:119      # listens on 127.0.0.1:8099
ssh -L 8099:127.0.0.1:8099 root@mbox-mo1.pugleaf.net    # then open http://localhost:8099/
# on mo1 it runs as unit spamfilter-web behind nginx: https://mbox-mo1.pugleaf.net:8182/
```

Read-only. The overview counts flagged Message-IDs by stage and reason and
lists hierarchies and groups by spam share. A group page reads 100-1000
articles live from the news server and shows, for each, whether it is in
the filter and why (stored row, rule, model probability, Breidbart index,
NoCeM entry), or clean / unsure. Click an article for its full text,
look up any Message-ID, browse the labelled training items and the NoCeM
types and issuers.

## NoCeM notices

`spamfilter nocem -server HOST:PORT` reads the notices in news.lists.filters
and alt.nocem.misc into the database: Message-ID, type, issuer and, where the
issuer gives them (bleachbot), sender and subject. From bwh on 2026-11-02:
1.9M + 132k notices, 60.8M Message-IDs, 67 minutes, 8.9 GB of database.

- The full scan flags NoCeM-listed articles of the spam types
  (`DefaultNocemTypes`: spam, spam2-4, general-spam, aioe-spam, mmf, spew,
  flood, thai, emp, cleanfeed-emp, hipcrime) and keeps one posting in 200 as a
  training example (`-nocem-keep`).
- `history` writes every NoCeM spam Message-ID, also those the scan never saw.
- `train` learns from up to 150k NoCeM entries with a subject (one per
  From+Subject, `-nocem-max`), only to learn from: thresholds and the test
  come from the model labels. One From+Subject key in ten is held out for
  `nocem-eval`.

Held-out NoCeM postings the model recognises (spam / uncertain / ham), and
spam recall on the model-labelled test set at 98% precision:

| training             | NoCeM spam          | test recall |
|----------------------|---------------------|-------------|
| 328k labels          | 41.7 / 42.8 / 15.5% | 49.2%       |
| + 50k NoCeM          | 78.6 / 18.6 / 2.8%  | 50.4%       |
| + 150k NoCeM         | 85.3 / 13.2 / 1.5%  | 49.9%       |
| + 500k NoCeM         | 92.2 / 7.6 / 0.2%   | 43.2%       |

## The model's answer format

Each request holds up to 50 numbered articles; the model answers one line per
article: the number and one letter (`17m`). The letter gives label and
reason (spam: m c x r b s p a k j o; ham: d q w f h t e i n l z g; unsure: u
v y; see `codes` in `spamfilter/llm.go`). The fixed instructions are cached.

## Measured (347 items with body snippets, same batches)

| | cost per 1000 items | agreement with Opus 5.5 |
|---|---|---|
| Opus 5.5, words | $1.28 | (Opus vs its own rerun: 341/347) |
| Haiku 5.5, words | $0.032 | 328/347 |
| Haiku 5.5, letters, no thinking | $0.029 | 321 to 323/347 |

Headers-only items (overview) cost about half as much in input.

## Verdict codes for cleanfeed-ng

| stage / reason | rule | code |
|---|---|---|
| rules `bi=N` | `emp.md5` | `CF-EMP-MD5` |
| rules `subj:*` | `header.subject` | `CF-BAD-SUBJECT` |
| llm | `llm.<label>` | `CF-LLM.<LABEL>` |
| local model | `model.spam` | `CF-MODEL.SPAM` |
