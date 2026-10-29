# pcapwatch

Network traffic analyzer that reads `.pcap` files and hunts for attacker
behavior on the wire. Counterpart to [logwatch](https://github.com/Hriitiik/logwatch),
which does the same for logs. Findings are tagged with MITRE ATT&CK IDs.

## What it detects

| Detector              | ATT&CK    | How it works                                                                    |
| --------------------- | --------- | ------------------------------------------------------------------------------- |
| Port scan             | T1046     | One source hits 15+ distinct ports on one host within 10s                       |
| DNS tunneling         | T1071.004 | 20+ unique, long (avg 20+ chars) subdomains under one parent domain             |
| DGA                   | T1071.004 | 10+ distinct long, high-entropy (3.3+ bits/char) domains from one host          |
| C2 beaconing          | T1071     | 8+ connections to one destination with jitter (std/mean of gaps) of 0.2 or less |
| Cleartext credentials | T1040     | HTTP Basic auth and FTP `USER`/`PASS` in the clear                              |
| Suspicious downloads  | T1105     | PE/ELF/script bodies over HTTP, identified by magic bytes, with SHA-256         |

All thresholds are constants at the top of each detector file.

## Install

```bash
git clone <repo-url> && cd pcapwatch
python -m venv .venv && source .venv/bin/activate
pip install scapy tldextract pytest
```

## Usage

```bash
python -m pcapwatch capture.pcap
python -m pcapwatch capture.pcap --json reports/out.json --html reports/out.html
```

Example console output:

```
pcapwatch: samples/2015-12-09-traffic-from-Blackhole-EK-activity.pcap
Packets: 3190   Flows: 35   Findings: 1

  [T1105] 2015-12-09 18:55:12 UTC  192.168.122.123 downloaded PE executable from tehnoartspictures.film/... (595456 bytes, sha256 98d9927e70173a03...) (disguised extension)
```

The HTML report is a timeline table with ATT&CK links and collapsible
evidence per finding.

## How it works

1. **Parse:** packets are grouped into flows (5-tuple, both directions merged
   under the initiator). DNS queries, auth headers, and HTTP responses are
   extracted from payloads. HTTP bodies are rebuilt by reassembling TCP
   streams (out-of-order, retransmits, chunked encoding).
2. **Detect:** each detector takes the extracted data and returns `Finding`
   objects.
3. **Report:** findings are sorted by time and written as console, JSON, and
   HTML output.

Design choices:

- Downloads are identified by magic bytes, not file extension, so an
  executable served as `.php` or `.jpg` is still caught (and flagged as disguised).
- Passwords are never stored. Only the username and password length are kept.
- HTML output escapes all fields, because captured data is attacker-controlled.
- Captured files are never written to disk, only hashed.

## Tests

```bash
pytest
```

33 tests, using synthetic PCAPs built with scapy. Detector tests use hand-built
objects, so they need no capture files.

## Validation on real malware traffic

Run blind on two public captures from
[malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2015/index.html),
then compared with the published analyses. No thresholds were tuned to fit them.

### 2015-12-09: Blackhole exploit kit

3190 packets, 35 flows, 1 finding.

| Activity                                    | pcapwatch             | Notes                                                                                                                                                                   |
| ------------------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Malware payload from tehnoartspictures.film | **Detected (T1105)**  | PE file, 595,456 bytes, served from a `.php` URL, flagged as disguised                                                                                                  |
| SHA-256 `98d9927e...ddd9`                   | **Matches** the diary | The diary's VirusTotal link for the payload points to the same SHA-256, and the size (595,456 bytes) matches too. Shows stream reassembly is byte-exact on real traffic |
| Landing page, Java and PDF exploits         | Not detected          | Out of scope by design (exploit delivery)                                                                                                                               |
| Post-infection traffic to 185.62.189.23     | Not detected          | 30 connections in ~60s (mean gap 2.0s), but bursty rather than periodic: jitter 1.71 vs. threshold 0.2. The beaconing rule correctly did not fire                       |
| False positives                             | 0                     |                                                                                                                                                                         |

### 2015-12-18: Rig exploit kit

1201 packets, 27 flows, 1 finding.

| Activity                                                       | pcapwatch            | Notes                                                                                                                                                                                                |
| -------------------------------------------------------------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cleartext FTP login from the infected host to 69.195.124.60:21 | **Detected (T1040)** | Confirmed against the raw traffic with tshark                                                                                                                                                        |
| Exploit kit payload                                            | Not detected         | Reassembled correctly (275,456 bytes, Content-Type `application/x-msdownload`) but the body does not start with `MZ`, consistent with an obfuscated payload. Magic-byte detection cannot identify it |
| C2 requests to a random-looking domain                         | Not detected         | 3 requests, below the DGA (10 domains) and beaconing (8 connections) minimums                                                                                                                        |
| False positives                                                | 0                    |                                                                                                                                                                                                      |

## Limitations

- **HTTP only for payloads.** TLS traffic is invisible without keys.
- **Obfuscated or compressed bodies** (gzip, encrypted payloads) don't match magic bytes.
- **Beaconing assumes a new connection per check-in.** One long-lived connection
  is a single flow, and bursty (non-periodic) C2 is not flagged.
- **No exploit-delivery detection** (Java/PDF/Flash).
- **Telnet credentials** are not detected (login is sent one character per packet).
- **Request/response pairing is positional** (i-th GET with i-th response).
- **Performance:** whole files are loaded into memory, and the capture is read
  several times. Keep test captures under about 50 MB.
- Known false-positive sources: periodic legitimate polling (NTP and mDNS are
  allowlisted; update checks are not) and CDNs with hashed subdomains.
- **Gzip-encoded bodies** (seen on the HTML/JS responses in the Rig capture) are not decompressed.
- **Unpaired responses:** some responses had no matching GET (e.g. replies to POSTs) and show as `(unknown)` URLs.

## Roadmap

- Single streaming pass over large captures
- Telnet reassembly
- Burst-activity rule for newly contacted hosts
- Flag responses whose Content-Type claims an executable but whose bytes are not (seen in the Rig capture)
- Decompress gzip bodies before magic-byte checks

## License

MIT
