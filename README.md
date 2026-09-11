# CIDR / IP Range Expander

**Project 02** of a pentest/red-team learning portfolio — see the [full roadmap](../ROADMAP.md).

Turns a CIDR block (`192.168.1.0/24`), an explicit range
(`192.168.1.10-192.168.1.20`), or a single IP into a flat list of
individual addresses, using Python's built-in `ipaddress` module. Project
01's port pinger only checks *one* host — this is the piece that lets a
future scanner sweep an entire subnet instead.

> ⚠️ Same rule as every project here: only ever run this against ranges
> you own or are explicitly authorized to test.

## Concepts you need before reading the code

**CIDR notation.** `192.168.1.0/24` means: the first 24 bits are the
*network* portion, the remaining 8 bits are free to vary — giving you
2⁸ = 256 possible addresses (`.0` through `.255`). The `/24` is called the
**prefix length**, and it's just a compact way of writing the subnet mask
`255.255.255.0`.

**Network address vs. broadcast address.** In any subnet, the *first*
address (all variable bits = 0, e.g. `192.168.1.0`) identifies the network
itself, and the *last* address (all variable bits = 1, e.g.
`192.168.1.255`) is the broadcast address — a packet sent there reaches
every host on the subnet. Neither is assignable to a single host, which
is why a "/24" gives you 256 total addresses but only **254 usable
hosts**.

**It's all bitwise math.** An IPv4 address is really just a 32-bit
integer. `192.168.1.5` is `11000000.10101000.00000001.00000101` in
binary. A router (and this script) decides "is this address inside that
subnet?" by comparing the first N bits (per the prefix length) — that's
the entire mechanism behind routing and subnetting. Python's `ipaddress`
module does this bit-masking for you so you never touch binary directly,
but knowing it's happening is what makes CIDR notation click.

## Code walkthrough

Open [`cidr_expander.py`](cidr_expander.py) alongside this section.

- **`expand_cidr()`** — `ipaddress.ip_network("192.168.1.0/24")` parses the
  string into an `IPv4Network` object that already knows its network
  address, broadcast address, and prefix length. `.hosts()` is a
  generator that yields every *usable* address (it silently skips network
  + broadcast for anything larger than a `/31`) — that's why
  `--include-net-broadcast` exists as an opt-in, not the default.
- **`expand_range()`** — real engagement scope documents often give you
  an arbitrary range instead of a clean subnet (`"start IP - end IP"`).
  This converts each endpoint to its integer form with `int(ip_address)`,
  walks every integer between them with a plain `range()`, and converts
  each one back to a string. This only works because IP addresses *are*
  integers underneath — the dotted-quad notation is just for humans.
- **`expand_target()`** — a tiny dispatcher that looks at the input
  string's shape (`/` present, `-` present, or neither) to decide which
  expander to call. This "sniff the input, dispatch accordingly" pattern
  shows up constantly in recon tooling, where you want one flexible
  target argument instead of three separate flags.

## Try it yourself (exercises)

1. Run `python3 cidr_expander.py 192.168.1.0/24` and count the output —
   confirm it's 254, not 256. Then add `--include-net-broadcast` and
   confirm it becomes 256. Explain in one sentence *why* the difference
   is exactly 2.
2. What does `192.168.1.0/31` output with and without
   `--include-net-broadcast`? Look up why `/31` is a special case in the
   `ipaddress` docs (hint: it's used for point-to-point links) — this is
   a real edge case Python's standard library had to special-case.
3. Add support for reading multiple CIDR blocks/ranges from a file
   (one per line) and merging the results into one deduplicated list.
4. (Preview of Project 03) This script *writes* a list of IPs — the
   `-o` flag saves it to a file. Sketch how you'd feed that file into
   `port_pinger.py` from Project 01 so it scans every host in a subnet,
   not just one. What would need to change in Project 01 to accept a
   *list* of hosts instead of a single one?

## Running it

```bash
git clone <your-repo-url>
cd 02-cidr-ip-range-expander
python3 cidr_expander.py 192.168.1.0/24
python3 cidr_expander.py 192.168.1.0/24 -o hosts.txt   # save to a file
```

Standard library only — no `pip install` needed.

## What's next

**Project 03 — Multi-threaded Port Scanner:** combines Project 01
(port checking) with Project 02 (host expansion) and adds `threading` so
you can scan hundreds of host/port combinations concurrently instead of
one at a time.
