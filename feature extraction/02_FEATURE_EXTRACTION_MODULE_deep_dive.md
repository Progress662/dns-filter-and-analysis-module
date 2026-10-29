# DNS Threat Detection System — Document 2 of 3
## Deep Dive: The Feature Extraction Module (`feature extraction/`)

> Companion to `00_OVERVIEW_architecture_and_viva_cheatsheet.md` and `01_PARSING_MODULE_deep_dive.md`.

### Folder map
```
feature extraction/
├── main.py                            ← demo entry point (builds synthetic DNSRecords + runs extraction)
├── feature_extractor.py               ← FeatureExtractor orchestrator class
├── data/                              ← (empty, just a .gitkeep — output CSVs would land here)
└── extractors/
    ├── init.py                        ← package marker (typo + import-mismatch — see below)
    ├── lexical.py                     ← LexicalExtractor (Features 1–10)
    ├── dns_features.py                ← DnsExtractor (Features 11–15)
    ├── whois.py                       ← WhoisExtractor (Features 16–19)
    ├── infra_features.py              ← InfrastructureExtractor (Features 20–21)
    └── behavioural_features.py        ← BehavioralExtractor (Features 22–25)
```

### ⚠️ Read this before anything else: a confirmed, blocking bug

I actually ran `python main.py` in this folder. It failed immediately with:
```
ModuleNotFoundError: No module named 'extractors.lexical_features'
```
Here's exactly why, mapped out:

| File that exists on disk | Name the imports expect instead |
|---|---|
| `extractors/lexical.py` | `extractors/lexical_features.py` |
| `extractors/whois.py` | `extractors/whois_features.py` |
| `extractors/infra_features.py` | `extractors/infrastructure_features.py` |
| `extractors/behavioural_features.py` (British spelling) | `extractors/behavioral_features.py` (American spelling) |
| `extractors/dns_features.py` | ✅ matches — this is the *only* one of the five that's consistent |

Both `feature_extractor.py` (the orchestrator) **and** `extractors/init.py` make the same four wrong assumptions, which strongly suggests the extractor files were renamed at some point (shortened from `*_features.py` to shorter/British names) without updating the two files that import them. This is a textbook example of why real engineering teams run automated import/lint checks before merging code — a purely mechanical renaming slip that's invisible just from reading any *one* file in isolation, but breaks the instant you try to actually execute the program.

**What this means for you practically:**
- You can still learn and explain *everything* about how each extractor computes its features by reading the files individually (which is what the rest of this document does) — the *logic inside* each extractor is correct and runnable on its own.
- But the **package, as zipped, cannot currently produce a feature dataset end-to-end**, because `feature_extractor.py`'s very first lines fail before any logic runs.
- You are not expected (per your own instructions) to have me fix this, but you should walk into your viva already knowing this, rather than being asked "did you run this?" and discovering it live in front of your mentor. A confident, accurate answer is: *"Yes — I found that the extractor module filenames don't match the import statements in `feature_extractor.py` and `extractors/init.py`; four of five extractor imports are affected, the dns_features import is the only one that's consistent with its filename."*
- There's also a second, smaller naming issue: `extractors/init.py` should be named `__init__.py` (the double underscores are missing entirely) — combined with the import mismatch above, this file currently does nothing useful even if the names were fixed, since Python wouldn't even recognize it as the package's special init file without the correct name.

With that fully on the table, let's go through the actual logic — which is the part that matters most for understanding the *science* of the project.

---

## PART A — Why feature extraction exists at all, and why it's grouped *by domain*

### What it is
The bridge between "clean structured DNS event objects" (what the parser gives you) and "a fixed-length numeric vector a machine learning model can consume" (what `FeatureExtractor.extract()` gives you).

### The core architectural decision: group by domain, not by individual record
```python
groups: Dict[str, List] = defaultdict(list)
for rec in records:
    groups[rec.domain].append(rec)
```
**Why:** A single isolated DNS query line, by itself, often tells you very little. *Many* of the strongest threat signals only emerge when you look at the **full pattern of activity for one domain across time and across clients**:
- "This domain was queried by 200 different machines in 3 minutes" → needs to count unique client IPs *for that domain*
- "90% of lookups for this domain came back NXDOMAIN" → needs a ratio over *all* lookups for that domain
- "This domain's resolved IP changed 15 times in an hour" → needs to compare *consecutive* records for that domain, sorted by time

None of these are computable from one row alone. So the very first thing `FeatureExtractor.extract()` does is **group** all records by `domain`, and only then runs each extractor **per group**.

**Real-world analogy:** A single transaction on your credit card statement rarely looks suspicious in isolation. But "this card made 40 transactions in 6 different countries in the last hour" — a *pattern across many transactions* — is what triggers a fraud alert. You're doing the DNS equivalent of that: per-domain pattern-of-activity analysis, not per-event analysis.

### Why five separate extractor *classes* instead of one big function
Same Single Responsibility reasoning as the Parser/FeatureExtractor split (see Document 0 §3), applied one level deeper: lexical analysis (string math), DNS-protocol analysis (TTL/response codes), WHOIS analysis (registration metadata), infrastructure analysis (ASN/geography), and behavioral analysis (volume/timing patterns) are five genuinely *different bodies of domain knowledge*. A security researcher improving the WHOIS heuristics shouldn't need to read or risk breaking the entropy-calculation code, and vice versa. Each extractor class also has a uniform interface (`@staticmethod extract(...) -> Dict[str, float]`), which is what lets `feature_extractor.py` treat all five interchangeably in a simple loop-like sequence of `features.update(...)` calls.

---

## PART B — `extractors/lexical.py`: `LexicalExtractor` (Features 1–10)

**Category-level "why":** These are the **cheapest** features to compute — pure string math, zero network calls, zero latency, always available even fully offline. They exploit the fact that human-chosen domain names and algorithmically-generated (DGA) domain names have statistically different *character-level* properties.

All ten live inside one static method, `LexicalExtractor.extract(domain: str) -> Dict[str, float]`. Walking through each:

1. **`domain_length`** — `len(domain)`. Simple, but real: phishing/typosquatting domains tend to be longer than legitimate brand names (e.g., `update-windows-security.com` vs `microsoft.com`) because attackers pad them with extra trust-signaling words.

2. **`digit_count`** — `sum(c.isdigit() for c in domain)`. DGA algorithms frequently mix letters and digits in their generated strings (e.g., `xk3jf9a2b1`); legitimate brand domains rarely contain digits at all.

3. **`entropy`** (Shannon entropy) — the star feature of this whole extractor. Formula: H = −Σ p(x)·log₂(p(x)) over the frequency distribution of characters in the string.
   - **Intuition:** entropy measures how "surprising"/unpredictable each character is, given the distribution of characters already seen. A string like `"aaaaaa"` has entropy 0 (every character is totally predictable — it's always `'a'`). A string with many distinct, evenly-used characters, like a string of random letters and digits, has high entropy (each new character carries a lot of "information" because you couldn't have predicted it).
   - **Why this maps to malicious vs benign:** human-chosen brand names ("google", "facebook") are *words*, and words follow the statistical patterns of natural language (some letters — e, a, t — appear far more often than others — q, z, x). DGA output is usually closer to uniformly random character selection, which mathematically *maximizes* entropy for a given alphabet size. So: low entropy → "looks like a word" → probably benign; high entropy → "looks random" → possible DGA.
   - **Worked example:** `"google"` (6 distinct-ish characters, `'g'`, `'o'` repeated) has noticeably lower entropy than `"xk3jf9a2b1"` (10 mostly-unique characters). This is literally demonstrated in the project's own synthetic test data (Scenario B in `main.py`, domain `xk3jf9a2b1lq8mz.example.xyz`).
   - Implemented in a private module-level helper `_shannon_entropy()`, kept outside the class because it's a generic string-math utility, not something conceptually tied to "being a method of LexicalExtractor" — reusable, testable in isolation.

4. **`hyphen_count`** — raw count of `-` characters. Typosquatting domains frequently insert hyphens to look like a legitimate multi-word brand phrase (`pay-pal-secure-login.com`), a pattern called out explicitly in the code comments.

5. **`subdomain_count`** — `max(0, len(domain.split(".")) - 2)`. The `- 2` accounts for the second-level domain and the TLD always being present (e.g., `example` + `com` in `example.com` itself has 0 "extra" subdomains); anything beyond that 2-part baseline counts as a subdomain level. `max(0, ...)` guards against a negative result for unusually short/malformed inputs. High subdomain depth is a known indicator of **DNS tunneling** (encoding exfiltrated data into many subdomain labels, e.g., `4a8f2c91.exfil.attacker.com`).

6. **`vowel_ratio`** and **7. `consonant_ratio`** — fraction of alphabetic characters (digits/symbols excluded from the denominator via `alpha_count`) that are vowels vs consonants. English text averages roughly 38–42% vowels; strings that deviate sharply from this (either far too many or far too few vowels) are statistically less "word-like." `alpha_count = max(len(alpha_chars), 1)` is a defensive guard against division-by-zero for a domain with zero alphabetic characters (e.g., a purely numeric label, which is unusual but not impossible).

8. **`longest_digit_seq`** and **9. `longest_consonant_seq`** — longest *consecutive run* (not total count) of digits, and of consonants respectively, computed by a shared private helper `_longest_run(text, predicate)` that takes a one-argument boolean function and tracks a running counter, resetting to 0 whenever the predicate fails and updating a running "best" maximum whenever it's exceeded. This is a clean, reusable generalization — note it's used for *two different* predicates (`isdigit`, `in CONSONANTS`) without duplicating the run-length-counting logic.
   - **Why "longest run" matters beyond plain counts:** a domain with digits scattered singly throughout (`a1b2c3d4`) and a domain with one big digit block (`abcd1234`) could have the *same total digit count*, but the long, unbroken run is a stronger signal of algorithmic generation — humans rarely write 6+ consonants in a row (English phonotactics strongly discourage it), so `longest_consonant_seq` is specifically a "does this even look pronounceable" check, independent of overall letter frequency.

10. **`unique_char_count`** — `len(set(domain_lower))`, the number of *distinct* characters used. The docstring notes this can signal weirdness in *either* direction: DGA domains that **reuse very few distinct characters** (low unique count relative to length — repetitive, unnatural patterns) *or* DGA domains that **use unusually many distinct characters** (high unique count — closer to uniform-random sampling over a large alphabet) can both look abnormal compared to typical human-chosen names, which tend to sit in a moderate, "natural language" range.

---

## PART C — `extractors/dns_features.py`: `DnsExtractor` (Features 11–15)

**Category-level "why":** These come straight from the **protocol metadata itself** — the actual DNS response behavior — rather than the domain string. This extractor needs the *list* of `DNSRecord`s for one domain (not just the string), because some features (unique IP count, IP change frequency) only make sense across multiple observations.

- **Numeric encoding tables (`QUERY_TYPE_MAP`, `RESPONSE_CODE_MAP`):** these map string codes (`"A"`, `"NXDOMAIN"`, ...) to the **actual official IANA-assigned numeric codes** used in the real DNS protocol (A=1, AAAA=28, MX=15, NXDOMAIN=3, SERVFAIL=2, etc. — these are not made up; they're the real RFC-defined values). **Why encode as numbers at all?** Most ML algorithms, including the planned Random Forest, expect numeric input — Random Forest specifically *can* handle categorical splits reasonably well internally, but representing categories as consistent integers up front avoids needing extra preprocessing/one-hot-encoding machinery, and using the *real* IANA numbers (rather than arbitrary made-up codes like 0,1,2,3...) means the encoding is self-documenting and matches what any DNS engineer would recognize.

11. **`ttl`** — average TTL across all records for this domain (`sum(...) / len(records)`). **(See Document 0, Issue C, for the real edge-case risk here: this line assumes every record has a non-`None` ttl, which the parser's own data model explicitly allows to be false.)** Conceptually: legitimate large sites typically use TTLs in the hundreds-to-low-thousands of seconds; fast-flux malicious infrastructure often uses very short TTLs (tens of seconds) to rotate IPs quickly and evade IP-based blocklists.

12. **`query_type`** — the *most frequently observed* query type for this domain, numerically encoded. `max(set(type_list), key=type_list.count)` is a compact (if not maximally efficient for huge lists — see "alternatives" below) way to find the mode of a list in pure Python.

13. **`response_code`** — same "most common" logic, applied to response codes.

14. **`unique_ip_count`** — `len(set(resolved IPs, excluding None/empty))`. A domain resolving to many distinct IPs over time can mean a legitimate CDN/load-balanced service — **or** a fast-flux botnet C2 deliberately rotating IPs. (This is exactly why this single feature isn't decisive on its own — it needs to be combined with others, like TTL and WHOIS age, for the classifier to tell the two apart; a single feature rarely proves maliciousness by itself, which is part of *why* you have 25 of them feeding a Random Forest instead of one hard-coded if/else rule.)

15. **`ip_change_frequency`** — computed by the private helper `_ip_change_frequency()`: sort records by timestamp, then count how many *consecutive* pairs have a different `resolved_ip` than the previous one, divide by the number of consecutive pairs (`len - 1`). Result is a ratio from 0.0 (the IP never changed across all observations) to 1.0 (the IP changed on literally every single query). This is a more nuanced companion to `unique_ip_count` — it captures *rate of change over time*, not just *how many distinct values ever appeared*; a domain that used 5 different IPs but changed slowly over a year looks very different from one that cycles through 5 IPs every few minutes, even though `unique_ip_count` would be identical for both.

**Alternative approach worth knowing (for "could this be done differently" questions):** Using Python's `collections.Counter(type_list).most_common(1)` would be a more efficient way to find the mode than `max(set(list), key=list.count)` (the latter is O(n²)-ish for large lists since `.count()` rescans the whole list for every distinct candidate value) — a fair, honest critique to be ready to offer if asked "how would you optimize this for millions of records," demonstrating you understand algorithmic complexity even in code you didn't personally write.

---

## PART D — `extractors/whois.py`: `WhoisExtractor` (Features 16–19)

**Category-level "why":** Registration metadata. The single strongest, most-cited heuristic in real-world threat intelligence: **malicious domains tend to be very recently registered**, because attackers burn through domains quickly as they get detected/blocklisted, while a domain that's been registered and stable for years with no prior abuse history is overwhelmingly likely to be legitimate.

16. **`domain_age`** — days since the WHOIS `creation_date`. A small/negative-looking number (a domain registered yesterday) is a red flag; a number in the thousands (registered years ago) is reassuring.
17. **`days_until_expiry`** — days remaining until the WHOIS `expiration_date`. Attackers often register domains for the *minimum* possible period (commonly just 1 year) since they don't intend long-term use; very long pre-paid registration periods are a (weak, but real) trust signal.
18. **`registration_period`** — total span between creation and expiry, i.e. how many days the registrant *paid for up front*. Computed only if *both* creation and expiry dates were available (note the `if creation:` nested check before computing this).
19. **`nameserver_count`** — number of distinct nameservers configured for the domain. Legitimate, well-resourced organizations often run multiple redundant nameservers; some throwaway malicious domains use a minimal, single, often-shared/bulletproof-hosting nameserver setup.

**Default/sentinel values (`-1.0` for the three date-based features, `0.0` for nameserver count) are a deliberate design choice**, not an oversight: using `-1` (an impossible real value — no domain can be "−1 days old") lets a downstream model or analyst clearly distinguish *"this WHOIS data was unavailable/failed"* from *"this domain genuinely has 0 days of age"* (a domain registered today, age 0, IS a real and meaningful value — it must not be confused with "lookup failed"). This is a subtle but important data-engineering principle: **never let "missing data" and "a real zero/low value" collapse into the same number**, or your model will learn the wrong thing from lookup failures.

**Why caching (`_cache: Dict[str, Optional[Any]] = {}`)?** WHOIS servers are rate-limited by registrars and the protocol itself is slow (each lookup is a real network round-trip to a WHOIS server, sometimes with redirects between registry and registrar servers). If the same domain appears in many log lines (which it usually will — that's the whole point of grouping by domain), you only want to pay that network cost **once per domain**, not once per log line. The cache is a **class-level** dict (shared across all calls/instances), not an instance-level one — meaning it persists for the lifetime of the Python process, which is appropriate here since WHOIS records don't change minute-to-minute.

**Why is this whole extractor wrapped in `try/except ImportError` at the top** (`try: import whois ... except ImportError: _WHOIS_AVAILABLE = False`)? **Graceful degradation.** The `python-whois` package is an optional, external dependency that might not be installed in every environment (e.g., a CI test runner, an air-gapped/offline DRDO lab environment without internet access for security reasons). Rather than crashing the entire feature extraction pipeline if this one package is missing, the code detects its absence once at import time and falls back to safe default values for the rest of the run. This is exactly the kind of defensive-coding pattern a security/defense-context reviewer would specifically want to see — **a production threat-detection system should degrade gracefully, not crash entirely, just because one optional, network-dependent data source is unavailable.**

---

## PART E — `extractors/infra_features.py`: `InfrastructureExtractor` (Features 20–21)

**Category-level "why":** Where in the world, and on whose network, is this domain actually hosted? Uses **RDAP** (Registration Data Access Protocol — the modern, structured, machine-readable successor to plain-text WHOIS, standardized to replace WHOIS's inconsistent free-text format) via the `ipwhois` package's `IPWhois(ip).lookup_rdap()`.

20. **`asn`** (Autonomous System Number) — identifies *which network operator* (ISP, hosting company, cloud provider) controls the IP space a domain resolves into. Certain ASNs are well-known in threat-intel circles for hosting "bulletproof" servers that ignore abuse complaints — so the ASN itself, independent of the domain name, can be a strong signal.
21. **`country_count`** — number of *distinct* countries (`asn_country_code` from the RDAP response) across all of a domain's resolved IPs. A domain resolving to IPs across many countries can mean a legitimate global CDN — or geo-distributed fast-flux malicious infrastructure (same ambiguity as `unique_ip_count` in Part C — again, the point is that no single feature decides the verdict alone).

**Same two engineering patterns as WHOIS, intentionally mirrored:** (1) caching per-IP in a class-level dict to avoid redundant network calls, and (2) a `try/except ImportError` guard around the optional `ipwhois` dependency, falling back to safe `0.0` defaults if it's not installed. Reusing the same two patterns across both network-dependent extractors (WHOIS and Infrastructure) is itself a sign of **consistent design discipline** across the codebase — worth explicitly pointing out if asked "what design patterns repeat across your extractors?"

**A subtle simplification worth knowing:** the code takes `next(iter(asns), 0)` for the "primary" ASN — i.e., just grabs *one* (arbitrary, since `set` iteration order isn't semantically meaningful) ASN out of however many were found, rather than (say) the *most common* one weighted by how many of the domain's IPs belong to it. The code comment is honest about this: *"Take the 'primary' ASN (the one found first / only one)"* — a reasonable simplification for a first version, but a fair thing to flag yourself if asked "how would you improve this," and a good demonstration that you can read code critically rather than just accept it.

---

## PART F — `extractors/behavioural_features.py`: `BehavioralExtractor` (Features 22–25)

**Category-level "why":** This is arguably the **most directly security-relevant** category, because it captures *dynamics over time and across hosts* — exactly the kind of pattern that's invisible from a single packet or a single log line, and exactly the kind of pattern DPI-based systems are bad at capturing (DPI looks at content, not at *behavioral cadence across many events*).

22. **`query_count`** — raw total number of queries observed for this domain. DGA bots probing for a live C2 server generate very high query volumes in short windows.
23. **`host_count`** — number of **distinct client IPs** that queried this domain. One host querying a domain = ordinary personal browsing. Many internal hosts suddenly querying the *same* unusual domain = a strong sign of a worm/botnet spreading across a network, all phoning home to the same C2 address.
24. **`nxdomain_ratio`** — the proportion of all queries for this domain that came back `NXDOMAIN` (note: the code checks for both `"NXDOMAIN"` and `"NAMEERROR"` — a defensive choice, since `NAMEERROR` is an older/alternate name some systems use for the same underlying response code). This is described in the code's own comments as *"the single strongest indicator of a DGA-based botnet"* — legitimate domains essentially never sit at a high NXDOMAIN ratio (if a real, popular domain existed, it... exists, and resolves), whereas a domain name generated by a DGA algorithm that *happens* to also be queried by many infected machines testing many candidate names will show a high failure ratio, because most generated candidate names simply don't exist.
25. **`query_interval`** — wall-clock seconds between the *earliest* and *latest* observed query for this domain (`sorted timestamps[-1] - timestamps[0]`). A huge number of queries packed into a *very short* interval (high `query_count`, low `query_interval`) is a burst-traffic pattern characteristic of automated/malware behavior; the same query count spread over days/weeks looks like ordinary, organic usage.

**Why these four features specifically require *grouped* records (can't be computed per-record):** this is the clearest illustration in the whole codebase of *why* the orchestrator groups by domain before calling any extractor — `host_count` literally requires seeing every record for a domain to count distinct client IPs; `query_interval` requires comparing the earliest and latest timestamp across the *whole group*. None of these numbers exist, even conceptually, for a single isolated DNS event.

---

## PART G — `feature_extractor.py`: The `FeatureExtractor` Orchestrator

### `FEATURE_COLUMNS` — why a fixed, explicit list at module level
```python
FEATURE_COLUMNS: List[str] = [
    "domain_length", "digit_count", ..., "query_count", "host_count", "nxdomain_ratio", "query_interval",
]
```
**Why hardcode the column order rather than just letting dict-merge order decide it implicitly?** Two reasons: (1) **Determinism/reproducibility** — a Random Forest (or any ML pipeline) trained on a feature matrix needs the *same column meaning in the same position* every single time it's used for training and later for prediction; relying on implicit Python dict-insertion order across five different extractor classes that might be reordered or modified independently is fragile. An explicit, named list is the single source of truth for "this is exactly what a feature row looks like." (2) **Self-documentation** — anyone reading this one list immediately sees the full 25-feature schema, grouped by category via the comments, without having to read all five extractor files to reconstruct it.

### `__init__(self, enable_whois=True, enable_ip_lookup=True)`
Two boolean toggles that flow straight through to the optional, network-dependent extractors (WHOIS, Infrastructure). **Why toggle at the orchestrator level rather than inside each extractor individually deciding for itself?** Centralized control — the *caller* (whoever's running the pipeline) gets to make one explicit decision per run ("am I online right now, do I want to pay the latency cost of live lookups") rather than each extractor silently guessing or needing its own separate flag wired through from somewhere else.

### `extract(records) -> pd.DataFrame`
1. Groups by domain (`defaultdict(list)`)
2. Calls `self._extract_one(domain, domain_records)` for every group, **sorted by domain name** (`sorted(groups.items())`) — sorting here is a small but real reproducibility choice: re-running extraction on the same input always produces rows in the same order, which makes diffing/debugging output across runs much easier
3. Builds a `pandas.DataFrame` from the list of row-dicts
4. Explicitly reorders columns to `["domain"] + FEATURE_COLUMNS`, with a defensive `[c for c in ordered if c in df.columns]` filter — a safety net so that if some unexpected feature name mismatch ever occurred (ironic, given the actual bug discussed at the top of this document!), the code wouldn't crash trying to select a column that doesn't exist; it would just silently omit it. (Worth noting: a "safety net" like this is good for not-crashing, but can also silently hide bugs — a real tradeoff between robustness and visibility that's worth being able to discuss if asked.)

### `_extract_one(domain, records) -> Dict`
The literal assembly line: starts with `{"domain": domain}`, then calls `features.update(...)` once per extractor category in sequence — Lexical, then DNS, then (conditionally) WHOIS, then (conditionally) Infrastructure, then Behavioral. Using `dict.update()` repeatedly to merge five separate small dicts into one big one is a simple, readable pattern *specifically enabled* by the design discipline of having every extractor return a flat `Dict[str, float]` with no overlapping key names across categories — another place where the consistent "every extractor returns the same shape of thing" interface convention pays off.

---

## PART H — `main.py`: The Synthetic Demo Data

Rather than reusing the *real* sample logs from the parsing project, this `main.py` builds its **own** small, self-contained `DNSRecord` dataclass (redefined locally, with a comment explicitly saying *"In YOUR real project this comes from your existing DNS parser. We redefine it here so this file is self-contained"*) and four hand-crafted synthetic scenarios designed to make the 25 features' discriminative power visible at a glance:

- **Scenario A — `www.google.com`:** 30 queries, mostly-stable resolved IP (one IP for 25 queries, switching to a second IP only at the end), spread across a full hour, `ttl=300`. **Purpose:** the "obviously benign" baseline — high query count is fine when it's *stable* and *spread out*, not bursty.
- **Scenario B — `xk3jf9a2b1lq8mz.example.xyz`:** 200 queries from **20 different client IPs**, packed into roughly **10 minutes**, **90% NXDOMAIN**, `ttl=60`. **Purpose:** the textbook DGA-botnet fingerprint — high `host_count`, high `nxdomain_ratio`, short `query_interval`, low `ttl`, and (since the domain string itself is gibberish) high lexical `entropy` too. This scenario is designed to light up features from *every single category* simultaneously.
- **Scenario C — `update-windows-security.com`:** 15 queries, all `NOERROR`, all resolving to the same IP, `ttl=120`. **Purpose:** a phishing-style domain — notice it does **not** look suspicious behaviorally or via DNS-protocol features (no NXDOMAIN, stable IP) — its red flags are purely **lexical/social-engineering** (the domain name itself impersonates a trustworthy brand/update mechanism) and would need WHOIS (likely very recently registered) to seal the case. This scenario exists specifically to demonstrate that **not every malicious category looks the same** — you need all 25 features, spanning all 5 categories, because different attack types leave different fingerprints.
- **Scenario D — `short.io`:** 8 queries, all clean, `ttl=600`. **Purpose:** a short, slightly unusual-looking but entirely legitimate domain (a real URL-shortener service) — included to test that the system doesn't *over-flag* short domains just because "short + unusual-looking" superficially resembles some DGA patterns. This is a deliberate **false-positive guard-rail example** — and being able to say *"I included a legitimate-but-short domain specifically to verify my features don't naively over-penalize brevity"* is exactly the kind of test-design thinking a mentor wants to hear.

**Why these four scenarios, specifically, are good evidence of your understanding (not just your coding):** They aren't random test data — each one is engineered to isolate which feature *category* catches which attack *pattern*, and Scenario D is specifically there to catch a false-positive failure mode. If asked "how did you validate your feature design," this is a precise, confident answer: *"I built four synthetic scenarios, each representing a different real-world traffic pattern — stable legitimate traffic, DGA-botnet bursts, phishing/typosquatting, and an edge-case legitimate-but-short domain — to confirm each feature category responds the way the underlying security theory predicts, and to guard against false positives on unusual-but-benign domains."*

---

**Recap — go back to `00_OVERVIEW_architecture_and_viva_cheatsheet.md`** for the end-to-end trace tying both modules together, the master Q&A bank, and the full list of verified issues you should be ready to mention proactively.
