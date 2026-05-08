# Passive OSINT Leak Review

Use this workflow only for domains, brands, apps, and data you own or are authorized to assess. The Safety Lab OSINT module is search-only: it helps generate defensive dorks, review public search results, and document leads without scraping, bypassing access controls, or downloading unknown dumps.

## Workflow

1. Open `index.html` and go to **Safety Lab**.
2. In **Data Leak Dork Review**, enter your primary domain and brand aliases.
3. Click **Build Dorks** and copy each query into your search engine.
4. Paste result URLs or snippets back into the OSINT findings box.
5. Click **Analyze Findings** to score public leak indicators.
6. Run the full audit and export JSON/TXT for a local evidence note.

## What The Dorks Check

- Public files on your own domain, such as PDFs, CSVs, SQL dumps, logs, and env-style files.
- Directory listings, backups, and exposed config references.
- Brand or domain mentions on code repositories, paste sites, and shared document platforms.
- Admin/login surface discovery for internal review, not exploitation.

## Triage Rules

- Critical/high leads: preserve the URL, timestamp, screenshot, and search query, then rotate any potentially exposed secrets.
- Public code or paste hits: contact the owner/platform for removal and check whether the exposed key still works before disabling it.
- Files on your own domain: remove or restrict the file, invalidate cached copies where possible, and review server access logs.
- Unknown dumps: do not download them. Record public metadata and escalate to your incident response owner.

## Boundaries

This framework does not perform intrusion, vulnerability exploitation, password guessing, credential stuffing, dump downloading, or automated scraping. It is designed for defensive exposure management and chain-of-custody friendly documentation.
