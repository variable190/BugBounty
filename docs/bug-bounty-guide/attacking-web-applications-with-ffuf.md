# Attacking Web Applications with Ffuf

[Relative Cheat Sheet](./ffuf-cheat.md)

## Overview
Ffuf (Fuzz Faster U Fool) is a fast web fuzzer used to discover hidden files, directories, subdomains, and parameters on web applications.

## Web Fuzzing
- **Purpose**: Identifies unlinked or hidden resources by sending multiple requests with varying inputs.
- **Use Case**: Finding backup files or admin panels.

## Directory Fuzzing
- **Process**: Uses wordlists to guess directory names (e.g., `/admin`, `/backup`).
- **Benefit**: Uncovers accessible but unadvertised directories.

## Page Fuzzing
- **Process**: Fuzzes page names or extensions (e.g., `/login.php`, `/index.html`).
- **Benefit**: Detects dynamic pages or misconfigured file types.

## Recursive Fuzzing
- **Process**: Recursively explores subdirectories with `-recursion`.
- **Benefit**: Maps deep site structure for comprehensive testing.

## DNS Records and Sub-domain Fuzzing
- **Process**: Fuzzes subdomains (e.g., `dev.example.com`) using DNS queries.
- **Benefit**: Reveals hidden or forgotten subdomains.

## Vhost Fuzzing
- **Process**: Fuzzes Host headers to find virtual hosts on the same IP.
- **Benefit**: Identifies multiple sites with potentially different security.

## Filtering Results
- **Process**: Use `-fs` to filter by response size or status to reduce noise.
- **Benefit**: Focuses on valid findings, ignoring irrelevant responses.

## Parameter Fuzzing (GET/POST)
- **Process**: Fuzzes GET (`?id=FUZZ`) or POST (`-d 'id=FUZZ'`) parameters.
- **Benefit**: Discovers injectable parameters for exploitation.

## Value Fuzzing
- **Process**: Fuzzes parameter values to test input validation.
- **Benefit**: Identifies weak validation leading to vulns like SQLi.

## Tools
- Ffuf ([https://github.com/ffuf/ffuf](https://github.com/ffuf/ffuf)) for setup and usage.
- SecLists ([https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)) for wordlists.