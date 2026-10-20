# Security policy

Rudy PE is a local static parser for Windows Portable Executable files. It treats input as untrusted bytes and uses bounds checks, parser caps, and a CLI file-size limit. It does not execute samples or make network requests.

## Reporting a parser vulnerability

Please do not attach malware samples to a public issue. Use GitHub's private vulnerability reporting for this repository when available, or contact the maintainer through the contact details on the GitHub profile. Include the affected release or commit, the relevant command or API call, and a minimized non-sensitive reproducer where possible.

Reports are triaged on a best-effort basis. No response-time guarantee is made.

## Supported versions

Only the latest published release is supported for security fixes.
