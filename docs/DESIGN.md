# Design notes

Rudy PE has three small layers:

1. `Reader` provides little-endian reads over an immutable byte span and checks every access before dereferencing it.
2. `Parser` validates required headers, records bounded section metadata, maps RVAs only when a single section provides the requested file-backed range, and emits findings instead of guessing when optional structures are malformed.
3. The CLI applies a 1 GiB file-size limit and selects a text, JSON, or SARIF formatter. The library itself accepts a caller-owned span and does not impose file I/O policy.

The parser limits section count to 96, import descriptors to 4,096, import thunks to 65,536 per descriptor, and retained imports to 10,000. These limits keep malformed input from causing unbounded traversal or report growth.

## Deliberate boundaries

- Does not map or execute the image.
- Does not resolve forwarded exports or emulate Windows loader behavior.
- Does not verify Authenticode signatures or certificate trust.
- Does not decompress or unpack sections.
- Does not call the file malicious based on entropy, permissions, imports, or overlays.

The PE specification defines the security directory's address as a file offset. The parser follows that special case; all other data directories handled here are mapped from RVAs.
