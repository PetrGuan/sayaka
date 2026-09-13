<!-- SPDX-License-Identifier: MPL-2.0 -->

# Installer preview (bounded, read-only)

`sayaka installer ROOT` performs explicit-root discovery of existing ordinary
`.dmg` and `.pkg` filenames and inspects only bounded structural bytes:

- `.dmg`: final 512-byte UDIF `koly` footer checks only.
- `.pkg`: XAR header + bounded compressed TOC + bounded XML descriptor hints.

## Safety and non-goals

- No mount/attach/install/execute operations.
- No payload/Bom/Scripts/PackageInfo body extraction.
- No signature trust, certificate, notarization, or receipt/install-state checks.
- No quarantine/origin/provenance attribute reads in this slice (`not_read`).

## Frozen limits

- Candidate paths: 512
- DMG footer read: exactly 512 bytes
- XAR TOC: 4 MiB compressed, 16 MiB expanded (per file)
- XML: depth 32, nodes 50,000, retained name/text bytes 1 MiB
- Aggregate candidate I/O: 64 MiB
- Aggregate expanded TOC bytes: 128 MiB
- Combined scan + inspection budget: 30 seconds

When limits/cancellation/freshness checks trigger, status is partial/cancelled
and retained evidence is reported without claiming success.

## Dependency/license notes

This slice uses:

- `flate2` (MIT/Apache-2.0) for bounded zlib decoding
- `quick-xml` (MIT) for streaming XML parsing

The implementation is original Rust code under MPL-2.0 and does not copy Apple
or third-party parser code/prose.

## Reference provenance (facts, not copied implementation)

- XAR header/TOC format facts: Apple OSS XAR public sources and license:
  - https://raw.githubusercontent.com/apple-oss-distributions/xar/main/xar/include/xar.h.in
  - https://raw.githubusercontent.com/apple-oss-distributions/xar/main/xar/lib/archive.c
  - https://raw.githubusercontent.com/apple-oss-distributions/xar/main/xar/LICENSE
- UDIF trailer field facts in this slice are based on public reverse-engineered
  references (non-Apple-primary), currently libyal/libmodi documentation:
  - https://raw.githubusercontent.com/libyal/libmodi/main/documentation/Mac%20OS%20disk%20image%20types.asciidoc

This command reports bounded structural evidence only. It does **not** prove a
DMG is mountable or a PKG is installable/authentic.
