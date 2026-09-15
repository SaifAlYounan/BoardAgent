# Third-party notices

BoardAgent is distributed under the Apache License 2.0 in the repository root (see `LICENSE` and `NOTICE`). The following
notice records the sole pinned source-code prior-art repository reviewed during Phase 0.
It does not make that repository a BoardAgent runtime or build dependency.

The production PostgreSQL image also contains the separately pinned Alpine `libuuid`
runtime package recorded below.

## Alpine libuuid runtime package

- Package: `libuuid` `2.42.3-r1` (from util-linux)
- Purpose: patched UUID runtime library for the PostgreSQL image
- Repository: <https://dl-cdn.alpinelinux.org/alpine/v3.24/main>
- Architectures and SHA-256:
  - `x86_64`: `8306e5bb577696c9069fe1dfd9e1dcc39d2d481c6a1b0e707fd03c3e21aa6aa2`
  - `aarch64`: `9ce20c7ffe2ccaa7c321893c10564abbca13c3f2edb82f60a35f1f68e004f86c`
- Upstream: <https://git.kernel.org/pub/scm/utils/util-linux/util-linux.git>
- Package license: BSD-3-Clause
- Build verification: exact SHA-256 plus the Alpine package signature, using the trusted
  keys shipped in the digest-pinned PostgreSQL base image

## LQGovernance-OpenBoard

- Project: LQGovernance-OpenBoard
- Source: <https://github.com/LegalQuants/LQGovernance-OpenBoard>
- Frozen commit: `1b38dbf2c1ea413fea0661c34c63cd0fd10dc4bb`
- License: MIT
- Canonical license file in the read-only reference checkout:
  `vendor/openboard/LICENSE`
- Canonical file length: 1,088 bytes
- SHA-256:
  `8f8175ef116b82fbd057625d0751517802643de57254e4fb737b4f1e91e06521`
- Harvest treatment: concepts, failure cases, and limited implementation patterns only;
  no module is taken as-is. See `docs/HARVEST_REPORT.md`.
- Adapted files: `lib/db/src/migrate.ts`, `lib/domain/src/value-objects.ts`,
  `lib/domain/src/voting.ts` and `tests/unit/voting.test.ts` carry a header naming this
  origin. They are distributed here under the Apache License 2.0; the MIT notice below
  is retained for the material derived from the original.

The exact license text from the pinned checkout follows:

```text
MIT License

Copyright (c) 2026 Alexios Kirillov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Inclusion and attribution policy

`vendor/openboard/` is excluded from Git tracking, TypeScript workspaces, package
publishing, SBOM dependency closure, and the Docker build context. BoardAgent never
executes or imports the vendor checkout. It exists only so an engineer can reproduce the
hostile review against the exact frozen source.

Any BoardAgent source or test containing adapted OpenBoard expression must retain a
leading notice with the project URL, frozen commit, upstream path or area, original
copyright, MIT license reference, and the material BoardAgent security changes. That
file-level notice and this document must accompany every copy or substantial portion of
the adapted work. Purely rewritten files retain provenance through
`docs/HARVEST_REPORT.md`; a maintainer must not relabel copied expression as a rewrite to
avoid attribution.

Updating the upstream commit, copying an additional upstream area, or including vendor
files in a build or distribution requires a new hostile review, refreshed license
digest/notice, dependency and image-closure checks, and the applicable Architect
decision before release.
