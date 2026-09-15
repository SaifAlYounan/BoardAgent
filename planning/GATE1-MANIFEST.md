# BoardAgent Gate-1 manifest

Frozen: 2026-08-27 (Asia/Dubai)  
Digest algorithm: SHA-256  
Combined Gate-1 digest: `d87baff752cbd95b5cdcda9c8bc5aa8cbb03ab49e8622b17a64dcfdb1e77d998`

## Included approval files

```text
1152a6da2708e742872e25de1564b53d7db3e322f89004d4e2f9195739b024ad  00-GATE1-REQUIREMENTS-TRANSLATION.md
5d2791a32f1952c5a9673c8ad58dd45bf4fae52690dff3f511e5e2a74c66a1f9  01-REQUIREMENTS.md
09042fd601ded6393d75e1675ad66243912d3d3257f161399f33cc85f4484411  10-GATE1-APPROVAL-PACK.md
```

The combined digest is SHA-256 over the three UTF-8 lines above, in exactly that order, each terminated
by LF. The manifest is not hashed into itself.

## Authority boundary

- Approval covers only the exact three files above and their 47 itemized G1 cards.
- `02` through `09`, `INDEX.md`, root drafts and scratch files are explanatory/exploratory and excluded.
- Gate 1 can authorize only the disposable test/evaluation/read-only research spike in G1-42..45.
- Gate 1 cannot authorize product code, migrations, design freeze, a provider API, external contact,
  deployment, publication, regression-baseline blessing or release.
- Any included-file byte change invalidates this digest and requires a new manifest/terminal form.
- Corrections require a regenerated digest or an explicit correction overlay bound to this digest.

## Terminal decision grammar

To confirm every displayed card individually without changing it, the human response is exactly:

```text
APPROVED G1-01 THROUGH G1-47 WITHOUT CORRECTIONS
```

Otherwise use one or more exact entries:

```text
CORRECT G1-xx: <replacement text>
REJECT G1-xx: <reason>
```

A bare `approved`, blank answer, partial range, ambiguous response or response tied to another digest
confers no authority.
