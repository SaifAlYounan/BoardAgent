# BoardAgent Gate-2 freeze manifest

Status: **AWAITING SPONSOR APPROVAL**  
Prepared: 2026-08-28 (Asia/Dubai)

This manifest fixes the exact bytes offered for Gate-2 approval. Approval of the
terminal phrase in `GATE2-APPROVAL-PACK.md` applies to these digests. Any subsequent
change to a listed file invalidates this manifest and requires a new digest set before
approval.

Gate-1 prerequisite:

- approved requirements: `G1-01` through `G1-47`, without corrections;
- Gate-1 digest: `d87baff752cbd95b5cdcda9c8bc5aa8cbb03ab49e8622b17a64dcfdb1e77d998`;
- Gate-1 approval receipt hash:
  `a166010aa45b1222276eb15587c78c5ce3a612cb2f247d226b9e76bb3dca9bae`.

## Normative Gate-2 files

| SHA-256 | Relative path |
|---|---|
| `b2a5be718e44541b9c9c8022e9f94c24ab6c3eba79745079a96f56f0594bab50` | `gate2/GATE2-DECISIONS.md` |
| `a53bc820a15ea1fd0472678626eac04922213b1cc658327c113d795622ce5b7c` | `gate2/SURFACE-AUTHORITY-EVENT-MATRIX.md` |
| `c1d986fe2e6469897a6f6a2de71c606ec3e753e90123f2958793b5be98768952` | `gate2/DATA-STATE-TRANSACTIONS.md` |
| `2759dbd068827cb0f001a5c0c38047399f8821e2ff58139f91424a61013f85df` | `gate2/VERIFICATION-AND-RELEASE-NET.md` |
| `5351f3ede29b036272734bebc00399a945d9d0fcf99cd3dfdd9d9bf04902e3e1` | `gate2/BUILD_PLAN.proposed.md` |
| `721670ea050f1717dadb1b4ee5dcbb019d9db3bdd714fe4be9b1e7cfe617643f` | `gate2/GATE2-APPROVAL-PACK.md` |
| `9b013acaa3892fe48371b5d5efc99f836196c449a2b23b9e41b82942f2585366` | `evidence/STATUS.md` |

## Research and post-Gate-1 sponsor direction

| SHA-256 | Relative path |
|---|---|
| `dc7b7a29d853328fabc612bee88377951a8a171d832783984d36e4781d688325` | `research/MCP-OAUTH-PRIMARY-SOURCES.md` |
| `7fdfd658eebb5371835d8c3f233769466b1564ff77491c2fa4e6e039788118a7` | `research/TOOLCHAIN-AND-DEPLOYMENT-PRIMARY-SOURCES.md` |
| `43b7015899db915da89fe80ac4c18d8702588ef90db23a4c87a6dd5b9a985c9a` | `research/OPENBOARD-READONLY-HARVEST.md` |
| `52d184390409dd730784ae61217f174f189e7d0405f777f0e51330d47fe13019` | `research/POST-GATE1-SPONSOR-DIRECTION-01.md` |
| `2c67457d0eda8f62890f57c4466a2f02b6398e357c573f931feacac7b84f781f` | `research/POST-GATE1-SPONSOR-DIRECTION-02-IDENTITY-HOSTING.md` |
| `ac2a364165741ff3cbb986087868f1bac1c22b23fabf87a837d3a2ac521991bf` | `research/POST-GATE1-SPONSOR-DIRECTION-03-MEMBER-SURFACES.md` |
| `792a7b102d3b0e681913f70dac0601229b159700f1e9a89c5dfef59c0494e58c` | `research/POST-GATE1-SPONSOR-DIRECTION-04-CLIENT-PORTABILITY.md` |
| `6a0925971c3b2ccf6747aaf5605b668f41eba79cad72715245ef3ead7321d204` | `research/POST-GATE1-SPONSOR-DIRECTION-05-RETENTION-AND-MANAGEMENT-QUESTIONS.md` |
| `c42371da54fd36b59ed5d027b612e0d166fb5dfecc182483e12ffd15bdcc979e` | `research/POST-GATE1-SPONSOR-DIRECTION-06-MEETING-TRANSCRIPTS.md` |
| `8e6e282e29355f36124882db62ac266c49066fd10522ba5ec519e9709d07dd0f` | `research/POST-GATE1-SPONSOR-DIRECTION-07-MINUTES-REVIEW-ACTIONS.md` |

## Registry and evaluation closure

- decisions: 69 unique entries, contiguous `D2-001` through `D2-069`;
- MCP tools: 148 unique identifiers;
- audit event types: 128 unique identifiers;
- security requirements: 94 unique entries, contiguous `SR-001` through `SR-094`;
- mandatory attack scenarios: 63 unique entries, contiguous `TH-01` through `TH-63`;
- acceptance scenarios: 22 unique entries, contiguous `AC-01` through `AC-22`;
- strict TypeScript: pass;
- Vitest 4.1.11: 20/20 files and 171/171 tests pass;
- seeded Stage-B tally properties: 25,000 pass.

Verification commands used from `/private/tmp/boardagent-stage-b`:

```text
/private/tmp/boardagent-toolchain/node-v24.20.0-darwin-arm64/bin/node node_modules/typescript/bin/tsc --noEmit --pretty false
/private/tmp/boardagent-toolchain/node-v24.20.0-darwin-arm64/bin/node node_modules/vitest/vitest.mjs run --no-file-parallelism --maxWorkers=1
```

Stage-B evidence is disposable design evidence, not product proof. Real PostgreSQL,
browser/authenticator, off-the-shelf client, worker/crash, Compose/VPS, export,
backup/restore, adversarial and acceptance lanes remain `UNVERIFIED` until the frozen
build plan executes.
