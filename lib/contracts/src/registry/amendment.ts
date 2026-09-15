/** Exact additive build contract; changing these pins requires a new recorded amendment. */
export const ADMINISTRATIVE_AMENDMENT = Object.freeze({
  id: "administrative-authority-20260906-v1",
  path: "docs/decisions/access-control-amendment-v1.json",
  sha256: "20af9fbc08eaa829fe2fdbc87ff730edd029d85e5d86b26a656e16648dfea3f4",
  authorizationPath: "docs/decisions/access-control-implementation-authorization.md",
  authorizationSha256: "72d871745cc9e9650a9804704e0a8db3d4174319a177ee24586c1e7218839011",
  surfaceMatrixSha256: "a53bc820a15ea1fd0472678626eac04922213b1cc658327c113d795622ce5b7c",
  verificationMatrixSha256: "2759dbd068827cb0f001a5c0c38047399f8821e2ff58139f91424a61013f85df"
} as const);

export const ADMINISTRATIVE_REGISTRY_COUNTS = Object.freeze({
  tools: 151,
  readTools: 58,
  directTools: 30,
  humanConfirmedTools: 63,
  resourceTemplates: 16,
  prompts: 7,
  httpAuthorityFamilies: 11,
  cliRows: 8,
  cliCommands: 9,
  events: 136,
  securityRequirements: 102,
  threats: 71,
  acceptanceScenarios: 25,
  verificationTiers: 11
} as const);

export const OPERATIONAL_AMENDMENT = Object.freeze({
  id: "operational-maintenance-20260909-v1",
  path: "docs/decisions/operational-maintenance-amendment-v1.json",
  sha256: "3d4547a933ae8c2095b8dac9d603a8a20a5f5d26a6a204e2e411cede1f18de4d",
  instructionPath: "docs/decisions/operational-completion-instruction-2026-09-08.md",
  instructionSha256: "e8fe4b97ff50c76f601825c81e0edd2c53575a267178c0ccbd412c7139e555e1",
  parentRegistryDigest: "7a8607647c451c6594c09a34f6ad7c0a9e80d91a75295ce5bf092a53035878bc"
} as const);

export const OPERATIONAL_REGISTRY_COUNTS = Object.freeze({
  ...ADMINISTRATIVE_REGISTRY_COUNTS,
  cliRows: 10,
  cliCommands: 11,
  events: 137
} as const);

export const ONBOARDING_AMENDMENT = Object.freeze({
  id: "onboarding-publication-20260910-v1",
  path: "docs/decisions/onboarding-publication-amendment-v1.json",
  sha256: "6cd9e5b9fc9cb37867beec317e4ebf476e01f8a67f079d9d7e07e2632fe2b6ed",
  instructionPath: "docs/decisions/onboarding-publication-implementation-2026-09-10.md",
  instructionSha256: "74ac5ee7f76ec7ea64ce88f7d613b38b674ee48bc2c78429d002bb99ecab1195",
  parentRegistryDigest: "1362f5dece04d2af4a76216d4eb3c4f37aa316a052178d5380518123f7becf7a"
} as const);

export const ONBOARDING_REGISTRY_COUNTS = Object.freeze({
  ...OPERATIONAL_REGISTRY_COUNTS,
  tools: 153,
  humanConfirmedTools: 65,
  events: 139
} as const);

export const ACTIVATION_RESTART_AMENDMENT = Object.freeze({
  id: "activation-restart-20260913-v1",
  path: "docs/decisions/activation-restart-amendment-v1.json",
  sha256: "626249f99591bb7b5a09025f80340258c579b693e7968275811c25bb1f85789e",
  instructionPath: "docs/decisions/activation-restart-proposal-2026-09-13.md",
  instructionSha256: "9a0cd82e6ba260dbb42fda33c1cc799b9101cddc2a114d50d66c9dea31ac3092",
  parentRegistryDigest: "c5318e35629312133a4e7d55df9cde7b0bcb15f205e55542927033af7754d920"
} as const);

export const ACTIVE_REGISTRY_COUNTS = Object.freeze({
  ...ONBOARDING_REGISTRY_COUNTS,
  tools: 154,
  humanConfirmedTools: 66,
  events: 141
} as const);
