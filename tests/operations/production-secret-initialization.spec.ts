import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

const execute = promisify(execFile);
const TARGETS = ["initializer", "operator", "server", "worker", "postgres"] as const;
const SOURCES = [
  "database_owner_password",
  "database_migrator_password",
  "database_server_password",
  "database_worker_password",
  "database_backup_password",
  "oauth_signing_key",
  "evidence_signing_key",
  "browser_session_key",
  "data_kek"
] as const;

interface Probe {
  readonly code: number;
  readonly marker: boolean;
  readonly files: readonly string[];
  readonly repeatCode: number | null;
  readonly faultInjected: boolean;
  readonly custody: readonly {
    readonly name: string;
    readonly uid: number;
    readonly mode: number;
  }[];
}

async function probe(scenario: string): Promise<Probe> {
  const compose = await readFile(new URL("../../compose.production.yaml", import.meta.url), "utf8");
  const match = /    command:\n      - (>-|\|)\n([\s\S]*?)    volumes:\n/u.exec(compose);
  if (!match?.[2]) throw new Error("production secret initializer command is missing");
  const lines = match[2].split("\n").map((line) => line.replace(/^ {8}/u, ""));
  const initializer = lines.join(match[1] === ">-" ? " " : "\n").replaceAll("$$", "$");
  // Only synthetic material enters this networkless container. Execute the actual
  // Compose command under its Alpine shell without needing a database or host mounts.
  const program = `
    const fs = require('node:fs');
    const {spawnSync} = require('node:child_process');
    const scenario = process.argv[1];
    const command = process.argv[2];
    const sources = ${JSON.stringify(SOURCES)};
    const targets = ${JSON.stringify(TARGETS)};
    fs.mkdirSync('/run/secrets', {recursive:true});
    for (const name of sources) fs.writeFileSync('/run/secrets/'+name,'SYNTHETIC-TEST-ONLY');
    if (scenario.startsWith('missing:')) fs.unlinkSync('/run/secrets/'+scenario.slice(8));
    if (scenario === 'empty') fs.writeFileSync('/run/secrets/oauth_signing_key','');
    if (scenario === 'oversize') fs.writeFileSync('/run/secrets/oauth_signing_key',Buffer.alloc(65537,0x61));
    if (scenario === 'unexpected') fs.writeFileSync('/server-target/database_owner_password','SYNTHETIC-STALE');
    if (scenario === 'symlink-source') { fs.unlinkSync('/run/secrets/oauth_signing_key'); fs.symlinkSync('/run/secrets/evidence_signing_key','/run/secrets/oauth_signing_key'); }
    if (scenario === 'symlink-target') fs.symlinkSync('/run/secrets/data_kek','/server-target/oauth_signing_key');
    if (scenario === 'target-directory') fs.mkdirSync('/server-target/oauth_signing_key');
    if (scenario === 'interrupted') {
      for (const target of targets) fs.writeFileSync('/'+target+'-target/.initialization-incomplete','');
      fs.writeFileSync('/server-target/.next-oauth_signing_key','SYNTHETIC-PARTIAL');
    }
    let fault = '';
    if (scenario === 'copy-failure' || scenario === 'publish-failure') {
      const tool = scenario === 'copy-failure' ? 'install' : 'mv';
      const target = scenario === 'copy-failure' ? '*worker-target*evidence_signing_key*' : '*worker-target*data_kek*';
      fault=tool+'() { case "$*" in '+target+') touch /tmp/fault-injected; return 73;; esac; command '+tool+' "$@"; }\\n';
    }
    const first=spawnSync('sh',['-ec',fault+command],{encoding:'utf8'});
    const files=fs.readdirSync('/server-target').sort();
    const marker=fs.existsSync('/server-target/.initialization-incomplete');
    const repeated=scenario==='valid' ? spawnSync('sh',['-ec',command],{encoding:'utf8'}).status : null;
    const custody=files.map(name=>{const stat=fs.lstatSync('/server-target/'+name);return {name,uid:stat.uid,mode:stat.mode&0o777};});
    process.stdout.write(JSON.stringify({code:first.status,marker,files,repeatCode:repeated,faultInjected:fs.existsSync('/tmp/fault-injected'),custody}));
  `;
  const { stdout } = await execute(
    "docker",
    [
      "run",
      "--rm",
      "--pull=never",
      "--network=none",
      "--read-only",
      "--user=0:0",
      "--cap-drop=ALL",
      "--cap-add=CHOWN",
      "--cap-add=DAC_OVERRIDE",
      "--cap-add=FOWNER",
      "--security-opt=no-new-privileges:true",
      ...["run", "tmp", ...TARGETS.map((target) => `${target}-target`)].flatMap((directory) => [
        "--tmpfs",
        `/${directory}:size=1m`
      ]),
      "--entrypoint=node",
      process.env["BOARDAGENT_RELEASE_IMAGE"] ?? "boardagent:verification-current",
      "-e",
      program,
      scenario,
      initializer
    ],
    { timeout: 30_000, maxBuffer: 1_048_576 }
  );
  return JSON.parse(stdout) as Probe;
}

const SERVER_FILES = [
  "browser_session_key",
  "data_kek",
  "database_server_password",
  "evidence_signing_key",
  "oauth_signing_key"
];

describe("production secret initialization failure and reuse boundaries", () => {
  it("publishes only the required consumer secrets and permits a complete repeat", async () => {
    expect(await probe("valid")).toEqual({
      code: 0,
      marker: false,
      files: SERVER_FILES,
      repeatCode: 0,
      faultInjected: false,
      custody: SERVER_FILES.map((name) => ({ name, uid: 10001, mode: 0o400 }))
    });
  });

  it.each(SOURCES)("refuses the whole initialization when %s is missing", async (name) => {
    expect((await probe(`missing:${name}`)).code).not.toBe(0);
  });

  it.each([
    "empty",
    "oversize",
    "unexpected",
    "symlink-source",
    "symlink-target",
    "target-directory"
  ])("refuses unsafe input or residue: %s", async (scenario) => {
    expect((await probe(scenario)).code).not.toBe(0);
  });

  it.each(["copy-failure", "publish-failure"])(
    "keeps startup blocked after %s",
    async (scenario) => {
      const result = await probe(scenario);
      expect(result.faultInjected).toBe(true);
      expect(result.code).not.toBe(0);
      expect(result.marker).toBe(true);
    }
  );

  it("recovers a prior incomplete initialization only by publishing the complete set", async () => {
    const result = await probe("interrupted");
    expect(result.code).toBe(0);
    expect(result.marker).toBe(false);
    expect(result.files).toEqual(SERVER_FILES);
  });
});
