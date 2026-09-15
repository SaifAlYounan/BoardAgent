import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
const execute = promisify(execFile);

async function probe(scenario: string) {
  const module = path.resolve("artifacts/server/dist/kernel-maintenance-lease.js");
  await readFile(module); // Real compiled implementation must exist, never a substitute lock.
  const program = `
    import fs from 'node:fs/promises';import {spawn} from 'node:child_process';
    import {acquireKernelMaintenanceLease} from '/probe/lease.mjs';
    const scenario=process.argv[1],file='/coord/maintenance.lock';
    await fs.chown('/coord',0,10001);await fs.chmod('/coord',0o750);
    await fs.writeFile(file,'',{mode:0o440});await fs.chown(file,0,10001);
    const childSource="import {acquireKernelMaintenanceLease} from '/probe/lease.mjs'; const l=await acquireKernelMaintenanceLease('/coord/maintenance.lock','shared');process.stdout.write('ready');process.stdin.once('data',async()=>{await l.close();process.exit(0)});process.stdin.resume();";
    const start=async()=>{const child=spawn(process.execPath,['--input-type=module','-e',childSource],{uid:10001,gid:10001,stdio:['pipe','pipe','pipe']});let diagnostic='';child.stderr.on('data',x=>diagnostic=(diagnostic+x).slice(-2000));await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',code=>reject(new Error('lease child exited '+code+': '+diagnostic)));child.stdout.once('data',resolve)});return child};
    const close=async(child,killed=false)=>{const done=new Promise(resolve=>child.once('exit',resolve));if(killed)child.kill('SIGKILL');else child.stdin.write('close');await done};
    const attempt=async()=>{try{const l=await acquireKernelMaintenanceLease(file,'exclusive');await l.close();return 'acquired'}catch(error){return error.code}};
    if(scenario==='shared-and-exclusive'||scenario==='killed-holder'){
      const first=await start(),second=await start();
      const whileBoth=await attempt();await close(first,scenario==='killed-holder');const whileSecond=await attempt();await close(second);const after=await attempt();
      process.stdout.write(JSON.stringify({whileBoth,whileSecond,after}));
    }else if(scenario==='unprivileged-substitution'){
      const child=spawn(process.execPath,['--input-type=module','-e',"import fs from 'node:fs/promises';try{await fs.unlink('/coord/maintenance.lock');process.stdout.write('removed')}catch(e){process.stdout.write(e.code)}"],{uid:10001,gid:10001,stdio:['ignore','pipe','pipe']});let output='';child.stdout.on('data',x=>output+=x);await new Promise(resolve=>child.once('exit',resolve));process.stdout.write(JSON.stringify({output,after:await attempt()}));
    }else{
      if(scenario==='writable-directory')await fs.chmod('/coord',0o770);
      if(scenario==='owned-by-application')await fs.chown(file,10001,10001);
      if(scenario==='hardlink')await fs.link(file,'/coord/alias');
      if(scenario==='symlink'){await fs.rename(file,'/coord/original');await fs.symlink('/coord/original',file)}
      process.stdout.write(JSON.stringify({after:await attempt()}));
    }
  `;
  const result = await execute(
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
      "--cap-add=FOWNER",
      "--cap-add=SETUID",
      "--cap-add=SETGID",
      "--cap-add=KILL",
      "--label=org.boardagent.test=kernel-maintenance-lease",
      "--security-opt=no-new-privileges:true",
      "--tmpfs",
      "/coord:mode=0750",
      "--mount",
      `type=bind,source=${module},target=/probe/lease.mjs,readonly`,
      "--entrypoint",
      "node",
      process.env["BOARDAGENT_RELEASE_IMAGE"] ?? "boardagent:verification-current",
      "--input-type=module",
      "-e",
      program,
      scenario
    ],
    { timeout: 20_000, maxBuffer: 16_384 }
  );
  return JSON.parse(result.stdout);
}

describe("kernel-held production maintenance lease", () => {
  it.each(["shared-and-exclusive", "killed-holder"])(
    "retains exclusion until every actual process closes (%s)",
    async (scenario) => {
      expect(await probe(scenario)).toEqual({
        whileBoth: "maintenance_lock_busy",
        whileSecond: "maintenance_lock_busy",
        after: "acquired"
      });
    }
  );
  it("denies replacement of the shared lock inode by the application identity", async () => {
    expect(await probe("unprivileged-substitution")).toEqual({
      output: "EACCES",
      after: "acquired"
    });
  });
  it.each(["writable-directory", "owned-by-application", "hardlink", "symlink"])(
    "refuses unsafe coordination paths (%s)",
    async (scenario) => {
      expect(await probe(scenario)).toEqual({ after: "maintenance_lock_invalid" });
    }
  );
});
