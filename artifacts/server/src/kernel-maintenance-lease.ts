import { spawn } from "node:child_process";
import { constants, type Stats } from "node:fs";
import { lstat, open } from "node:fs/promises";
import path from "node:path";

export const PRODUCTION_MAINTENANCE_LOCK_FILE = "/run/boardagent-maintenance/maintenance.lock";
export type KernelMaintenanceMode = "shared" | "exclusive";
export interface KernelMaintenanceLease {
  close(): Promise<void>;
}
export class KernelMaintenanceLeaseError extends Error {
  constructor(
    readonly code:
      "maintenance_lock_invalid" | "maintenance_lock_busy" | "maintenance_lock_unavailable"
  ) {
    super(code);
  }
}
const invalid = () => new KernelMaintenanceLeaseError("maintenance_lock_invalid");

async function trustedDirectoryChain(file: string): Promise<void> {
  if (
    !path.isAbsolute(file) ||
    path.normalize(file) !== file ||
    file === "/" ||
    Array.from(file).some((c) => c.codePointAt(0)! < 32 || c.codePointAt(0) === 127)
  )
    throw invalid();
  let directory = path.dirname(file);
  for (;;) {
    const stat = await lstat(directory);
    // The runtime identity must never be able to substitute another inode or parent.
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o022) !== 0)
      throw invalid();
    const parent = path.dirname(directory);
    if (directory === parent) return;
    directory = parent;
  }
}
function protectedInode(stat: Stats): boolean {
  return (
    stat.isFile() &&
    stat.uid === 0 &&
    stat.nlink === 1 &&
    stat.size === 0 &&
    ((stat.mode & 0o7777) === 0o440 || (stat.mode & 0o7777) === 0o400)
  );
}
async function lockDescriptor(fd: number, mode: KernelMaintenanceMode): Promise<void> {
  // Linux flock locks the shared open-file description. The duplicated child descriptor
  // closes on exit, while this process's original descriptor keeps the lock until close/death.
  const child = spawn("/usr/bin/flock", [mode === "shared" ? "-s" : "-x", "-n", "3"], {
    stdio: ["ignore", "ignore", "ignore", fd]
  });
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", () =>
      reject(new KernelMaintenanceLeaseError("maintenance_lock_unavailable"))
    );
    child.once("close", resolve);
  });
  if (code === 1) throw new KernelMaintenanceLeaseError("maintenance_lock_busy");
  if (code !== 0) throw new KernelMaintenanceLeaseError("maintenance_lock_unavailable");
}

/** Kernel lifetime exclusion survives database loss. Supported production profile is direct Linux. */
export async function acquireKernelMaintenanceLease(
  file: string,
  mode: KernelMaintenanceMode
): Promise<KernelMaintenanceLease> {
  if (process.platform !== "linux" || !["shared", "exclusive"].includes(mode)) throw invalid();
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    await trustedDirectoryChain(file);
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = await handle.stat();
    if (!protectedInode(before)) throw invalid();
    await lockDescriptor(handle.fd, mode);
    await trustedDirectoryChain(file);
    const after = await lstat(file);
    if (
      !protectedInode(after) ||
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.ctimeMs !== after.ctimeMs
    )
      throw invalid();
    const held = handle;
    handle = undefined;
    let closing: Promise<void> | undefined;
    return { close: () => (closing ??= held.close()) };
  } catch (error) {
    await handle?.close();
    if (error instanceof KernelMaintenanceLeaseError) throw error;
    throw invalid();
  }
}
