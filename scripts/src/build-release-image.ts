import { spawn } from "node:child_process";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { z } from "zod";

import { sourceTreeSha256 } from "./verify-release.js";

const PROJECT = path.resolve(import.meta.dirname, "../..");
export const DEFAULT_RELEASE_IMAGE = "boardagent:verification-current";
export const DEFAULT_POSTGRES_IMAGE = "boardagent-postgres:verification-current";
export const DEFAULT_CADDY_IMAGE = "boardagent-caddy:verification-current";
export const SOURCE_TREE_LABEL = "org.boardagent.source-tree-sha256";
export const RELEASE_COMPONENT_LABEL = "org.boardagent.release-component";

const ImageReferenceSchema = z
  .string()
  .min(1)
  .max(512)
  .regex(/^\S+$/u)
  .refine(
    (value) =>
      [...value].every((character) => {
        const codePoint = character.codePointAt(0)!;
        return codePoint >= 0x20 && codePoint !== 0x7f;
      }),
    "image reference contains a control character"
  );

interface DockerImageInspection {
  readonly Id?: string;
  readonly Config?: { readonly Labels?: Readonly<Record<string, string>> | null } | null;
}

async function command(
  executable: string,
  args: readonly string[],
  output: "inherit" | "capture"
): Promise<string> {
  const child = spawn(executable, [...args], {
    cwd: PROJECT,
    env: process.env,
    stdio: output === "inherit" ? ["ignore", "inherit", "inherit"] : ["ignore", "pipe", "pipe"]
  });
  let stdout = "";
  let stderr = "";
  if (child.stdout) {
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
  }
  if (child.stderr) {
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
  }
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  if (code !== 0) {
    throw new Error(
      `${executable} ${args[0] ?? "command"} failed${stderr ? `: ${stderr.trim()}` : ""}`
    );
  }
  return stdout;
}

async function inspect(image: string): Promise<DockerImageInspection> {
  const raw = await command("docker", ["image", "inspect", image], "capture");
  const parsed = z.array(z.unknown()).length(1).parse(JSON.parse(raw));
  return parsed[0] as DockerImageInspection;
}

export interface ReleaseImageBinding {
  readonly component: "application" | "postgres" | "caddy";
  readonly image: string;
  readonly imageId: string;
  readonly built: boolean;
}

export interface ReleaseImagesBinding {
  readonly sourceTreeSha256: string;
  readonly application: ReleaseImageBinding;
  readonly postgres: ReleaseImageBinding;
  readonly caddy: ReleaseImageBinding;
}

function assertBinding(
  image: string,
  expectedSourceTreeSha256: string,
  expectedComponent: ReleaseImageBinding["component"],
  inspected: DockerImageInspection
): string {
  const actual = inspected.Config?.Labels?.[SOURCE_TREE_LABEL];
  if (actual !== expectedSourceTreeSha256) {
    throw new Error(
      `release image ${image} is not bound to the current source tree: expected ${expectedSourceTreeSha256}, observed ${actual ?? "missing"}`
    );
  }
  const actualComponent = inspected.Config?.Labels?.[RELEASE_COMPONENT_LABEL];
  if (actualComponent !== expectedComponent) {
    throw new Error(
      `release image ${image} has the wrong component binding: expected ${expectedComponent}, observed ${actualComponent ?? "missing"}`
    );
  }
  if (!inspected.Id || !/^sha256:[0-9a-f]{64}$/u.test(inspected.Id)) {
    throw new Error(`release image ${image} has no valid immutable image identifier`);
  }
  return inspected.Id;
}

async function buildComponent(
  component: ReleaseImageBinding["component"],
  target: "runtime" | "postgres-runtime" | "caddy-runtime",
  image: string,
  sourceTreeSha256: string,
  built: boolean
): Promise<ReleaseImageBinding> {
  if (built) {
    await command(
      "docker",
      [
        "build",
        "--target",
        target,
        "--tag",
        image,
        "--label",
        `${SOURCE_TREE_LABEL}=${sourceTreeSha256}`,
        "--label",
        `${RELEASE_COMPONENT_LABEL}=${component}`,
        "."
      ],
      "inherit"
    );
  }
  return {
    component,
    image,
    imageId: assertBinding(image, sourceTreeSha256, component, await inspect(image)),
    built
  };
}

export async function buildOrVerifyReleaseImage(env: NodeJS.ProcessEnv): Promise<{
  readonly image: string;
  readonly imageId: string;
  readonly sourceTreeSha256: string;
  readonly built: boolean;
}> {
  const configuredImage = env["BOARDAGENT_RELEASE_IMAGE"];
  const image = ImageReferenceSchema.parse(configuredImage ?? DEFAULT_RELEASE_IMAGE);
  const before = await sourceTreeSha256();
  const binding = await buildComponent("application", "runtime", image, before, !configuredImage);
  const after = await sourceTreeSha256();
  if (after !== before) {
    throw new Error("source tree changed while the release image was being built or inspected");
  }
  return {
    image: binding.image,
    imageId: binding.imageId,
    sourceTreeSha256: after,
    built: binding.built
  };
}

export async function buildOrVerifyReleaseImages(
  env: NodeJS.ProcessEnv
): Promise<ReleaseImagesBinding> {
  const configuredApplication = env["BOARDAGENT_RELEASE_IMAGE"];
  const configuredPostgres = env["BOARDAGENT_POSTGRES_IMAGE"];
  const configuredCaddy = env["BOARDAGENT_CADDY_IMAGE"];
  const applicationImage = ImageReferenceSchema.parse(
    configuredApplication ?? DEFAULT_RELEASE_IMAGE
  );
  const postgresImage = ImageReferenceSchema.parse(configuredPostgres ?? DEFAULT_POSTGRES_IMAGE);
  const caddyImage = ImageReferenceSchema.parse(configuredCaddy ?? DEFAULT_CADDY_IMAGE);
  const before = await sourceTreeSha256();
  const application = await buildComponent(
    "application",
    "runtime",
    applicationImage,
    before,
    !configuredApplication
  );
  const postgres = await buildComponent(
    "postgres",
    "postgres-runtime",
    postgresImage,
    before,
    !configuredPostgres
  );
  const caddy = await buildComponent(
    "caddy",
    "caddy-runtime",
    caddyImage,
    before,
    !configuredCaddy
  );
  const after = await sourceTreeSha256();
  if (after !== before) {
    throw new Error("source tree changed while release images were being built or inspected");
  }
  return { sourceTreeSha256: after, application, postgres, caddy };
}

async function main(): Promise<number> {
  const result = await buildOrVerifyReleaseImages(process.env);
  process.stdout.write(
    `${JSON.stringify({ schemaVersion: "boardagent.release-images.v2", status: "verified", ...result })}\n`
  );
  return 0;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    process.exitCode = await main();
  } catch (error) {
    process.stderr.write(
      `${JSON.stringify({
        schemaVersion: "boardagent.release-images.v2",
        status: "failed",
        reasonCode: "release_image_build_or_binding_failed",
        message: error instanceof Error ? error.message : "unknown release image failure"
      })}\n`
    );
    process.exitCode = 1;
  }
}
