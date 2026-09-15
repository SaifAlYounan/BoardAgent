import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { TOOL_IDS } from "../../lib/contracts/src/generated/registry.ids.js";
import { registryData } from "../../lib/contracts/src/generated/registry.data.js";

const ROOT = path.resolve(import.meta.dirname, "../..");

describe("TH-53 permanent-record purge", () => {
  it("exposes no governance purge callable and grants no runtime DELETE authority", () => {
    expect(TOOL_IDS.filter((tool) => /purge|hard_delete/iu.test(tool))).toEqual([]);
    for (const forbidden of [
      "delete_document",
      "delete_vote",
      "delete_minutes",
      "delete_task",
      "delete_audit_chain"
    ]) {
      expect(TOOL_IDS).not.toContain(forbidden);
    }
    expect(TOOL_IDS).toContain("soft_delete_document");
    expect(TOOL_IDS).toContain("delete_export_artifact");

    const migrationDirectory = path.join(ROOT, "lib/db/migrations");
    const migrations = readdirSync(migrationDirectory)
      .filter((name) => name.endsWith(".sql"))
      .map((name) => readFileSync(path.join(migrationDirectory, name), "utf8"))
      .join("\n");
    const deleteGrants = (migrations.match(/\bgrant\s+delete\s+on\b[^;]+;/giu) ?? []).map(
      (statement) => statement.replaceAll(/\s+/gu, " ").toLowerCase()
    );
    expect(deleteGrants).toEqual([
      "grant delete on public.jobs,public.job_attempt_results,public.notification_attempts to boardagent_migrator;"
    ]);
    expect(
      registryData.securityRequirements.find(({ id }) => id === "SR-077")?.requirement
    ).toContain("no physical purge path");
  });
});
