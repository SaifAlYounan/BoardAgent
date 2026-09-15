module.exports = {
  forbidden: [
    {
      name: "domain-has-effects",
      comment: "The deterministic domain kernel cannot depend on adapters or effects.",
      severity: "error",
      from: { path: "^lib/domain/src" },
      to: { path: "^(lib/(db|config)|artifacts|scripts)" }
    },
    {
      name: "ruleset-has-effects",
      comment: "Ruleset evaluation is pure.",
      severity: "error",
      from: { path: "^lib/ruleset/src" },
      to: { path: "^(lib/(db|config)|artifacts|scripts)" }
    },
    {
      name: "contracts-depend-upstream",
      comment: "Contracts are the bottom layer.",
      severity: "error",
      from: { path: "^lib/contracts/src" },
      to: { path: "^(lib/(domain|ruleset|audit|authz|db|config)|artifacts|scripts)" }
    },
    {
      name: "no-circular",
      severity: "error",
      from: {},
      to: { circular: true }
    }
  ],
  options: {
    // Preserve sealed test/review artifacts, but inspect the application sources
    // rather than captured third-party bundles inside those ignored directories.
    exclude: { path: "^artifacts/(verification|review|sbom|license-report)(/|$)" },
    doNotFollow: { path: "node_modules" },
    reporterOptions: { dot: { collapsePattern: "node_modules/[^/]+" } }
  }
};
