import type { FlywayMigrationsChecksInputs } from "../types.js";
import type { FlywayEdition } from "@flyway-actions/shared/types";
import * as core from "@actions/core";
import { resolvePath } from "@flyway-actions/shared/resolve-path";
import { runCheckChanges } from "./check-changes.js";
import { runCheckCode } from "./check-code.js";
import { runCheckDrift } from "./check-drift.js";
import { runCheckDryrun } from "./check-dryrun.js";

const runChecks = async (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): Promise<void> => {
  const results = [
    await runCheckDryrun(inputs, edition),
    await runCheckCode(inputs),
    await runCheckDrift(inputs, edition),
    await runCheckChanges(inputs, edition),
  ];

  const reportFile = results.find((r) => r?.reportPath)?.reportPath;
  core.setOutput("report-path", resolvePath(reportFile ?? "report.html", inputs.workingDirectory));

  const failed = results.find((r) => r !== undefined && r.exitCode !== 0);
  core.setOutput("exit-code", (failed?.exitCode ?? 0).toString());

  if (failed) {
    throw new Error("Flyway checks failed");
  }
};

export { runChecks };
