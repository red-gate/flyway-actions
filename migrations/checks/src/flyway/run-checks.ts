import type { FlywayMigrationsChecksInputs } from "../types.js";
import type { FlywayEdition } from "@flyway-actions/shared";
import * as path from "node:path";
import * as core from "@actions/core";
import { runCheckChanges } from "./check-changes.js";
import { runCheckCode } from "./check-code.js";
import { runCheckDrift } from "./check-drift.js";
import { runCheckDryrun } from "./check-dryrun.js";

const getReportPath = (inputs: FlywayMigrationsChecksInputs, reportFile?: string): string => {
  const file = reportFile ?? "report.html";
  if (path.isAbsolute(file)) {
    return file;
  }
  return inputs.workingDirectory ? path.join(inputs.workingDirectory, file) : file;
};

const runChecks = async (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): Promise<void> => {
  const results = [
    await runCheckDryrun(inputs, edition),
    await runCheckCode(inputs),
    await runCheckDrift(inputs, edition),
    await runCheckChanges(inputs, edition),
  ];

  const reportFile = results.find((r) => r?.reportPath)?.reportPath;
  core.setOutput("report-path", getReportPath(inputs, reportFile));

  const failed = results.find((r) => r !== undefined && r.exitCode !== 0);
  core.setOutput("exit-code", (failed?.exitCode ?? 0).toString());

  if (failed) {
    throw new Error("Flyway checks failed");
  }
};

export { runChecks };
