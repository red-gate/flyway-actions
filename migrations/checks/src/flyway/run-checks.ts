import type { FlywayMigrationsChecksInputs } from "../types.js";
import type { CheckDriftResult } from "./check-drift.js";
import type { FlywayEdition } from "@flyway-actions/shared/types";
import * as core from "@actions/core";
import { resolvePath } from "@flyway-actions/shared/resolve-path";
import { writeSummary } from "../write-summary.js";
import { runCheckChanges } from "./check-changes.js";
import { runCheckCode } from "./check-code.js";
import { runCheckDrift } from "./check-drift.js";
import { runCheckDryrun } from "./check-dryrun.js";

const runChecks = async (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): Promise<void> => {
  const dryrunResult = await runCheckDryrun(inputs, edition);
  const codeResult = await runCheckCode(inputs);
  const driftResult = await runCheckDrift(inputs, edition);
  const changesResult = await runCheckChanges(inputs, edition);
  const results = [dryrunResult, codeResult, driftResult, changesResult];

  const reportFile = results.find((r) => r?.reportPath)?.reportPath;
  core.setOutput("report-path", resolvePath(reportFile ?? "report.html", inputs.workingDirectory));

  const failed = results.find((r) => r !== undefined && r.exitCode !== 0);
  core.setOutput("exit-code", (failed?.exitCode ?? 0).toString());

  await writeSummary({
    dryrun: dryrunResult ? { exitCode: dryrunResult.exitCode } : undefined,
    code: codeResult ? { exitCode: codeResult.exitCode, violationCount: codeResult.violationCount } : undefined,
    driftStatus: getDriftStatus(driftResult),
    changes: changesResult
      ? { exitCode: changesResult.exitCode, changedObjectCount: changesResult.changedObjectCount ?? 0 }
      : undefined,
  });

  if (failed) {
    throw new Error("Flyway checks failed");
  }
};

const getDriftStatus = (driftResult: CheckDriftResult): string | undefined => {
  if (!driftResult) {
    return undefined;
  }
  if (driftResult.driftDetected) {
    return "Drift detected";
  }
  return driftResult.comparisonSupported
    ? !driftResult.driftCheckSkipped
      ? "No drift"
      : "Drift check not run - skipped because no snapshot in database (expected for initial deployment)"
    : "Drift check not run - drift analysis is not supported for this database type";
};

export { runChecks };
