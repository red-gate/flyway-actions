import type { FlywayMigrationsUndoInputs } from "../types.js";
import * as core from "@actions/core";
import { checkForDrift } from "@flyway-actions/shared/check-for-drift";
import { getCommonArgs } from "./arg-builders.js";

const getDriftArgs = (inputs: FlywayMigrationsUndoInputs): string[] => [
  "check",
  "-drift",
  "-check.failOnDrift=true",
  ...getCommonArgs(inputs),
  ...(inputs.undoReportName ? [`-reportFilename=${inputs.undoReportName}`] : []),
];

const runCheckDrift = async (inputs: FlywayMigrationsUndoInputs) => {
  const { exitCode, result } = await checkForDrift(getDriftArgs(inputs), inputs.workingDirectory);

  core.setOutput("exit-code", exitCode.toString());
  core.setOutput("drift-detected", result.driftDetected.toString());
  result.reportPath !== undefined && core.setOutput("report-path", result.reportPath);
  result.driftResolutionFolder !== undefined && core.setOutput("drift-resolution-folder", result.driftResolutionFolder);
  return { exitCode, result };
};

export { runCheckDrift };
