import type { FlywayMigrationsUndoInputs } from "../types.js";
import * as core from "@actions/core";
import { parseDriftErrorOutput, runFlyway } from "@flyway-actions/shared/flyway-runner";
import { resolvePath } from "@flyway-actions/shared/resolve-path";
import { getCommonArgs } from "./arg-builders.js";

const getCheckDriftArgs = (inputs: FlywayMigrationsUndoInputs): string[] => [
  "check",
  "-drift",
  "-check.failOnDrift=true",
  ...getCommonArgs(inputs),
  ...(inputs.driftReportName ? [`-reportFilename=${inputs.driftReportName}`] : []),
];

type CheckForDriftResult = { driftDetected: boolean; comparisonSupported: boolean };

const checkForDrift = async (inputs: FlywayMigrationsUndoInputs): Promise<CheckForDriftResult> => {
  core.startGroup("Checking for drift");
  try {
    const driftArgs = getCheckDriftArgs(inputs);
    const result = await runFlyway(driftArgs, inputs.workingDirectory);

    if (result.exitCode !== 0) {
      const errorOutput = parseDriftErrorOutput(result.stdout);
      if (errorOutput?.error?.errorCode === "CHECK_DRIFT_DETECTED") {
        const reportPath = resolvePath(errorOutput.error.htmlReport, inputs.workingDirectory);
        const resolutionFolder = resolvePath(errorOutput.error.driftResolutionFolderPath, inputs.workingDirectory);
        setOutput(result.exitCode, true, reportPath, resolutionFolder);
        return { driftDetected: true, comparisonSupported: true };
      }
      if (errorOutput?.error?.errorCode === "COMPARISON_DATABASE_NOT_SUPPORTED") {
        core.info(
          "Drift check could not be run because advanced comparison features are not supported for this database type.",
        );
        setOutput(0);
        return { driftDetected: false, comparisonSupported: false };
      }
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      setOutput(result.exitCode);
      return { driftDetected: false, comparisonSupported: true };
    }

    setOutput(result.exitCode, false);
    return { driftDetected: false, comparisonSupported: true };
  } finally {
    core.endGroup();
  }
};

const setOutput = (exitCode: number, driftDetected?: boolean, reportPath?: string, resolutionFolder?: string) => {
  core.setOutput("exit-code", exitCode.toString());
  driftDetected !== undefined && core.setOutput("drift-detected", driftDetected.toString());
  reportPath !== undefined && core.setOutput("report-path", reportPath);
  resolutionFolder !== undefined && core.setOutput("drift-resolution-folder", resolutionFolder);
};

export { checkForDrift, getCheckDriftArgs };
