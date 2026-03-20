import type { Drift, FlywayCheckOutput } from "./types.js";
import * as core from "@actions/core";
import { parseDriftErrorOutput, runFlyway } from "./flyway-runner.js";
import { resolvePath } from "./resolve-path.js";

type CheckForDriftResult = { driftDetected: boolean; comparisonSupported: boolean };

const parseCheckOutput = (stdout: string): FlywayCheckOutput | undefined => {
  try {
    return JSON.parse(stdout) as FlywayCheckOutput;
  } catch {
    return undefined;
  }
};

const checkForDrift = async (args: string[], workingDirectory?: string): Promise<CheckForDriftResult> => {
  core.startGroup("Checking for drift");
  try {
    const result = await runFlyway(args, workingDirectory);

    if (result.exitCode !== 0) {
      const errorOutput = parseDriftErrorOutput(result.stdout);
      if (errorOutput?.error?.errorCode === "CHECK_DRIFT_DETECTED") {
        const reportPath = resolvePath(errorOutput.error.htmlReport, workingDirectory);
        const resolutionFolder = resolvePath(errorOutput.error.driftResolutionFolderPath, workingDirectory);
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

    const output = parseCheckOutput(result.stdout);
    setOutput(result.exitCode, isDriftDetected(output));
    return { driftDetected: isDriftDetected(output), comparisonSupported: true };
  } finally {
    core.endGroup();
  }
};

const isDriftDetected = (output: FlywayCheckOutput | undefined): boolean =>
  !!output?.individualResults
    ?.filter((r): r is Drift => r.operation === "drift")
    .some((r) => r.onlyInSource?.length || r.onlyInTarget?.length || r.differences?.length);

const setOutput = (exitCode: number, driftDetected?: boolean, reportPath?: string, resolutionFolder?: string) => {
  core.setOutput("exit-code", exitCode.toString());
  driftDetected !== undefined && core.setOutput("drift-detected", driftDetected.toString());
  reportPath !== undefined && core.setOutput("report-path", reportPath);
  resolutionFolder !== undefined && core.setOutput("drift-resolution-folder", resolutionFolder);
};

export { checkForDrift };
export type { CheckForDriftResult };
