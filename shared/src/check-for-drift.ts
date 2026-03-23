import type { Drift, FlywayCheckOutput } from "./types.js";
import * as core from "@actions/core";
import { parseDriftErrorOutput, runFlyway } from "./flyway-runner.js";
import { resolvePath } from "./resolve-path.js";

type CheckForDriftOutput = {
  driftDetected: boolean;
  comparisonSupported: boolean;
  reportPath?: string;
  driftResolutionFolder?: string;
};

type CheckForDriftResult = {
  exitCode: number;
  result: CheckForDriftOutput;
};

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
        return {
          exitCode: result.exitCode,
          result: {
            driftDetected: true,
            comparisonSupported: true,
            reportPath: resolvePath(errorOutput.error.htmlReport, workingDirectory),
            driftResolutionFolder: resolvePath(errorOutput.error.driftResolutionFolderPath, workingDirectory),
          },
        };
      }
      if (errorOutput?.error?.errorCode === "COMPARISON_DATABASE_NOT_SUPPORTED") {
        core.info(
          "Drift check could not be run because advanced comparison features are not supported for this database type.",
        );
        return { exitCode: 0, result: { driftDetected: false, comparisonSupported: false } };
      }
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      return { exitCode: result.exitCode, result: { driftDetected: false, comparisonSupported: true } };
    }

    const output = parseCheckOutput(result.stdout);
    const driftResult = output?.individualResults?.find((r): r is Drift => r.operation === "drift");
    return {
      exitCode: result.exitCode,
      result: {
        driftDetected: isDriftDetected(output),
        comparisonSupported: true,
        reportPath: resolvePath(output?.htmlReport, workingDirectory),
        driftResolutionFolder: resolvePath(driftResult?.driftResolutionFolder, workingDirectory),
      },
    };
  } finally {
    core.endGroup();
  }
};

const isDriftDetected = (output: FlywayCheckOutput | undefined): boolean =>
  !!output?.individualResults
    ?.filter((r): r is Drift => r.operation === "drift")
    .some((r) => r.onlyInSource?.length || r.onlyInTarget?.length || r.differences?.length);

export { checkForDrift };
export type { CheckForDriftResult };
