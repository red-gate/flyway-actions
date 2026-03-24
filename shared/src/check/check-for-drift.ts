import type { ErrorOutput } from "../types.js";
import * as core from "@actions/core";
import { parseOutput, runFlyway } from "../flyway-runner.js";

type DriftItem = {
  operation?: "drift";
  onlyInSource?: unknown[];
  onlyInTarget?: unknown[];
  differences?: unknown[];
  driftResolutionFolder?: string;
  driftDetected: boolean;
  driftCheckSkipped: boolean;
};

type DriftSuccessOutput = { htmlReport?: string; individualResults?: (DriftItem | { operation?: string })[] };

type DriftErrorOutput = { error?: ErrorOutput["error"] & { htmlReport?: string; driftResolutionFolderPath?: string } };

type CheckForDriftResult = {
  exitCode: number;
  result: {
    driftDetected?: boolean;
    comparisonSupported: boolean;
    reportPath?: string;
    driftResolutionFolder?: string;
  };
};

const checkForDrift = async (args: string[], workingDirectory?: string): Promise<CheckForDriftResult> => {
  core.startGroup("Checking for drift");
  try {
    const result = await runFlyway(args, workingDirectory);

    if (result.exitCode !== 0) {
      const errorOutput = parseOutput<DriftErrorOutput>(result.stdout);
      if (errorOutput?.error?.errorCode === "CHECK_DRIFT_DETECTED") {
        return {
          exitCode: result.exitCode,
          result: {
            driftDetected: true,
            comparisonSupported: true,
            reportPath: errorOutput.error.htmlReport,
            driftResolutionFolder: errorOutput.error.driftResolutionFolderPath,
          },
        };
      }
      if (errorOutput?.error?.errorCode === "COMPARISON_DATABASE_NOT_SUPPORTED") {
        core.info(
          "Drift check could not be run because advanced comparison features are not supported for this database type.",
        );
        return { exitCode: 0, result: { comparisonSupported: false } };
      }
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      return { exitCode: result.exitCode, result: { driftDetected: false, comparisonSupported: true } };
    }

    const output = parseOutput<DriftSuccessOutput>(result.stdout);
    const driftResult = output?.individualResults?.find((r): r is DriftItem => r.operation === "drift");
    return {
      exitCode: result.exitCode,
      result: {
        driftDetected: driftResult?.driftDetected,
        comparisonSupported: true,
        reportPath: output?.htmlReport,
        driftResolutionFolder: driftResult?.driftResolutionFolder,
      },
    };
  } finally {
    core.endGroup();
  }
};

export { checkForDrift };
export type { CheckForDriftResult };
