import type { FlywayMigrationsDeploymentInputs } from "../types.js";
import * as core from "@actions/core";
import { parseErrorOutput, runFlyway } from "@flyway-actions/shared";
import { getCommonArgs } from "./arg-builders.js";

const getCheckDriftArgs = (inputs: FlywayMigrationsDeploymentInputs): string[] => [
  "check",
  "-drift",
  "-check.failOnDrift=true",
  ...getCommonArgs(inputs),
];

type DriftCheckResult = {
  driftDetected: boolean;
  comparisonSupported: boolean;
};

const checkForDrift = async (inputs: FlywayMigrationsDeploymentInputs): Promise<DriftCheckResult> => {
  core.startGroup("Checking for drift");
  try {
    const driftArgs = getCheckDriftArgs(inputs);
    const result = await runFlyway(driftArgs, inputs.workingDirectory);

    let exitCode = result.exitCode;
    let driftDetected: boolean | undefined;
    let comparisonSupported = true;
    if (exitCode === 0) {
      driftDetected = false;
    } else {
      const errorOutput = parseErrorOutput(result.stdout);
      if (errorOutput?.error?.errorCode === "CHECK_DRIFT_DETECTED") {
        driftDetected = true;
      } else if (errorOutput?.error?.errorCode === "COMPARISON_DATABASE_NOT_SUPPORTED") {
        core.info(
          "Drift check could not be run because advanced comparison features are not supported for this database type.",
        );
        exitCode = 0;
        comparisonSupported = false;
      } else {
        errorOutput?.error?.message && core.error(errorOutput.error.message);
      }
    }

    core.setOutput("exit-code", exitCode.toString());
    if (driftDetected !== undefined) {
      core.setOutput("drift-detected", driftDetected.toString());
    }

    return { driftDetected: !!driftDetected, comparisonSupported };
  } finally {
    core.endGroup();
  }
};

export { checkForDrift, getCheckDriftArgs };
