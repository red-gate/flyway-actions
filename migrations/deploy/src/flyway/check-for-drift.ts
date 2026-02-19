import type { FlywayMigrationsDeploymentInputs } from "../types.js";
import * as core from "@actions/core";
import { runFlyway } from "@flyway-actions/shared";
import { getCommonArgs } from "./arg-builders.js";

const getCheckDriftArgs = (inputs: FlywayMigrationsDeploymentInputs): string[] => [
  "check",
  "-drift",
  "-check.failOnDrift=true",
  ...getCommonArgs(inputs),
];

const NO_COMPARISON_SUPPORT = "No comparison capability found that supports both types";
const NO_SNAPSHOT_HISTORY_SUPPORT = "Snapshot history not supported for database type";

const checkForDrift = async (inputs: FlywayMigrationsDeploymentInputs): Promise<boolean> => {
  core.startGroup("Checking for drift");
  try {
    const driftArgs = getCheckDriftArgs(inputs);
    const result = await runFlyway(driftArgs, inputs.workingDirectory);

    if (result.stderr?.includes(NO_COMPARISON_SUPPORT) || result.stderr?.includes(NO_SNAPSHOT_HISTORY_SUPPORT)) {
      core.info(
        "Drift check could not be run because advanced comparison features are not supported for this database type.",
      );
      return false;
    }

    if (result.stderr) {
      core.error(result.stderr);
    }

    const driftDetected = result.exitCode !== 0;
    setDriftOutput(result.exitCode, driftDetected);

    return driftDetected;
  } finally {
    core.endGroup();
  }
};

const setDriftOutput = (exitCode: number, driftDetected: boolean): void => {
  core.setOutput("exit-code", exitCode.toString());
  core.setOutput("drift-detected", driftDetected.toString());
};

export { checkForDrift, getCheckDriftArgs };
