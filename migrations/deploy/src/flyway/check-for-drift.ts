import type { FlywayMigrationsDeploymentInputs } from "../types.js";
import * as core from "@actions/core";
import { parseErrorOutput, runFlyway } from "@flyway-actions/shared";
import { getCommonArgs } from "./arg-builders.js";

const getCheckDriftArgs = (inputs: FlywayMigrationsDeploymentInputs): string[] => [
  "check",
  "-drift",
  "-check.failOnDrift=true",
  ...getCommonArgs(inputs),
  "-outputType=json",
  "-outputLogsInJson=true",
];

const checkForDrift = async (inputs: FlywayMigrationsDeploymentInputs): Promise<boolean> => {
  core.startGroup("Checking for drift");
  try {
    const driftArgs = getCheckDriftArgs(inputs);
    const result = await runFlyway(driftArgs, inputs.workingDirectory);

    const exitCode = result.exitCode;
    let driftDetected = false;
    if (exitCode !== 0) {
      const errorOutput = parseErrorOutput(result.stdout);

      if (errorOutput?.error?.message?.includes("Drift detected")) {
        driftDetected = true;
      }
    }

    setDriftOutput(exitCode, driftDetected);

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
