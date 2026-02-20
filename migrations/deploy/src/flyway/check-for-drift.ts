import type { FlywayMigrationsDeploymentInputs } from "../types.js";
import * as core from "@actions/core";
import { parseErrorOutput, runFlyway } from "@flyway-actions/shared";
import { getCommonArgs } from "./arg-builders.js";

const getCheckDriftArgs = (inputs: FlywayMigrationsDeploymentInputs): string[] => [
  "check",
  "-drift",
  "-check.failOnDrift=true",
  "-outputType=json",
  "-outputLogsInJson=true",
  ...getCommonArgs(inputs),
];

const checkForDrift = async (inputs: FlywayMigrationsDeploymentInputs): Promise<boolean> => {
  core.startGroup("Checking for drift");
  try {
    const driftArgs = getCheckDriftArgs(inputs);
    const result = await runFlyway(driftArgs, inputs.workingDirectory);

    const errorOutput = parseErrorOutput(result.stdout);
    const driftDetected =
      result.exitCode === 0 ? false : (errorOutput?.error?.message?.includes("Drift detected") ?? false);
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
