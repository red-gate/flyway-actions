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

const checkForDrift = async (inputs: FlywayMigrationsDeploymentInputs): Promise<boolean> => {
  core.startGroup("Checking for drift");
  try {
    const driftArgs = getCheckDriftArgs(inputs);
    const result = await runFlyway(driftArgs, inputs.workingDirectory);

    const driftDetected = isDriftDetected(result.exitCode, result.stdout);
    setDriftOutput(result.exitCode, driftDetected);
    return !!driftDetected;
  } finally {
    core.endGroup();
  }
};

const isDriftDetected = (exitCode: number, stdout: string): boolean | undefined => {
  if (exitCode !== 0) {
    const errorOutput = parseErrorOutput(stdout);
    if (errorOutput?.error?.message?.includes("Drift detected")) {
      return true;
    }
    return undefined;
  }
  return false;
};

const setDriftOutput = (exitCode: number, driftDetected: boolean | undefined): void => {
  core.setOutput("exit-code", exitCode.toString());
  driftDetected !== undefined && core.setOutput("drift-detected", driftDetected.toString());
};

export { checkForDrift, getCheckDriftArgs };
