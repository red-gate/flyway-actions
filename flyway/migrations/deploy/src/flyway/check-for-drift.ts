import * as core from "@actions/core";
import type { FlywayMigrationsDeploymentInputs } from "../types.js";
import { buildCommonArgs, runFlyway } from "./flyway-runner.js";

const buildFlywayCheckDriftArgs = (inputs: FlywayMigrationsDeploymentInputs): string[] => {
  return ["check", "-drift", "-failOnDrift=true", ...buildCommonArgs(inputs)];
};

const checkForDrift = async (inputs: FlywayMigrationsDeploymentInputs): Promise<boolean> => {
  core.startGroup("Checking for drift");
  try {
    const driftArgs = buildFlywayCheckDriftArgs(inputs);
    const result = await runFlyway(driftArgs, inputs.workingDirectory);

    if (result.stderr) {
      core.error(result.stderr);
    }

    const driftDetected = result.exitCode !== 0;
    setDriftOutput(result.exitCode, driftDetected);

    if (!driftDetected) {
      core.info("No drift detected. Proceeding with migration.");
    }

    return driftDetected;
  } finally {
    core.endGroup();
  }
};

const setDriftOutput = (exitCode: number, driftDetected: boolean): void => {
  core.setOutput("exit-code", exitCode.toString());
  core.setOutput("drift-detected", driftDetected.toString());
};

export { buildFlywayCheckDriftArgs, checkForDrift };
