import * as core from "@actions/core";
import type { FlywayMigrationsDeploymentInputs } from "../types.js";
import { buildCommonArgs, runFlyway, setDriftOutput } from "./flyway-runner.js";

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
    setDriftOutput(driftDetected);

    if (!driftDetected) {
      core.info("No drift detected. Proceeding with migration.");
    }

    return driftDetected;
  } finally {
    core.endGroup();
  }
};

export { buildFlywayCheckDriftArgs, checkForDrift };
