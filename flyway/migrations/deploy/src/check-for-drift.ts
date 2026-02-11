import * as core from "@actions/core";
import { FlywayMigrationsDeploymentInputs } from "./types.js";
import { buildFlywayCheckDriftArgs, runFlyway, setDriftOutput } from "./flyway-runner.js";

const checkForDrift = async (inputs: FlywayMigrationsDeploymentInputs): Promise<boolean> => {
  core.info("Running drift check before migration...");
  const driftArgs = buildFlywayCheckDriftArgs(inputs);
  const result = await runFlyway(driftArgs, inputs.workingDirectory);

  if (result.stdout) {
    core.info(result.stdout);
  }
  if (result.stderr) {
    core.warning(result.stderr);
  }

  const driftDetected = result.exitCode !== 0;
  setDriftOutput(driftDetected);

  if (!driftDetected) {
    core.info("No drift detected. Proceeding with migration.");
  }

  return driftDetected;
};

export { checkForDrift };
