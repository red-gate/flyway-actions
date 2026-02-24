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

    const exitCode = result.exitCode;
    let driftDetected: boolean | undefined;
    if (exitCode === 0) {
      driftDetected = false;
    } else {
      const errorOutput = parseErrorOutput(result.stdout);
      if (errorOutput?.error?.message?.includes("Drift detected")) {
        driftDetected = true;
      }
    }

    core.setOutput("exit-code", exitCode.toString());
    if (driftDetected !== undefined) {
      core.setOutput("drift-detected", driftDetected.toString());
    }

    return !!driftDetected;
  } finally {
    core.endGroup();
  }
};

export { checkForDrift, getCheckDriftArgs };
