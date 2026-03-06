import type { FlywayStateDeploymentInputs } from "../types.js";
import * as core from "@actions/core";
import { parseErrorOutput, runFlyway } from "@flyway-actions/shared/flyway-runner";
import { getCommonArgs } from "./arg-builders.js";

const getDeployArgs = (inputs: FlywayStateDeploymentInputs): string[] => {
  const args: string[] = ["deploy", ...getCommonArgs(inputs)];
  if (inputs.scriptPath) {
    args.push(`-deploy.scriptFilename=${inputs.scriptPath}`);
  }
  if (inputs.saveSnapshot) {
    args.push("-deploy.saveSnapshot=true");
  }
  return args;
};

const deploy = async (inputs: FlywayStateDeploymentInputs): Promise<void> => {
  core.startGroup("Running state-based deployment");
  try {
    const args = getDeployArgs(inputs);
    const result = await runFlyway(args, inputs.workingDirectory);

    if (result.exitCode !== 0) {
      const errorOutput = parseErrorOutput(result.stdout);
      if (errorOutput?.error?.errorCode === "COMPARISON_DATABASE_NOT_SUPPORTED") {
        core.info(
          "No snapshot was generated or stored in the target database as snapshots are not supported for this database type.",
        );
        setOutput(0);
        return;
      }
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      setOutput(result.exitCode);
      throw new Error(`Flyway deploy failed with exit code ${result.exitCode}`);
    }

    setOutput(result.exitCode);
  } finally {
    core.endGroup();
  }
};

const setOutput = (exitCode: number) => {
  core.setOutput("exit-code", exitCode.toString());
};

export { deploy, getDeployArgs };
