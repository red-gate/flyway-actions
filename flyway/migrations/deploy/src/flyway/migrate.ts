import * as core from "@actions/core";
import type { FlywayMigrationsDeploymentInputs } from "../types.js";
import { buildCommonArgs, runFlyway, parseFlywayOutput, setOutputs } from "./flyway-runner.js";

const buildFlywayMigrateArgs = (inputs: FlywayMigrationsDeploymentInputs): string[] => {
  const args: string[] = ["migrate", ...buildCommonArgs(inputs)];

  if (inputs.target) {
    args.push(`-target=${inputs.target}`);
  }

  if (inputs.cherryPick) {
    args.push(`-cherryPick=${inputs.cherryPick}`);
  }

  if (inputs.saveSnapshot) {
    args.push("-saveSnapshot=true");
  }

  return args;
};

const migrate = async (inputs: FlywayMigrationsDeploymentInputs): Promise<void> => {
  const args = buildFlywayMigrateArgs(inputs);
  const result = await runFlyway(args, inputs.workingDirectory);

  if (result.stdout) {
    core.info(result.stdout);
  }
  if (result.stderr) {
    core.warning(result.stderr);
  }

  const { migrationsApplied, schemaVersion } = parseFlywayOutput(result.stdout);

  setOutputs({
    exitCode: result.exitCode,
    migrationsApplied,
    schemaVersion,
  });

  if (result.exitCode !== 0) {
    throw new Error(`Flyway migrate failed with exit code ${result.exitCode}`);
  }
};

export { buildFlywayMigrateArgs, migrate };
