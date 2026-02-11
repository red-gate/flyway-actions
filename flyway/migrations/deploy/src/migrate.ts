import * as core from "@actions/core";
import { FlywayMigrationsDeploymentInputs } from "./types.js";
import { buildFlywayMigrateArgs, runFlyway, parseFlywayOutput, setOutputs } from "./flyway-runner.js";

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

  core.info(`Migration completed successfully. Applied ${migrationsApplied} migration(s).`);
  if (schemaVersion !== "unknown") {
    core.info(`Schema version: ${schemaVersion}`);
  }
};

export { migrate };
