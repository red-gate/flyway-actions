import * as core from '@actions/core';
import { getInputs, maskSecrets } from './inputs.js';
import {
  getFlywayDetails,
  buildFlywayMigrateArgs,
  runFlyway,
  parseFlywayOutput,
  setOutputs,
} from './flyway-runner.js';

const run = async (): Promise<void> => {
  try {
    const flyway = await getFlywayDetails();
    if (!flyway.installed) {
      throw new Error(
        'Flyway is not installed or not in PATH. Please run red-gate/setup-flyway@v1 before this action.'
      );
    }
    const inputs = getInputs();

    if (!inputs.url && !inputs.environment) {
      throw new Error(
        'Either "url" or "environment" must be provided for Flyway to connect to a database.'
      );
    }

    if (flyway.edition === 'enterprise') {
      inputs.saveSnapshot = true;
    }

    maskSecrets(inputs);

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
    if (schemaVersion !== 'unknown') {
      core.info(`Schema version: ${schemaVersion}`);
    }
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed('An unexpected error occurred');
    }
  }
};

run();
