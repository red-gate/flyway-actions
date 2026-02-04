import * as core from '@actions/core';
import { getInputs, maskSecrets } from './inputs.js';
import {
  checkFlywayInstalled,
  getFlywayVersion,
  runFlyway,
  parseFlywayOutput,
  setOutputs,
} from './flyway-runner.js';

async function run(): Promise<void> {
  try {
    // Check if Flyway is installed
    const flywayInstalled = await checkFlywayInstalled();
    if (!flywayInstalled) {
      throw new Error(
        'Flyway is not installed or not in PATH. Please run red-gate/setup-flyway@v1 before this action.'
      );
    }

    // Get Flyway version
    const flywayVersion = await getFlywayVersion();
    core.info(`Using Flyway version: ${flywayVersion}`);

    // Parse inputs
    const inputs = getInputs();

    // Mask sensitive values
    maskSecrets(inputs);

    // Run Flyway migrate
    const result = await runFlyway(inputs);

    // Log output
    if (result.stdout) {
      core.info(result.stdout);
    }
    if (result.stderr) {
      core.warning(result.stderr);
    }

    // Parse output for migration info
    const { migrationsApplied, schemaVersion } = parseFlywayOutput(result.stdout);

    // Set outputs
    setOutputs({
      exitCode: result.exitCode,
      flywayVersion,
      migrationsApplied,
      schemaVersion,
    });

    // Check exit code
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
}

run();
