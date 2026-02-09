import * as core from '@actions/core';
import { getInputs, maskSecrets } from './inputs.js';
import {
  checkFlywayInstalled,
  getFlywayInfo,
  runFlyway,
  parseFlywayOutput,
  setOutputs,
} from './flyway-runner.js';

const run = async (): Promise<void> => {
  try {
    const flywayInstalled = await checkFlywayInstalled();
    if (!flywayInstalled) {
      throw new Error(
        'Flyway is not installed or not in PATH. Please run red-gate/setup-flyway@v1 before this action.'
      );
    }

    const flywayInfo = await getFlywayInfo();
    core.info(`Using Flyway ${flywayInfo.edition} edition ${flywayInfo.version}`);

    const inputs = getInputs();

    if (flywayInfo.edition === 'community') {
      inputs.saveSnapshot = undefined;
    }

    maskSecrets(inputs);

    const result = await runFlyway(inputs);

    if (result.stdout) {
      core.info(result.stdout);
    }
    if (result.stderr) {
      core.warning(result.stderr);
    }

    const { migrationsApplied, schemaVersion } = parseFlywayOutput(result.stdout);

    setOutputs({
      exitCode: result.exitCode,
      flywayVersion: flywayInfo.version,
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
