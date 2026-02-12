import * as core from "@actions/core";
import { getInputs, maskSecrets } from "./inputs.js";
import { getFlywayDetails } from "./flyway/flyway-runner.js";
import { checkForDrift } from "./flyway/check-for-drift.js";
import { migrate } from "./flyway/migrate.js";

const run = async (): Promise<void> => {
  try {
    const flyway = await getFlywayDetails();
    if (!flyway.installed) {
      core.setFailed("Flyway is not installed or not in PATH. Please run red-gate/setup-flyway@v1 before this action.");
      return;
    }

    if (flyway.edition !== "enterprise") {
      core.setFailed("This action requires Flyway Enterprise Edition. Please upgrade to use this action.");
      return;
    }

    const inputs = getInputs();

    if (!inputs.environment && !inputs.url) {
      core.setFailed('Either "url" or "environment" must be provided for Flyway to connect to a database.');
      return;
    }

    maskSecrets(inputs);

    const driftDetected = await checkForDrift(inputs);
    if (driftDetected) {
      core.setFailed("Drift detected: the target database has diverged from the expected state. Aborting migration.");
      return;
    }

    inputs.saveSnapshot = true;
    await migrate(inputs);
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed("An unexpected error occurred");
    }
  }
};

await run();
