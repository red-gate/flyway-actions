import * as core from "@actions/core";
import { getInputs, maskSecrets } from "./inputs.js";
import { getFlywayDetails } from "./flyway-runner.js";
import { checkForDrift } from "./check-for-drift.js";
import { migrate } from "./migrate.js";

const run = async (): Promise<void> => {
  try {
    const flyway = await getFlywayDetails();
    if (!flyway.installed) {
      throw new Error(
        "Flyway is not installed or not in PATH. Please run red-gate/setup-flyway@v1 before this action.",
      );
    }
    const inputs = getInputs();

    if (!inputs.url && !inputs.environment) {
      throw new Error('Either "url" or "environment" must be provided for Flyway to connect to a database.');
    }

    maskSecrets(inputs);

    if (flyway.edition === "enterprise") {
      const driftDetected = await checkForDrift(inputs);
      if (driftDetected) {
        core.setFailed("Drift detected: the target database has diverged from the expected state. Aborting migration.");
        return;
      }
      inputs.saveSnapshot = true;
    }

    await migrate(inputs);
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed("An unexpected error occurred");
    }
  }
};

run();
