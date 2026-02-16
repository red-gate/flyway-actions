import * as core from "@actions/core";
import { getInputs, maskSecrets } from "./inputs.js";
import { getFlywayDetails } from "@flyway-actions/shared";
import { checkForDrift } from "./flyway/check-for-drift.js";
import { migrate } from "./flyway/migrate.js";

const run = async (): Promise<void> => {
  try {
    const flyway = await getFlywayDetails();
    if (!flyway.installed) {
      core.setFailed("Flyway is not installed or not in PATH. Please run red-gate/setup-flyway before this action.");
      return;
    }
    const inputs = getInputs();
    if (!inputs.targetEnvironment && !inputs.targetUrl) {
      core.setFailed(
        'Either "target-url" or "target-environment" must be provided for Flyway to connect to a database.',
      );
      return;
    }

    maskSecrets(inputs);

    if (flyway.edition === "enterprise") {
      if (inputs.skipDriftCheck) {
        core.info("Skipping drift check.");
      } else {
        const driftDetected = await checkForDrift(inputs);
        if (driftDetected) {
          core.setFailed("Drift detected. Aborting deployment.");
          return;
        }
      }
      inputs.saveSnapshot = true;
    } else {
      core.info(`Skipping drift check as edition is not Enterprise (actual edition: ${flyway.edition}).`);
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

await run();
