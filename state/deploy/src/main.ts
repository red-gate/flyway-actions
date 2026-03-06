import * as core from "@actions/core";
import { getFlywayDetails } from "@flyway-actions/shared/flyway-runner";
import { checkForDrift } from "./flyway/check-for-drift.js";
import { deploy } from "./flyway/deploy.js";
import { getInputs, maskSecrets } from "./inputs.js";

if (process.env.FLYWAY_INPUTS) {
  for (const [key, value] of Object.entries(JSON.parse(process.env.FLYWAY_INPUTS) as Record<string, string>)) {
    if (value) {
      process.env[`INPUT_${key.toUpperCase()}`] = value;
    }
  }
}

const run = async (): Promise<void> => {
  try {
    const flywayDetails = await getFlywayDetails();
    if (!flywayDetails.installed) {
      core.setFailed("Flyway is not installed or not in PATH. Run red-gate/setup-flyway before this action.");
      return;
    }
    const inputs = getInputs();
    if (!inputs.targetEnvironment && !inputs.targetUrl) {
      core.setFailed(
        'Either "target-environment" or "target-url" must be provided for Flyway to connect to a database.',
      );
      return;
    }

    maskSecrets(inputs);

    if (flywayDetails.edition === "enterprise") {
      if (inputs.skipDriftCheck) {
        core.info('Skipping drift check: "skip-drift-check" set to true');
        inputs.saveSnapshot = true;
      } else {
        const { driftDetected, comparisonSupported } = await checkForDrift(inputs);
        if (driftDetected) {
          core.setFailed("Drift detected. Aborting deployment.");
          return;
        }
        inputs.saveSnapshot = comparisonSupported;
      }
    } else {
      core.info(`Skipping drift check as edition is not Enterprise (actual edition: ${flywayDetails.edition}).`);
    }

    await deploy(inputs);
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed(String(error));
    }
  }
};

await run();
