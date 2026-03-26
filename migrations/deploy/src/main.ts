import * as core from "@actions/core";
import { getFlywayDetails } from "@flyway-actions/shared/flyway-runner";
import { runCheckDrift } from "./flyway/check-drift.js";
import { migrate } from "./flyway/migrate.js";
import { getInputs, maskSecrets } from "./inputs.js";
import { writeSummary } from "./write-summary.js";

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

    let driftStatus: string | undefined;

    if (flywayDetails.edition === "enterprise") {
      if (inputs.skipDriftCheck) {
        core.info('Skipping drift check: "skip-drift-check" set to true');
        inputs.saveSnapshot = true;
      } else {
        const {
          result: { driftDetected, driftCheckSkipped, comparisonSupported },
        } = await runCheckDrift(inputs);
        if (driftDetected) {
          driftStatus = "Drift detected";
          await writeSummary({ driftStatus, migrationsApplied: 0, schemaVersion: "unknown" });
          core.setFailed("Drift detected. Aborting deployment.");
          return;
        }
        inputs.saveSnapshot = comparisonSupported;
        driftStatus = comparisonSupported
          ? !driftCheckSkipped
            ? "No drift"
            : "Drift check not run - skipped because no snapshot in database (expected for initial deployment)"
          : "Drift check not run - drift analysis is not supported for this database type";
      }
    } else {
      core.info(`Skipping drift check as edition is not Enterprise (actual edition: ${flywayDetails.edition}).`);
    }

    const { migrationsApplied, schemaVersion } = await migrate(inputs);
    await writeSummary({ driftStatus, migrationsApplied, schemaVersion });
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed(String(error));
    }
  }
};

await run();
