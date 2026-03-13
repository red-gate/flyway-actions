import * as core from "@actions/core";
import { getFlywayDetails } from "@flyway-actions/shared/flyway-runner";
import { runCheckChanges } from "./flyway/check-changes.js";
import { runCheckCode } from "./flyway/check-code.js";
import { runCheckDrift } from "./flyway/check-drift.js";
import { prepare } from "./flyway/prepare.js";
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
      } else {
        const { driftDetected } = await runCheckDrift(inputs);
        if (driftDetected) {
          if (inputs.failOnDrift) {
            core.setFailed("Drift detected. Aborting prepare.");
            return;
          }
          core.warning("Drift detected. Continuing because fail-on-drift is disabled.");
        }
      }
    } else {
      core.info(`Skipping drift check as edition is not Enterprise (actual edition: ${flywayDetails.edition}).`);
    }

    await runCheckChanges(inputs, flywayDetails.edition);

    const { scriptPath } = await prepare(inputs);

    if (!scriptPath) {
      core.warning("No script path returned from prepare. Skipping code review.");
      return;
    }

    const codeReviewResult = await runCheckCode(inputs, scriptPath);
    if (codeReviewResult && codeReviewResult.violationCount > 0 && inputs.failOnCodeReview) {
      core.setOutput("exit-code", "1");
      core.setFailed(`Code review failed with ${codeReviewResult.violationCount} violation(s).`);
      return;
    }
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed(String(error));
    }
  }
};

await run();
