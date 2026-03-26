import * as core from "@actions/core";
import { getFlywayDetails } from "@flyway-actions/shared/flyway-runner";
import { runCheckChanges } from "./flyway/check-changes.js";
import { runCheckCode } from "./flyway/check-code.js";
import { runCheckDrift } from "./flyway/check-drift.js";
import { prepare } from "./flyway/prepare.js";
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
    if (flywayDetails.edition !== "enterprise") {
      core.setFailed(
        `State-based deployments require Flyway Enterprise edition (current edition: ${flywayDetails.edition}).`,
      );
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

    if (inputs.skipDriftCheck) {
      core.info('Skipping drift check: "skip-drift-check" set to true');
    } else {
      const {
        result: { driftDetected, driftCheckSkipped, comparisonSupported },
      } = await runCheckDrift(inputs);
      if (driftDetected) {
        driftStatus = "Drift detected";
        if (inputs.failOnDrift) {
          await writeSummary({ driftStatus });
          core.setFailed("Drift detected. Aborting prepare.");
          return;
        }
        core.warning("Drift detected. Continuing because fail-on-drift is disabled.");
      } else {
        driftStatus = comparisonSupported
          ? !driftCheckSkipped
            ? "No drift"
            : "Drift check not run - skipped because no snapshot in database (expected for initial deployment)"
          : "Drift check not run - drift analysis is not supported for this database type";
      }
    }

    const changesResult = await runCheckChanges(inputs, flywayDetails.edition);

    const { scriptPath } = await prepare(inputs);

    if (!scriptPath) {
      core.warning("No script path returned from prepare. Skipping code review.");
      await writeSummary({
        driftStatus,
        changes: changesResult?.result
          ? { exitCode: changesResult.exitCode, changedObjectCount: changesResult.result.changedObjectCount }
          : undefined,
      });
      return;
    }

    const codeReviewResult = await runCheckCode(inputs, scriptPath);

    await writeSummary({
      driftStatus,
      code: codeReviewResult
        ? { exitCode: codeReviewResult.exitCode, violationCount: codeReviewResult.result.violationCount }
        : undefined,
      changes: changesResult?.result
        ? { exitCode: changesResult.exitCode, changedObjectCount: changesResult.result.changedObjectCount }
        : undefined,
    });

    if (codeReviewResult && codeReviewResult.result.violationCount > 0 && inputs.failOnCodeReview) {
      core.setOutput("exit-code", "1");
      core.setFailed(`Code review failed with ${codeReviewResult.result.violationCount} violation(s).`);
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
