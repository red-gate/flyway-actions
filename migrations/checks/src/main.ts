import * as core from "@actions/core";
import { getFlywayDetails } from "@flyway-actions/shared";
import { runChecks } from "./flyway/run-checks.js";
import { getInputs, maskSecrets } from "./inputs.js";

const run = async (): Promise<void> => {
  try {
    const flyway = await getFlywayDetails();
    if (!flyway.installed) {
      core.setFailed("Flyway is not installed or not in PATH. Run red-gate/setup-flyway before this action.");
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

    const hasBuildEnv = !!inputs.buildEnvironment || !!inputs.buildUrl;
    if (inputs.generateReport && !hasBuildEnv) {
      core.info("No build environment provided. Skipping change report.");
    }

    const flags = {
      code: inputs.generateReport || inputs.failOnCodeReview,
      drift: inputs.generateReport || inputs.failOnDrift,
      changes: inputs.generateReport && hasBuildEnv,
      dryrun: inputs.generateReport,
    };

    if (!flags.code && !flags.drift && !flags.changes && !flags.dryrun) {
      return;
    }

    const exitCode = await runChecks(inputs, flags);

    if (exitCode !== 0) {
      core.setFailed("Flyway checks failed");
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
