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

    const exitCode = await runChecks(inputs);

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
