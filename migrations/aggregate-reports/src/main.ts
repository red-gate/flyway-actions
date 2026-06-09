import * as core from "@actions/core";
import { getFlywayDetails } from "@flyway-actions/shared/flyway-runner";
import { checkMinimumFlywayVersion } from "@flyway-actions/shared/version-check";
import { aggregate } from "./flyway/aggregate.js";
import { getInputs } from "./inputs.js";

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
    const versionCheck = checkMinimumFlywayVersion(flywayDetails.version);
    if (!versionCheck.success) {
      core.setFailed(versionCheck.message);
      return;
    }

    const inputs = getInputs();
    await aggregate(inputs);
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed(String(error));
    }
  }
};

await run();
