import * as core from "@actions/core";
import { getFlywayDetails } from "@flyway-actions/shared/flyway-runner";
import { checkMinimumFlywayVersion } from "@flyway-actions/shared/version-check";
import { deleteDiffArtifact } from "./flyway/cleanup.js";
import { diff } from "./flyway/diff.js";
import { generate } from "./flyway/generate.js";
import { commitAndPush } from "./git/commit.js";
import { getInputs, maskSecrets } from "./inputs.js";
import { writeSummary } from "./write-summary.js";

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
    if (flywayDetails.edition !== "enterprise") {
      core.setFailed(
        `Migration generation requires Flyway Enterprise edition (current edition: ${flywayDetails.edition}).`,
      );
      return;
    }

    const inputs = getInputs();
    maskSecrets(inputs);

    const { artifactPath } = await diff(inputs);

    try {
      const { scripts } = await generate(inputs);

      await commitAndPush(
        inputs,
        scripts.map((s) => s.location),
      );

      await writeSummary({ scripts });
    } finally {
      await deleteDiffArtifact(artifactPath);
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
