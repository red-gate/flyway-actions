import * as core from "@actions/core";
import { getFlywayDetails, uploadReport } from "@flyway-actions/shared";
import { runChecks } from "./flyway/run-checks.js";
import { getInputs, maskSecrets } from "./inputs.js";

const run = async (): Promise<void> => {
  let inputs: ReturnType<typeof getInputs> | undefined;
  try {
    const flywayDetails = await getFlywayDetails();
    if (!flywayDetails.installed) {
      core.setFailed("Flyway is not installed or not in PATH. Run red-gate/setup-flyway before this action.");
      return;
    }
    inputs = getInputs();
    if (!inputs.targetEnvironment && !inputs.targetUrl) {
      core.setFailed(
        'Either "target-url" or "target-environment" must be provided for Flyway to connect to a database.',
      );
      return;
    }

    maskSecrets(inputs);

    const exitCode = await runChecks(inputs, flywayDetails.edition);
    if (exitCode !== 0) {
      core.setFailed("Flyway checks failed");
    }
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed(String(error));
    }
  } finally {
    if (!inputs?.skipHtmlReportUpload) {
      await uploadReport({
        workingDirectory: inputs?.workingDirectory,
        retentionDays: inputs?.reportRetentionDays,
        artifactName: inputs?.reportName,
      });
    }
  }
};

await run();
