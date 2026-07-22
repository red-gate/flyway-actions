import type { FlywayMigrationsChecksInputs } from "../types.js";
import type { FlywayEdition } from "@flyway-actions/shared/types";
import * as core from "@actions/core";
import { checkForChanges } from "@flyway-actions/shared/check-for-changes";
import { getBuildEnvironmentArgs, getCheckCommandArgs, getTargetArgs, hasBuildInputs } from "./arg-builders.js";

const getChangesArgs = (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): string[] | undefined => {
  if (edition !== "enterprise") {
    core.info(
      `Skipping deployment changes report: not available in ${edition === "community" ? "Community" : "Teams"} edition`,
    );
    return undefined;
  }
  if (inputs.skipDeploymentChangesReport) {
    core.info('Skipping deployment changes report: "skip-deployment-changes-report" set to true');
    return undefined;
  }
  if (!hasBuildInputs(inputs)) {
    core.info(
      'No "build-environment" or "build-url" provided: defaulting to a disposable Docker-provisioned build database matching the target database engine. Requires Docker to be available on the runner; the deployment changes report will be skipped if it is not.',
    );
  }
  return [...getCheckCommandArgs(inputs), "-changes", ...getTargetArgs(inputs), ...getBuildEnvironmentArgs(inputs)];
};

const runCheckChanges = async (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition) => {
  const args = getChangesArgs(inputs, edition);
  if (!args) {
    return undefined;
  }
  const { exitCode, result } = await checkForChanges(args, inputs.workingDirectory, !inputs.buildOkToErase);
  result && core.setOutput("changed-object-count", result.changedObjectCount.toString());

  return { exitCode, reportPath: result?.reportPath, changedObjectCount: result?.changedObjectCount };
};

export { runCheckChanges };
