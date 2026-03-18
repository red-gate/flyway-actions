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
  if (inputs.skipDeploymentChangesReport && hasBuildInputs(inputs)) {
    core.info('Skipping deployment changes report: "skip-deployment-changes-report" set to true');
    return undefined;
  }
  if (!hasBuildInputs(inputs)) {
    core.info('Skipping deployment changes report: no "build-environment" or "build-url" provided');
    return undefined;
  }
  return [...getCheckCommandArgs(inputs), "-changes", ...getTargetArgs(inputs), ...getBuildEnvironmentArgs(inputs)];
};

const runCheckChanges = async (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition) => {
  const args = getChangesArgs(inputs, edition);
  if (!args) {
    return undefined;
  }
  const result = await checkForChanges(args, inputs.workingDirectory, !inputs.buildOkToErase);
  return { exitCode: result.exitCode, reportPath: result.reportPath, changedObjectCount: result.changedObjectCount };
};

export { runCheckChanges };
