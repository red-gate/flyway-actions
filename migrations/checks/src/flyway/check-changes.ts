import type { Changes, FlywayCheckOutput, FlywayMigrationsChecksInputs } from "../types.js";
import type { FlywayEdition } from "@flyway-actions/shared";
import * as core from "@actions/core";
import { parseErrorOutput, runFlyway } from "@flyway-actions/shared";
import { parseCheckOutput } from "../outputs.js";
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
  core.startGroup("Running Flyway check: deployment changes report");
  try {
    const result = await runFlyway(args, inputs.workingDirectory);
    setChangesOutputs(parseCheckOutput(result.stdout));
    if (result.exitCode !== 0) {
      const errorOutput = parseErrorOutput(result.stdout);
      if (errorOutput?.error?.errorCode === "CHECK_BUILD_NO_PROVISIONER" && !inputs.buildOkToErase) {
        core.error(
          'The build database needs to be erasable. Set the "build-ok-to-erase" input to "true" to allow Flyway to erase the build database. Note that this will drop all schema objects and data from the database.',
        );
      }
    }
    return { exitCode: result.exitCode };
  } finally {
    core.endGroup();
  }
};

const setChangesOutputs = (output: FlywayCheckOutput | undefined): void => {
  const changesResults = output?.individualResults?.filter((r): r is Changes => r.operation === "changes");
  if (changesResults?.length) {
    const changes = changesResults.reduce(
      (acc, r) => acc + (r.onlyInSource?.length ?? 0) + (r.onlyInTarget?.length ?? 0) + (r.differences?.length ?? 0),
      0,
    );
    core.setOutput("changed-object-count", changes.toString());
  }
};

export { getChangesArgs, runCheckChanges, setChangesOutputs };
