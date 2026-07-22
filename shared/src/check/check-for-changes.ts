import type { ErrorOutput } from "../types.js";
import * as core from "@actions/core";
import { parseOutput, runFlyway } from "../flyway-runner.js";

type ChangeItem = {
  operation?: "changes";
  onlyInSource?: unknown[];
  onlyInTarget?: unknown[];
  differences?: unknown[];
};

type CheckChangesOutput = { htmlReport?: string; individualResults?: (ChangeItem & { operation?: string })[] };

type CheckForChangesResult = {
  exitCode: number;
  result?: {
    reportPath?: string;
    changedObjectCount: number;
  };
};

const DOCKER_UNAVAILABLE_ERROR_CODES = new Set(["DOCKER_NOT_INSTALLED", "DOCKER_NOT_RUNNING"]);
const DOCKER_UNSUPPORTED_ENGINE_MESSAGE = "for the `docker` provisioner";

const checkForChanges = async (
  args: string[],
  workingDirectory?: string,
  warnAboutBuildDatabase?: boolean,
): Promise<CheckForChangesResult> => {
  core.startGroup("Running deployment changes report");
  try {
    const result = await runFlyway(args, workingDirectory);

    if (result.exitCode !== 0) {
      const errorOutput = parseOutput<ErrorOutput>(result.stdout);
      if (errorOutput?.error?.errorCode === "COMPARISON_DATABASE_NOT_SUPPORTED") {
        core.info(
          "Deployment changes report could not be generated because advanced comparison features are not supported for this database type.",
        );
        return { exitCode: 0 };
      }
      if (errorOutput?.error?.errorCode === "DOCKER_EULA_NOT_ACCEPTED") {
        core.warning(
          `Deployment changes report skipped: ${errorOutput.error.message ?? "The database vendor's EULA has not been accepted."} Set "build-docker-i-agree-to-the-db-vendors-eula" to "true" to allow Flyway to provision a container for the build environment, or configure "build-environment"/"build-url" to use a database you manage yourself.`,
        );
        return { exitCode: 0 };
      }
      if (errorOutput?.error?.errorCode && DOCKER_UNAVAILABLE_ERROR_CODES.has(errorOutput.error.errorCode)) {
        core.warning(
          `Deployment changes report skipped: ${errorOutput.error.message ?? "Docker is not available on this runner."} Set "build-environment" or "build-url" to configure a build database explicitly.`,
        );
        return { exitCode: 0 };
      }
      if (
        errorOutput?.error?.errorCode === "CONFIGURATION" &&
        errorOutput.error.message?.includes(DOCKER_UNSUPPORTED_ENGINE_MESSAGE)
      ) {
        core.warning(
          `Deployment changes report skipped: ${errorOutput.error.message}. Set "build-environment" or "build-url" to configure a build database explicitly.`,
        );
        return { exitCode: 0 };
      }
      if (errorOutput?.error?.errorCode === "CHECK_BUILD_NO_PROVISIONER" && warnAboutBuildDatabase) {
        core.error(
          'The build database needs to be erasable. Set the "build-ok-to-erase" input to "true" to allow Flyway to erase the build database. Note that this will drop all schema objects and data from the database.',
        );
      } else {
        errorOutput?.error?.message && core.error(errorOutput.error.message);
      }
      return { exitCode: result.exitCode };
    }

    const output = parseOutput<CheckChangesOutput>(result.stdout);

    return {
      exitCode: result.exitCode,
      result: { reportPath: output?.htmlReport, changedObjectCount: countChangedObjects(output) },
    };
  } finally {
    core.endGroup();
  }
};

const countChangedObjects = (output: CheckChangesOutput | undefined): number => {
  const changesResults = output?.individualResults?.filter((r): r is ChangeItem => r.operation === "changes");
  if (!changesResults?.length) {
    return 0;
  }
  return changesResults.reduce(
    (acc, r) => acc + (r.onlyInSource?.length ?? 0) + (r.onlyInTarget?.length ?? 0) + (r.differences?.length ?? 0),
    0,
  );
};

export { checkForChanges };
export type { CheckForChangesResult };
