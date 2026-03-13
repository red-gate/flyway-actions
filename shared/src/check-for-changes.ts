import * as core from "@actions/core";
import { parseErrorOutput, runFlyway } from "./flyway-runner.js";

type Changes = { operation?: "changes"; onlyInSource?: unknown[]; onlyInTarget?: unknown[]; differences?: unknown[] };

type CheckChangesOutput = { htmlReport?: string; individualResults?: (Changes & { operation?: string })[] };

type CheckForChangesResult = {
  exitCode: number;
  reportPath?: string;
};

const parseOutput = (stdout: string): CheckChangesOutput | undefined => {
  try {
    return JSON.parse(stdout) as CheckChangesOutput;
  } catch {
    return undefined;
  }
};

const checkForChanges = async (
  args: string[],
  workingDirectory?: string,
  warnAboutBuildDatabase?: boolean,
): Promise<CheckForChangesResult> => {
  core.startGroup("Running deployment changes report");
  try {
    const result = await runFlyway(args, workingDirectory);

    if (result.exitCode !== 0) {
      const errorOutput = parseErrorOutput(result.stdout);
      if (errorOutput?.error?.errorCode === "COMPARISON_DATABASE_NOT_SUPPORTED") {
        core.info(
          "Deployment changes report could not be generated because advanced comparison features are not supported for this database type.",
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

    const output = parseOutput(result.stdout);
    setChangesOutputs(output);
    return { exitCode: result.exitCode, reportPath: output?.htmlReport };
  } finally {
    core.endGroup();
  }
};

const setChangesOutputs = (output: CheckChangesOutput | undefined): void => {
  const changesResults = output?.individualResults?.filter((r): r is Changes => r.operation === "changes");
  if (changesResults?.length) {
    const changes = changesResults.reduce(
      (acc, r) => acc + (r.onlyInSource?.length ?? 0) + (r.onlyInTarget?.length ?? 0) + (r.differences?.length ?? 0),
      0,
    );
    core.setOutput("changed-object-count", changes.toString());
  }
};

export { checkForChanges };
export type { CheckForChangesResult };
