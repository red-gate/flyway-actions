import type { FlywayCheckOutput, FlywayMigrationsChecksInputs } from "../types.js";
import type { ErrorOutput, FlywayEdition } from "@flyway-actions/shared/types";
import * as core from "@actions/core";
import { parseOutput, runFlyway } from "@flyway-actions/shared/flyway-runner";
import { getCheckCommandArgs, getTargetArgs } from "./arg-builders.js";

const getDryrunArgs = (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): string[] | undefined => {
  if (edition === "community") {
    core.info("Skipping deployment script review: not available in Community edition");
    return undefined;
  }
  if (inputs.skipDeploymentScriptReview) {
    core.info('Skipping deployment script review: "skip-deployment-script-review" set to true');
    return undefined;
  }
  return [...getCheckCommandArgs(inputs), "-dryrun", ...getTargetArgs(inputs)];
};

const runCheckDryrun = async (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition) => {
  const args = getDryrunArgs(inputs, edition);
  if (!args) {
    return undefined;
  }
  core.startGroup("Running Flyway check: deployment script review");
  try {
    const result = await runFlyway(args, inputs.workingDirectory);
    if (result.exitCode !== 0) {
      const errorOutput = parseOutput<ErrorOutput>(result.stdout);
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      return { exitCode: result.exitCode };
    }
    const output = parseOutput<FlywayCheckOutput>(result.stdout);
    return { exitCode: result.exitCode, reportPath: output?.htmlReport };
  } finally {
    core.endGroup();
  }
};

export { getDryrunArgs, runCheckDryrun };
