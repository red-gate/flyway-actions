import type { FlywayCheckOutput, FlywayMigrationsChecksInputs } from "../types.js";
import type { FlywayEdition } from "@flyway-actions/shared";
import * as core from "@actions/core";
import { runFlyway } from "@flyway-actions/shared";
import { getBaseArgs, getCheckCommandArgs, getTargetAndVersionArgs } from "./arg-builders.js";

const getDryrunArgs = (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): string[] | undefined => {
  if (edition === "community") {
    core.info("Skipping deployment script review: not available in Community edition");
    return undefined;
  }
  if (inputs.skipDeploymentScriptReview) {
    core.info('Skipping deployment script review: "skip-deployment-script-review" set to true');
    return undefined;
  }
  return [...getCheckCommandArgs(), "-dryrun", ...getTargetAndVersionArgs(inputs), ...getBaseArgs(inputs)];
};

const runDryrunCheck = async (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition) => {
  const args = getDryrunArgs(inputs, edition);
  if (!args) {
    return undefined;
  }
  core.startGroup("Running Flyway check: deployment script review");
  try {
    const result = await runFlyway(args, inputs.workingDirectory);
    return {
      exitCode: result.exitCode,
      output: parseCheckOutput(result.stdout),
      stdout: result.stdout,
    };
  } finally {
    core.endGroup();
  }
};

const parseCheckOutput = (stdout: string): FlywayCheckOutput | undefined => {
  try {
    return JSON.parse(stdout) as FlywayCheckOutput;
  } catch {
    return undefined;
  }
};

export { getDryrunArgs, runDryrunCheck };
