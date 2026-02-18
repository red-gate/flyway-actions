import type { FlywayMigrationsChecksInputs } from "../types.js";
import * as core from "@actions/core";
import { runFlyway } from "@flyway-actions/shared";
import { buildBaseArgs, buildTargetArgs, getBuildEnvironmentArgs, hasBuildInputs } from "./arg-builders.js";

const buildCheckArgs = (inputs: FlywayMigrationsChecksInputs): string[] => {
  const args = ["check", "-dryrun", "-code", "-drift"];

  if (hasBuildInputs(inputs)) {
    args.push("-changes");
  } else {
    core.info('Skipping deployment changes report: no "build-environment" or "build-url" provided');
  }

  if (inputs.failOnCodeReview) {
    args.push("-failOnError=true");
  }

  if (inputs.failOnDrift) {
    args.push("-failOnDrift=true");
  }

  args.push(...buildTargetArgs(inputs));
  args.push(...getBuildEnvironmentArgs(inputs));
  args.push(...buildBaseArgs(inputs));

  if (inputs.targetMigrationVersion) {
    args.push(`-target=${inputs.targetMigrationVersion}`);
  }

  if (inputs.cherryPick) {
    args.push(`-cherryPick=${inputs.cherryPick}`);
  }

  return args;
};

const runChecks = async (inputs: FlywayMigrationsChecksInputs): Promise<number> => {
  core.startGroup("Running Flyway checks");
  try {
    const args = buildCheckArgs(inputs);
    const result = await runFlyway(args, inputs.workingDirectory);

    if (result.stderr) {
      core.error(result.stderr);
    }

    return result.exitCode;
  } finally {
    core.endGroup();
  }
};

export { buildCheckArgs, runChecks };
