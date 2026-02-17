import type { FlywayMigrationsChecksInputs } from "../types.js";
import * as core from "@actions/core";
import { runFlyway } from "@flyway-actions/shared";
import { buildBaseArgs, buildBuildEnvArgs, buildTargetArgs } from "./arg-builders.js";

type CheckFlags = {
  code: boolean;
  drift: boolean;
  changes: boolean;
  dryrun: boolean;
};

const buildCheckArgs = (inputs: FlywayMigrationsChecksInputs, flags: CheckFlags): string[] => {
  const args = ["check"];

  if (flags.code) {
    args.push("-code");
    if (inputs.failOnCodeReview) {
      args.push("-failOnError=true");
    }
  }

  if (flags.drift) {
    args.push("-drift");
    if (inputs.failOnDrift) {
      args.push("-failOnDrift=true");
    }
  }

  if (flags.changes) {
    args.push("-changes");
    args.push(...buildBuildEnvArgs(inputs));
  }

  if (flags.dryrun) {
    args.push("-dryrun");
  }

  args.push(...buildTargetArgs(inputs));
  args.push(...buildBaseArgs(inputs));

  if (inputs.targetMigrationVersion) {
    args.push(`-target=${inputs.targetMigrationVersion}`);
  }

  if (inputs.cherryPick) {
    args.push(`-cherryPick=${inputs.cherryPick}`);
  }

  return args;
};

const runChecks = async (inputs: FlywayMigrationsChecksInputs, flags: CheckFlags): Promise<number> => {
  core.startGroup("Running Flyway checks");
  try {
    const args = buildCheckArgs(inputs, flags);
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
export type { CheckFlags };
