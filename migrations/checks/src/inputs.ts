import type { FlywayMigrationsChecksInputs } from "./types.js";
import * as path from "path";
import * as core from "@actions/core";

const getInputs = (): FlywayMigrationsChecksInputs => {
  const targetEnvironment = core.getInput("target-environment") || undefined;
  const targetUrl = core.getInput("target-url") || undefined;
  const targetUser = core.getInput("target-user") || undefined;
  const targetPassword = core.getInput("target-password") || undefined;
  const targetSchemas = core.getInput("target-schemas") || undefined;
  const targetMigrationVersion = core.getInput("target-migration-version") || undefined;
  const cherryPick = core.getInput("cherry-pick") || undefined;
  const failOnCodeReview = core.getBooleanInput("fail-on-code-review");
  const rawWorkingDirectory = core.getInput("working-directory");
  const workingDirectory = rawWorkingDirectory ? path.resolve(rawWorkingDirectory) : undefined;
  const extraArgs = core.getInput("extra-args") || undefined;

  return {
    targetEnvironment,
    targetUrl,
    targetUser,
    targetPassword,
    targetSchemas,
    targetMigrationVersion,
    cherryPick,
    failOnCodeReview,
    workingDirectory,
    extraArgs,
  };
};

const maskSecrets = (inputs: FlywayMigrationsChecksInputs): void => {
  if (inputs.targetPassword) {
    core.setSecret(inputs.targetPassword);
  }
};

export { getInputs, maskSecrets };
