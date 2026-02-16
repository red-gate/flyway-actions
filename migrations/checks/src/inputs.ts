import * as path from "path";
import * as core from "@actions/core";
import type { FlywayMigrationsChecksInputs } from "./types.js";

const getInputs = (): FlywayMigrationsChecksInputs => {
  const targetEnvironment = core.getInput("target-environment") || undefined;
  const targetUrl = core.getInput("target-url") || undefined;
  const targetUser = core.getInput("target-user") || undefined;
  const targetPassword = core.getInput("target-password") || undefined;
  const targetSchemas = core.getInput("target-schemas") || undefined;
  const buildEnvironment = core.getInput("build-environment") || undefined;
  const buildUrl = core.getInput("build-url") || undefined;
  const buildUser = core.getInput("build-user") || undefined;
  const buildPassword = core.getInput("build-password") || undefined;
  const buildSchemas = core.getInput("build-schemas") || undefined;
  const generateReport = core.getBooleanInput("generate-report");
  const failOnDrift = core.getBooleanInput("fail-on-drift");
  const failOnCodeReview = core.getBooleanInput("fail-on-code-review");
  const targetMigrationVersion = core.getInput("target-migration-version") || undefined;
  const cherryPick = core.getInput("cherry-pick") || undefined;
  const rawWorkingDirectory = core.getInput("working-directory");
  const workingDirectory = rawWorkingDirectory ? path.resolve(rawWorkingDirectory) : undefined;
  const extraArgs = core.getInput("extra-args") || undefined;

  return {
    targetEnvironment,
    targetUrl,
    targetUser,
    targetPassword,
    targetSchemas,
    buildEnvironment,
    buildUrl,
    buildUser,
    buildPassword,
    buildSchemas,
    generateReport,
    failOnDrift,
    failOnCodeReview,
    targetMigrationVersion,
    cherryPick,
    workingDirectory,
    extraArgs,
  };
};

const maskSecrets = (inputs: FlywayMigrationsChecksInputs): void => {
  if (inputs.targetPassword) {
    core.setSecret(inputs.targetPassword);
  }
  if (inputs.buildPassword) {
    core.setSecret(inputs.buildPassword);
  }
};

export { getInputs, maskSecrets };
