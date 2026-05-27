import type { FlywayMigrationsGenerateInputs } from "./types.js";
import * as path from "path";
import * as core from "@actions/core";

const getInputs = (): FlywayMigrationsGenerateInputs => {
  const rawWorkingDirectory = core.getInput("working-directory");
  const workingDirectory = rawWorkingDirectory ? path.resolve(rawWorkingDirectory) : undefined;

  return {
    source: core.getInput("source") || undefined,
    migrationTypes: core.getInput("migration-types") || undefined,
    migrationDescription: core.getInput("migration-description") || undefined,
    buildEnvironment: core.getInput("build-environment") || undefined,
    buildUrl: core.getInput("build-url") || undefined,
    buildUser: core.getInput("build-user") || undefined,
    buildPassword: core.getInput("build-password") || undefined,
    buildSchemas: core.getInput("build-schemas") || undefined,
    workingDirectory,
    extraArgs: core.getInput("extra-args") || undefined,
    commit: {
      migrations: core.getBooleanInput("commit-migrations"),
      message: core.getInput("commit-message"),
      userName: core.getInput("commit-user-name"),
      userEmail: core.getInput("commit-user-email"),
      branch: core.getInput("commit-branch") || undefined,
    },
  };
};

const maskSecrets = (inputs: FlywayMigrationsGenerateInputs): void => {
  if (inputs.buildPassword) {
    core.setSecret(inputs.buildPassword);
  }
};

export { getInputs, maskSecrets };
