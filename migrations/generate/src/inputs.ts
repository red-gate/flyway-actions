import type { FlywayMigrationsGenerateInputs } from "./types.js";
import * as path from "path";
import * as core from "@actions/core";

const getInputs = (): FlywayMigrationsGenerateInputs => {
  const source = core.getInput("source") || undefined;
  const types = core.getInput("types") || undefined;
  const description = core.getInput("description") || undefined;
  const buildEnvironment = core.getInput("build-environment") || undefined;
  const buildUrl = core.getInput("build-url") || undefined;
  const buildUser = core.getInput("build-user") || undefined;
  const buildPassword = core.getInput("build-password") || undefined;
  const buildSchemas = core.getInput("build-schemas") || undefined;
  const rawWorkingDirectory = core.getInput("working-directory");
  const workingDirectory = rawWorkingDirectory ? path.resolve(rawWorkingDirectory) : undefined;
  const extraArgs = core.getInput("extra-args") || undefined;

  return {
    source,
    types,
    description,
    buildEnvironment,
    buildUrl,
    buildUser,
    buildPassword,
    buildSchemas,
    workingDirectory,
    extraArgs,
  };
};

const maskSecrets = (inputs: FlywayMigrationsGenerateInputs): void => {
  if (inputs.buildPassword) {
    core.setSecret(inputs.buildPassword);
  }
};

export { getInputs, maskSecrets };
