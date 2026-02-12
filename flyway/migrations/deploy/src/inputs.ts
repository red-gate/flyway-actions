import * as path from "path";
import * as core from "@actions/core";
import type { FlywayMigrationsDeploymentInputs } from "./types.js";

const getInputs = (): FlywayMigrationsDeploymentInputs => {
  const environment = core.getInput("environment") || undefined;
  const url = core.getInput("url") || undefined;
  const user = core.getInput("user") || undefined;
  const password = core.getInput("password") || undefined;
  const target = core.getInput("target") || undefined;
  const cherryPick = core.getInput("cherry-pick") || undefined;
  const skipDrift = core.getBooleanInput("skip-drift");
  const rawWorkingDirectory = core.getInput("working-directory");
  const workingDirectory = rawWorkingDirectory ? path.resolve(rawWorkingDirectory) : undefined;
  const extraArgs = core.getInput("extra-args") || undefined;

  return {
    environment,
    url,
    user,
    password,
    target,
    cherryPick,
    skipDrift,
    workingDirectory,
    extraArgs,
  };
};

const maskSecrets = (inputs: FlywayMigrationsDeploymentInputs): void => {
  if (inputs.password) {
    core.setSecret(inputs.password);
  }
};

export { getInputs, maskSecrets };
