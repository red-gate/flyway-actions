import * as path from "path";
import * as core from "@actions/core";
import type { FlywayMigrationsDeploymentInputs } from "./types.js";

const getInputs = (): FlywayMigrationsDeploymentInputs => {
  const targetEnvironment = core.getInput("target-environment") || undefined;
  const targetUrl = core.getInput("target-url") || undefined;
  const targetUser = core.getInput("target-user") || undefined;
  const targetPassword = core.getInput("target-password") || undefined;
  const target = core.getInput("target") || undefined;
  const cherryPick = core.getInput("cherry-pick") || undefined;
  const skipDrift = core.getBooleanInput("skip-drift");
  const rawWorkingDirectory = core.getInput("working-directory");
  const workingDirectory = rawWorkingDirectory ? path.resolve(rawWorkingDirectory) : undefined;
  const extraArgs = core.getInput("extra-args") || undefined;

  return {
    targetEnvironment,
    targetUrl,
    targetUser,
    targetPassword,
    target,
    cherryPick,
    skipDrift,
    workingDirectory,
    extraArgs,
  };
};

const maskSecrets = (inputs: FlywayMigrationsDeploymentInputs): void => {
  if (inputs.targetPassword) {
    core.setSecret(inputs.targetPassword);
  }
};

export { getInputs, maskSecrets };
