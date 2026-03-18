import type { FlywayStateDeploymentInputs } from "./types.js";
import * as path from "path";
import * as core from "@actions/core";

const getInputs = (): FlywayStateDeploymentInputs => {
  const scriptPath = core.getInput("script-path") || undefined;
  const targetEnvironment = core.getInput("target-environment") || undefined;
  const targetUrl = core.getInput("target-url") || undefined;
  const targetUser = core.getInput("target-user") || undefined;
  const targetPassword = core.getInput("target-password") || undefined;
  const targetSchemas = core.getInput("target-schemas") || undefined;
  const skipDriftCheck = core.getBooleanInput("skip-drift-check");
  const rawWorkingDirectory = core.getInput("working-directory");
  const workingDirectory = rawWorkingDirectory ? path.resolve(rawWorkingDirectory) : undefined;
  const extraArgs = core.getInput("extra-args") || undefined;
  const deploymentReportName = core.getInput("deployment-report-name") || undefined;

  return {
    scriptPath,
    targetEnvironment,
    targetUrl,
    targetUser,
    targetPassword,
    targetSchemas,
    skipDriftCheck,
    workingDirectory,
    extraArgs,
    deploymentReportName,
  };
};

const maskSecrets = (inputs: FlywayStateDeploymentInputs): void => {
  if (inputs.targetPassword) {
    core.setSecret(inputs.targetPassword);
  }
};

export { getInputs, maskSecrets };
