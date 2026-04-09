import type { FlywayStateDeploymentInputs } from "./types.js";
import * as path from "path";
import * as core from "@actions/core";

const getInputs = (): FlywayStateDeploymentInputs => {
  const targetEnvironment = core.getInput("target-environment") || undefined;
  const scriptPath =
    core.getInput("script-path") || path.join("deployments", `D__${targetEnvironment ?? "default"}_deployment.sql`);
  const targetUrl = core.getInput("target-url") || undefined;
  const targetUser = core.getInput("target-user") || undefined;
  const targetPassword = core.getInput("target-password") || undefined;
  const targetSchemas = core.getInput("target-schemas") || undefined;
  const skipDriftCheck = core.getBooleanInput("skip-drift-check");
  const skipSnapshot = core.getBooleanInput("skip-snapshot");
  const provisionMode = core.getInput("provision-mode") || undefined;
  const rawWorkingDirectory = core.getInput("working-directory");
  const workingDirectory = rawWorkingDirectory ? path.resolve(rawWorkingDirectory) : undefined;
  const extraArgs = core.getInput("extra-args") || undefined;
  const deploymentReportName =
    core.getInput("deployment-report-name") || `flyway-${targetEnvironment ?? "default"}-deployment-report`;

  return {
    scriptPath,
    targetEnvironment,
    targetUrl,
    targetUser,
    targetPassword,
    targetSchemas,
    skipDriftCheck,
    skipSnapshot,
    provisionMode,
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
