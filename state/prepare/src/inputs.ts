import type { FlywayStatePrepareInputs } from "./types.js";
import * as path from "path";
import * as core from "@actions/core";

const getInputs = (): FlywayStatePrepareInputs => {
  const targetEnvironment = core.getInput("target-environment") || undefined;
  const targetUrl = core.getInput("target-url") || undefined;
  const targetUser = core.getInput("target-user") || undefined;
  const targetPassword = core.getInput("target-password") || undefined;
  const targetSchemas = core.getInput("target-schemas") || undefined;
  const generateUndo = core.getBooleanInput("generate-undo");
  const failOnDrift = core.getBooleanInput("fail-on-drift");
  const skipDriftCheck = core.getBooleanInput("skip-drift-check");
  const rawWorkingDirectory = core.getInput("working-directory");
  const workingDirectory = rawWorkingDirectory ? path.resolve(rawWorkingDirectory) : undefined;
  const extraArgs = core.getInput("extra-args") || undefined;
  const driftReportName = core.getInput("drift-report-name") || undefined;

  return {
    targetEnvironment,
    targetUrl,
    targetUser,
    targetPassword,
    targetSchemas,
    generateUndo,
    failOnDrift,
    skipDriftCheck,
    workingDirectory,
    extraArgs,
    driftReportName,
  };
};

const maskSecrets = (inputs: FlywayStatePrepareInputs): void => {
  if (inputs.targetPassword) {
    core.setSecret(inputs.targetPassword);
  }
};

export { getInputs, maskSecrets };
