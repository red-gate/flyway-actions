import type { FlywayStatePrepareInputs } from "../types.js";
import { parseExtraArgs } from "@flyway-actions/shared/flyway-runner";

type EnvironmentFlag = "environment" | "target";

const getTargetConnectionArgs = (inputs: FlywayStatePrepareInputs, environmentFlag: EnvironmentFlag): string[] => {
  const args: string[] = [];

  if (inputs.targetEnvironment) {
    args.push(`-${environmentFlag}=${inputs.targetEnvironment}`);
  }

  const hasEnvironment = inputs.targetEnvironment && inputs.targetEnvironment !== "default";
  const targetPrefix = hasEnvironment ? `-environments.${inputs.targetEnvironment}.` : "-";

  if (inputs.targetUrl) {
    args.push(`${targetPrefix}url=${inputs.targetUrl}`);
  }

  if (inputs.targetUser) {
    args.push(`${targetPrefix}user=${inputs.targetUser}`);
  }

  if (inputs.targetPassword) {
    args.push(`${targetPrefix}password=${inputs.targetPassword}`);
  }

  if (inputs.targetSchemas) {
    args.push(`${targetPrefix}schemas=${inputs.targetSchemas}`);
  }

  return args;
};

const getPrepareArgs = (inputs: FlywayStatePrepareInputs): string[] => {
  const args: string[] = ["prepare", "-source=schemaModel", ...getTargetConnectionArgs(inputs, "target")];

  const types = inputs.generateUndo ? "deploy,undo" : "deploy";
  args.push(`-types=${types}`);

  if (inputs.deploymentScriptName) {
    args.push(`-scriptFilename=deployments/${inputs.deploymentScriptName}.sql`);
  }

  if (inputs.undoScriptName) {
    args.push(`-undoFilename=deployments/${inputs.undoScriptName}.sql`);
  }

  if (inputs.workingDirectory) {
    args.push(`-workingDirectory=${inputs.workingDirectory}`);
  }

  if (inputs.extraArgs) {
    args.push(...parseExtraArgs(inputs.extraArgs));
  }

  return args;
};

const getCommonArgs = (inputs: FlywayStatePrepareInputs): string[] => {
  const args: string[] = [...getTargetConnectionArgs(inputs, "environment")];

  if (inputs.workingDirectory) {
    args.push(`-workingDirectory=${inputs.workingDirectory}`);
  }

  if (inputs.extraArgs) {
    args.push(...parseExtraArgs(inputs.extraArgs));
  }

  return args;
};

const getTargetEnvironmentArgs = (inputs: FlywayStatePrepareInputs): string[] =>
  getTargetConnectionArgs(inputs, "environment");

export { getCommonArgs, getPrepareArgs, getTargetEnvironmentArgs };
