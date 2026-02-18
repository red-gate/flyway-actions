import type { FlywayMigrationsDeploymentInputs } from "../types.js";
import { parseExtraArgs } from "@flyway-actions/shared";

const getCommonArgs = (inputs: FlywayMigrationsDeploymentInputs): string[] => {
  const args: string[] = [];

  if (inputs.targetEnvironment) {
    args.push(`-environment=${inputs.targetEnvironment}`);
  }

  const scoped = inputs.targetEnvironment && inputs.targetEnvironment !== "default";
  const prefix = scoped ? `-environments.${inputs.targetEnvironment}.` : "-";

  if (inputs.targetUrl) {
    args.push(`${prefix}url=${inputs.targetUrl}`);
  }

  if (inputs.targetUser) {
    args.push(`${prefix}user=${inputs.targetUser}`);
  }

  if (inputs.targetPassword) {
    args.push(`${prefix}password=${inputs.targetPassword}`);
  }

  if (inputs.targetSchemas) {
    args.push(`${prefix}schemas=${inputs.targetSchemas}`);
  }

  if (inputs.workingDirectory) {
    args.push(`-workingDirectory=${inputs.workingDirectory}`);
  }

  if (inputs.extraArgs) {
    args.push(...parseExtraArgs(inputs.extraArgs));
  }

  return args;
};

export { getCommonArgs };
