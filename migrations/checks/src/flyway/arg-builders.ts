import type { FlywayMigrationsChecksInputs } from "../types.js";
import { parseExtraArgs } from "@flyway-actions/shared";

const buildTargetArgs = (inputs: FlywayMigrationsChecksInputs): string[] => {
  const args: string[] = [];

  if (inputs.targetEnvironment) {
    args.push(`-environment=${inputs.targetEnvironment}`);
  }

  if (inputs.targetUrl) {
    args.push(`-url=${inputs.targetUrl}`);
  }

  if (inputs.targetUser) {
    args.push(`-user=${inputs.targetUser}`);
  }

  if (inputs.targetPassword) {
    args.push(`-password=${inputs.targetPassword}`);
  }

  if (inputs.targetSchemas) {
    args.push(`-schemas=${inputs.targetSchemas}`);
  }

  return args;
};

const buildBaseArgs = (inputs: FlywayMigrationsChecksInputs): string[] => {
  const args: string[] = [];

  if (inputs.workingDirectory) {
    args.push(`-workingDirectory=${inputs.workingDirectory}`);
  }

  if (inputs.extraArgs) {
    args.push(...parseExtraArgs(inputs.extraArgs));
  }

  return args;
};

export { buildBaseArgs, buildTargetArgs };
