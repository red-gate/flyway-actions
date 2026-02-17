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

const buildBuildEnvArgs = (inputs: FlywayMigrationsChecksInputs): string[] => {
  const args: string[] = [];
  const envName = inputs.buildEnvironment || "build";

  if (inputs.buildEnvironment) {
    args.push(`-buildEnvironment=${inputs.buildEnvironment}`);
  }

  if (inputs.buildUrl) {
    if (!inputs.buildEnvironment) {
      args.push(`-buildEnvironment=${envName}`);
    }
    args.push(`-environments.${envName}.url=${inputs.buildUrl}`);
  }

  if (inputs.buildUser) {
    args.push(`-environments.${envName}.user=${inputs.buildUser}`);
  }

  if (inputs.buildPassword) {
    args.push(`-environments.${envName}.password=${inputs.buildPassword}`);
  }

  if (inputs.buildSchemas) {
    args.push(`-environments.${envName}.schemas=${inputs.buildSchemas}`);
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

export { buildBaseArgs, buildBuildEnvArgs, buildTargetArgs };
