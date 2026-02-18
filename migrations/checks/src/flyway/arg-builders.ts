import type { FlywayMigrationsChecksInputs } from "../types.js";
import { parseExtraArgs } from "@flyway-actions/shared";

const DEFAULT_BUILD_ENVIRONMENT = "default_build";

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

const getBuildEnvironmentArgs = (inputs: FlywayMigrationsChecksInputs): string[] => {
  const args: string[] = [];

  if (inputs.buildEnvironment) {
    args.push(`-buildEnvironment=${inputs.buildEnvironment}`);
  }

  if (inputs.buildUrl) {
    args.push(`-buildUrl=${inputs.buildUrl}`);
  }

  if (inputs.buildUser) {
    args.push(`-buildUser=${inputs.buildUser}`);
  }

  if (inputs.buildPassword) {
    args.push(`-buildPassword=${inputs.buildPassword}`);
  }

  if (inputs.buildSchemas) {
    args.push(`-buildSchemas=${inputs.buildSchemas}`);
  }

  if (inputs.buildOkToErase) {
    const environmentName = inputs.buildEnvironment ?? DEFAULT_BUILD_ENVIRONMENT;
    args.push(`-environments.${environmentName}.flyway.cleanDisabled=false`);
  }

  return args;
};

export { buildBaseArgs, buildTargetArgs, getBuildEnvironmentArgs };
