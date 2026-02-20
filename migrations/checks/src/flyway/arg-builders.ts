import type { FlywayMigrationsChecksInputs } from "../types.js";
import { parseExtraArgs } from "@flyway-actions/shared";

const DEFAULT_BUILD_ENVIRONMENT = "default_build";

const getCheckCommandArgs = (inputs: FlywayMigrationsChecksInputs): string[] => {
  const args: string[] = ["check", "-outputType=json", "-outputLogsInJson=true"];

  if (inputs.workingDirectory) {
    args.push(`-workingDirectory=${inputs.workingDirectory}`);
  }

  if (inputs.extraArgs) {
    args.push(...parseExtraArgs(inputs.extraArgs));
  }

  return args;
};

const getTargetArgs = (inputs: FlywayMigrationsChecksInputs): string[] => {
  const args = [...getTargetEnvironmentArgs(inputs)];

  if (inputs.targetMigrationVersion) {
    args.push(`-target=${inputs.targetMigrationVersion}`);
  }

  if (inputs.cherryPick) {
    args.push(`-cherryPick=${inputs.cherryPick}`);
  }

  return args;
};

const getTargetEnvironmentArgs = (inputs: FlywayMigrationsChecksInputs): string[] => {
  const args: string[] = [];

  if (inputs.targetEnvironment) {
    args.push(`-environment=${inputs.targetEnvironment}`);
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

const getBuildEnvironmentArgs = (inputs: FlywayMigrationsChecksInputs): string[] => {
  if (!hasBuildInputs(inputs)) {
    return [];
  }

  const environmentName = inputs.buildEnvironment ?? DEFAULT_BUILD_ENVIRONMENT;
  const args: string[] = [];

  args.push(`-check.buildEnvironment=${environmentName}`);

  if (inputs.buildUrl) {
    args.push(`-environments.${environmentName}.url=${inputs.buildUrl}`);
  }

  if (inputs.buildUser) {
    args.push(`-environments.${environmentName}.user=${inputs.buildUser}`);
  }

  if (inputs.buildPassword) {
    args.push(`-environments.${environmentName}.password=${inputs.buildPassword}`);
  }

  if (inputs.buildSchemas) {
    args.push(`-environments.${environmentName}.schemas=${inputs.buildSchemas}`);
  }

  if (inputs.buildOkToErase) {
    args.push(`-environments.${environmentName}.provisioner=clean`);
  }

  return args;
};

const hasBuildInputs = (inputs: FlywayMigrationsChecksInputs): boolean =>
  !!(inputs.buildEnvironment || inputs.buildUrl);

export { getBuildEnvironmentArgs, getCheckCommandArgs, getTargetArgs, getTargetEnvironmentArgs, hasBuildInputs };
