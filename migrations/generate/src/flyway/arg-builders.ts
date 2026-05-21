import type { FlywayMigrationsGenerateInputs } from "../types.js";
import { parseExtraArgs } from "@flyway-actions/shared/flyway-runner";

const DEFAULT_BUILD_ENVIRONMENT = "default_build";

const hasBuildInputs = (inputs: FlywayMigrationsGenerateInputs): boolean =>
  !!(inputs.buildEnvironment || inputs.buildUrl);

const getBuildEnvironmentName = (inputs: FlywayMigrationsGenerateInputs): string | undefined => {
  if (!hasBuildInputs(inputs)) {
    return undefined;
  }
  return inputs.buildEnvironment ?? DEFAULT_BUILD_ENVIRONMENT;
};

const getBuildEnvironmentArgs = (inputs: FlywayMigrationsGenerateInputs): string[] => {
  const environmentName = getBuildEnvironmentName(inputs);
  if (!environmentName) {
    return [];
  }
  const args: string[] = [`-environment=${environmentName}`];

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

  return args;
};

const getSharedArgs = (inputs: FlywayMigrationsGenerateInputs): string[] => {
  const args: string[] = [];

  if (inputs.workingDirectory) {
    args.push(`-workingDirectory=${inputs.workingDirectory}`);
  }

  if (inputs.extraArgs) {
    args.push(...parseExtraArgs(inputs.extraArgs));
  }

  return args;
};

const getDiffArgs = (inputs: FlywayMigrationsGenerateInputs): string[] => {
  const args: string[] = ["diff", "-target=migrations", ...getBuildEnvironmentArgs(inputs)];

  if (inputs.source) {
    args.push(`-source=${inputs.source}`);
  }

  const buildEnvironmentName = getBuildEnvironmentName(inputs);
  if (buildEnvironmentName) {
    args.push(`-diff.buildEnvironment=${buildEnvironmentName}`);
  }

  args.push(...getSharedArgs(inputs));

  return args;
};

const getGenerateArgs = (inputs: FlywayMigrationsGenerateInputs): string[] => {
  const args: string[] = ["generate"];

  if (inputs.types) {
    args.push(`-types=${inputs.types}`);
  }

  if (inputs.description) {
    args.push(`-description=${inputs.description}`);
  }

  args.push(...getSharedArgs(inputs));

  return args;
};

export { getDiffArgs, getGenerateArgs };
