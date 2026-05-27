import type { FlywayCommandInputs } from "../types.js";
import { parseExtraArgs } from "@flyway-actions/shared/flyway-runner";

const DEFAULT_BUILD_ENVIRONMENT = "default_build";

const hasBuildInputs = (inputs: FlywayCommandInputs): boolean => !!(inputs.buildEnvironment || inputs.buildUrl);

const getBuildEnvironmentName = (inputs: FlywayCommandInputs): string | undefined => {
  if (!hasBuildInputs(inputs)) {
    return undefined;
  }
  return inputs.buildEnvironment ?? DEFAULT_BUILD_ENVIRONMENT;
};

const getBuildEnvironmentArgs = (inputs: FlywayCommandInputs): string[] => {
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

const getSharedArgs = (inputs: FlywayCommandInputs): string[] => {
  const args: string[] = [];

  if (inputs.workingDirectory) {
    args.push(`-workingDirectory=${inputs.workingDirectory}`);
  }

  if (inputs.extraArgs) {
    args.push(...parseExtraArgs(inputs.extraArgs));
  }

  return args;
};

const getDiffArgs = (inputs: FlywayCommandInputs): string[] => {
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

const getGenerateArgs = (inputs: FlywayCommandInputs): string[] => {
  const args: string[] = ["generate"];

  if (inputs.migrationTypes) {
    args.push(`-types=${inputs.migrationTypes}`);
  }

  if (inputs.migrationDescription) {
    args.push(`-description=${inputs.migrationDescription}`);
  }

  args.push(...getSharedArgs(inputs));

  return args;
};

export { getDiffArgs, getGenerateArgs };
