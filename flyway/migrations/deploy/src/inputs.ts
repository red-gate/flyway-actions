import * as path from 'path';
import * as core from '@actions/core';
import { FlywayMigrateInputs } from './types.js';

const getInputs = (): FlywayMigrateInputs => {
  const url = core.getInput('url') || undefined;
  const user = core.getInput('user') || undefined;
  const password = core.getInput('password') || undefined;
  const environment = core.getInput('environment') || undefined;
  const target = core.getInput('target') || undefined;
  const cherryPick = core.getInput('cherry-pick') || undefined;
  const rawWorkingDirectory = core.getInput('working-directory');
  const workingDirectory = rawWorkingDirectory ? path.resolve(rawWorkingDirectory) : undefined;
  const extraArgs = core.getInput('extra-args') || undefined;

  return {
    url,
    user,
    password,
    environment,
    target,
    cherryPick,
    workingDirectory,
    extraArgs,
  };
};

const maskSecrets = (inputs: FlywayMigrateInputs): void => {
  if (inputs.password) {
    core.setSecret(inputs.password);
  }
};

export { getInputs, maskSecrets };
