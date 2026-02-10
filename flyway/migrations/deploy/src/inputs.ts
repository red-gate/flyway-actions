import * as core from '@actions/core';
import { FlywayMigrateInputs } from './types.js';

const getInputs = (): FlywayMigrateInputs => {
  const url = core.getInput('url') || undefined;
  const user = core.getInput('user') || undefined;
  const password = core.getInput('password') || undefined;
  const environment = core.getInput('environment') || undefined;
  const target = core.getInput('target') || undefined;
  const cherryPick = core.getInput('cherry-pick') || undefined;
  const saveSnapshot = core.getBooleanInput('save-snapshot');
  const workingDirectory = core.getInput('working-directory') || undefined;
  const extraArgs = core.getInput('extra-args') || undefined;

  return {
    url,
    user,
    password,
    environment,
    target,
    cherryPick,
    saveSnapshot,
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
