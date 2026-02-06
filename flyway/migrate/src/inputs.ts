import * as core from '@actions/core';
import { FlywayMigrateInputs, InputDefinition } from './types.js';
import { toCamelCase } from './utils.js';

const INPUT_DEFINITIONS: InputDefinition[] = [
  { inputName: 'url', flywayArg: 'url', type: 'string', isSecret: false },
  { inputName: 'user', flywayArg: 'user', type: 'string', isSecret: false },
  { inputName: 'password', flywayArg: 'password', type: 'string', isSecret: true },
  { inputName: 'config-files', flywayArg: 'configFiles', type: 'string' },
];

const parseBoolean = (value: string | undefined): boolean | undefined => {
  if (value === undefined || value === '') {
    return undefined;
  }
  const lower = value.toLowerCase();
  if (lower === 'true' || lower === 'yes' || lower === '1') {
    return true;
  }
  if (lower === 'false' || lower === 'no' || lower === '0') {
    return false;
  }
  throw new Error(`Invalid boolean value: ${value}`);
};

const getInputs = (): FlywayMigrateInputs => {
  const url = core.getInput('url', { required: true });

  const inputs: FlywayMigrateInputs = { url };

  for (const def of INPUT_DEFINITIONS) {
    if (def.inputName === 'url') continue;

    const rawValue = core.getInput(def.inputName);
    if (!rawValue) continue;

    const propName = toCamelCase(def.inputName);

    switch (def.type) {
      case 'boolean':
        (inputs as Record<string, unknown>)[propName] = parseBoolean(rawValue);
        break;
      default:
        (inputs as Record<string, unknown>)[propName] = rawValue;
    }
  }

  const workingDirectory = core.getInput('working-directory');
  if (workingDirectory) {
    inputs.workingDirectory = workingDirectory;
  }

  const extraArgs = core.getInput('extra-args');
  if (extraArgs) {
    inputs.extraArgs = extraArgs;
  }

  return inputs;
};

const maskSecrets = (inputs: FlywayMigrateInputs): void => {
  if (inputs.password) {
    core.setSecret(inputs.password);
  }
};

export { INPUT_DEFINITIONS, parseBoolean, getInputs, maskSecrets };
