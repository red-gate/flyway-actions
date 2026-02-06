import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { FlywayMigrateInputs, FlywayRunResult, FlywayMigrateOutputs } from './types.js';
import { INPUT_DEFINITIONS } from './inputs.js';
import { toCamelCase, createStdoutStderrListeners } from './utils.js';

const buildFlywayArgs = (inputs: FlywayMigrateInputs): string[] => {
  const args: string[] = ['migrate'];

  for (const def of INPUT_DEFINITIONS) {
    const propName = toCamelCase(def.inputName);
    const value = (inputs as Record<string, unknown>)[propName];

    if (value === undefined || value === null) {
      continue;
    }

    switch (def.type) {
      case 'boolean':
        args.push(`-${def.flywayArg}=${value ? 'true' : 'false'}`);
        break;
      default:
        args.push(`-${def.flywayArg}=${value}`);
    }
  }

  if (inputs.extraArgs) {
    const extraArgsArray = parseExtraArgs(inputs.extraArgs);
    args.push(...extraArgsArray);
  }

  return args;
};

const parseExtraArgs = (extraArgs: string): string[] => {
  const args: string[] = [];
  let current = '';
  let inQuotes = false;
  let quoteChar = '';

  for (let i = 0; i < extraArgs.length; i++) {
    const char = extraArgs[i];

    if ((char === '"' || char === "'") && !inQuotes) {
      inQuotes = true;
      quoteChar = char;
    } else if (char === quoteChar && inQuotes) {
      inQuotes = false;
      quoteChar = '';
    } else if (char === ' ' && !inQuotes) {
      if (current.trim()) {
        args.push(current.trim());
      }
      current = '';
    } else {
      current += char;
    }
  }

  if (current.trim()) {
    args.push(current.trim());
  }

  return args;
};

const checkFlywayInstalled = async (): Promise<boolean> => {
  try {
    await exec.exec('flyway', ['--version'], {
      silent: true,
      ignoreReturnCode: true,
    });
    return true;
  } catch {
    return false;
  }
};

const runFlyway = async (inputs: FlywayMigrateInputs): Promise<FlywayRunResult> => {
  const args = buildFlywayArgs(inputs);
  const { listeners, getOutput } = createStdoutStderrListeners();

  core.info(`Running: flyway ${maskArgsForLog(args).join(' ')}`);

  const options: exec.ExecOptions = {
    ignoreReturnCode: true,
    listeners,
  };

  if (inputs.workingDirectory) {
    options.cwd = inputs.workingDirectory;
  }

  const exitCode = await exec.exec('flyway', args, options);
  const { stdout, stderr } = getOutput();

  return { exitCode, stdout, stderr };
};

const maskArgsForLog = (args: string[]): string[] => {
  const sensitivePatterns = [/^-password=/i, /^-user=/i, /^-vault\.token=/i, /^-url=.*password=/i];

  return args.map((arg) => {
    for (const pattern of sensitivePatterns) {
      if (pattern.test(arg)) {
        const eqIndex = arg.indexOf('=');
        return arg.substring(0, eqIndex + 1) + '***';
      }
    }
    return arg;
  });
};

const extractSchemaVersion = (stdout: string): string => {
  const finalVersionMatch = stdout.match(/now\s+at\s+version\s+v?(\d+(?:\.\d+)*)/i);
  if (finalVersionMatch) {
    return finalVersionMatch[1];
  }

  const versionMatch = stdout.match(
    /(?:Schema\s+version|Current\s+version\s+of\s+schema(?:\s+"[^"]*")?):\s*v?(\d+(?:\.\d+)*)/i
  );
  if (versionMatch) {
    return versionMatch[1];
  }

  return 'unknown';
};

const parseFlywayOutput = (
  stdout: string
): {
  migrationsApplied: number;
  schemaVersion: string;
} => {
  let migrationsApplied = 0;
  let schemaVersion = extractSchemaVersion(stdout);

  const migrationsMatch = stdout.match(/Successfully\s+(?:applied|validated)\s+(\d+)\s+migration/i);
  if (migrationsMatch) {
    migrationsApplied = parseInt(migrationsMatch[1], 10);
  }

  try {
    const jsonMatch = stdout.match(/\{[\s\S]*"schemaVersion"[\s\S]*\}/);
    if (jsonMatch) {
      const json = JSON.parse(jsonMatch[0]);
      if (json.migrationsExecuted !== undefined) {
        migrationsApplied = json.migrationsExecuted;
      }
      if (json.schemaVersion) {
        schemaVersion = json.schemaVersion;
      }
    }
  } catch {
    // JSON parsing failed, continue with regex results
  }

  return { migrationsApplied, schemaVersion };
};

const setOutputs = (outputs: FlywayMigrateOutputs): void => {
  core.setOutput('exit-code', outputs.exitCode.toString());
  core.setOutput('migrations-applied', outputs.migrationsApplied.toString());
  core.setOutput('schema-version', outputs.schemaVersion);
};

export {
  buildFlywayArgs,
  parseExtraArgs,
  checkFlywayInstalled,
  runFlyway,
  maskArgsForLog,
  parseFlywayOutput,
  setOutputs,
};
