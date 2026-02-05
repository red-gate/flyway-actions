import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { FlywayMigrateInputs, FlywayRunResult, FlywayMigrateOutputs } from './types.js';
import { INPUT_DEFINITIONS } from './inputs.js';
import { toCamelCase } from './utils.js';

/**
 * Build the Flyway command arguments from inputs
 */
export const buildFlywayArgs = (inputs: FlywayMigrateInputs): string[] => {
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
      case 'number':
        args.push(`-${def.flywayArg}=${value}`);
        break;
      case 'placeholders':
        if (typeof value === 'object') {
          for (const [key, val] of Object.entries(value as Record<string, string>)) {
            args.push(`-placeholders.${key}=${val}`);
          }
        }
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

/**
 * Parse extra args string into array, handling quoted strings
 */
export const parseExtraArgs = (extraArgs: string): string[] => {
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

/**
 * Check if Flyway is available in PATH
 */
export const checkFlywayInstalled = async (): Promise<boolean> => {
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

/**
 * Get Flyway version
 */
export const getFlywayVersion = async (): Promise<string> => {
  let stdout = '';

  await exec.exec('flyway', ['--version'], {
    silent: true,
    listeners: {
      stdout: (data: Buffer) => {
        stdout += data.toString();
      },
    },
  });

  // Example: "Flyway Community Edition 10.0.0"
  const match = stdout.match(/Flyway\s+(?:Community|Teams|Enterprise)\s+Edition\s+(\d+\.\d+\.\d+)/);
  return match ? match[1] : 'unknown';
};

/**
 * Run the Flyway migrate command
 */
export const runFlyway = async (inputs: FlywayMigrateInputs): Promise<FlywayRunResult> => {
  const args = buildFlywayArgs(inputs);

  let stdout = '';
  let stderr = '';

  core.info(`Running: flyway ${maskArgsForLog(args).join(' ')}`);

  const options: exec.ExecOptions = {
    ignoreReturnCode: true,
    listeners: {
      stdout: (data: Buffer) => {
        stdout += data.toString();
      },
      stderr: (data: Buffer) => {
        stderr += data.toString();
      },
    },
  };

  if (inputs.workingDirectory) {
    options.cwd = inputs.workingDirectory;
  }

  const exitCode = await exec.exec('flyway', args, options);

  return { exitCode, stdout, stderr };
};

/**
 * Mask sensitive values in args for logging
 */
export const maskArgsForLog = (args: string[]): string[] => {
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

/**
 * Parse Flyway output to extract migration information
 */
export const parseFlywayOutput = (
  stdout: string
): {
  migrationsApplied: number;
  schemaVersion: string;
} => {
  let migrationsApplied = 0;
  let schemaVersion = 'unknown';

  const migrationsMatch = stdout.match(/Successfully\s+(?:applied|validated)\s+(\d+)\s+migration/i);
  if (migrationsMatch) {
    migrationsApplied = parseInt(migrationsMatch[1], 10);
  }

  const versionMatch = stdout.match(
    // Example: "Schema version: 2.0" or "Current version of schema "public": 2.0"
    /(?:Schema\s+version|Current\s+version\s+of\s+schema(?:\s+"[^"]*")?):\s*(\S+)/i
  );
  if (versionMatch) {
    schemaVersion = versionMatch[1];
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

/**
 * Set action outputs
 */
export const setOutputs = (outputs: FlywayMigrateOutputs): void => {
  core.setOutput('exit-code', outputs.exitCode.toString());
  core.setOutput('flyway-version', outputs.flywayVersion);
  core.setOutput('migrations-applied', outputs.migrationsApplied.toString());
  core.setOutput('schema-version', outputs.schemaVersion);
};
