import * as core from "@actions/core";
import * as exec from "@actions/exec";
import type { FlywayEdition, FlywayDetails, FlywayMigrationsDeploymentInputs, FlywayRunResult } from "../types.js";
import { createStdoutListener, createStdoutStderrListeners } from "../utils.js";

const buildCommonArgs = (inputs: FlywayMigrationsDeploymentInputs): string[] => {
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

  if (inputs.workingDirectory) {
    args.push(`-workingDirectory=${inputs.workingDirectory}`);
  }

  if (inputs.extraArgs) {
    args.push(...parseExtraArgs(inputs.extraArgs));
  }

  return args;
};

const parseExtraArgs = (extraArgs: string): string[] => {
  const args: string[] = [];
  let current = "";
  let inQuotes = false;
  let quoteChar = "";

  for (let i = 0; i < extraArgs.length; i++) {
    const char = extraArgs[i];

    if ((char === '"' || char === "'") && !inQuotes) {
      inQuotes = true;
      quoteChar = char;
    } else if (char === quoteChar && inQuotes) {
      inQuotes = false;
      quoteChar = "";
    } else if (char === " " && !inQuotes) {
      if (current.trim()) {
        args.push(current.trim());
      }
      current = "";
    } else {
      current += char;
    }
  }

  if (current.trim()) {
    args.push(current.trim());
  }

  return args;
};

const getFlywayDetails = async (): Promise<FlywayDetails> => {
  try {
    const { listener, getOutput } = createStdoutListener();

    await exec.exec("flyway", ["--version"], {
      silent: true,
      listeners: { stdout: listener },
    });

    const stdout = getOutput();
    const match = stdout.match(/Flyway\s+(Community|Teams|Enterprise)\s+Edition/);
    return {
      installed: true,
      edition: (match ? match[1].toLowerCase() : "community") as FlywayEdition,
    };
  } catch {
    return { installed: false };
  }
};

const runFlyway = async (args: string[], cwd?: string): Promise<FlywayRunResult> => {
  const { listeners, getOutput } = createStdoutStderrListeners();

  core.info(`Running: flyway ${maskArgsForLog(args).join(" ")}`);

  const options: exec.ExecOptions = {
    ignoreReturnCode: true,
    listeners,
  };

  if (cwd) {
    options.cwd = cwd;
  }

  const exitCode = await exec.exec("flyway", args, options);
  const { stdout, stderr } = getOutput();

  return { exitCode, stdout, stderr };
};

const maskArgsForLog = (args: string[]): string[] => {
  const sensitivePatterns = [/^-url=/i, /^-user=/i, /password.*=/i, /token.*=/i];

  return args.map((arg) => {
    for (const pattern of sensitivePatterns) {
      if (pattern.test(arg)) {
        const eqIndex = arg.indexOf("=");
        return arg.substring(0, eqIndex + 1) + "***";
      }
    }
    return arg;
  });
};

export { buildCommonArgs, parseExtraArgs, getFlywayDetails, runFlyway, maskArgsForLog };
