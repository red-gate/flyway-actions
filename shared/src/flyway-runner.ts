import type { FlywayDetails, FlywayEdition, FlywayRunResult, FlywayVersionOutput } from "./types.js";
import * as core from "@actions/core";
import * as exec from "@actions/exec";
import { createJsonStderrListener, createStdoutListener, createStdoutStderrListeners } from "./utils.js";

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

const maskArgsForLog = (args: string[]): string[] => {
  const sensitivePatterns = [/^-url=/i, /^-user=/i, /password.*=/i, /token.*=/i];

  return args.map((arg) => {
    for (const pattern of sensitivePatterns) {
      if (pattern.test(arg)) {
        const eqIndex = arg.indexOf("=");
        return `${arg.substring(0, eqIndex + 1)}***`;
      }
    }
    return arg;
  });
};

const runFlyway = async (args: string[], cwd?: string): Promise<FlywayRunResult> => {
  const { listeners, getOutput } = createStdoutStderrListeners();
  const jsonStderrListener = createJsonStderrListener();

  core.info(`Running: flyway ${maskArgsForLog(args).join(" ")}`);

  const options: exec.ExecOptions = {
    silent: args.includes("-outputType=json"),
    ignoreReturnCode: true,
    listeners: {
      stdout: listeners.stdout,
      stderr: (data: Buffer) => (args.includes("-outputType=json") ? jsonStderrListener(data) : listeners.stderr(data)),
    },
    cwd: cwd || undefined,
  };
  const exitCode = await exec.exec("flyway", args, options);

  const { stdout, stderr } = getOutput();
  return { exitCode, stdout, stderr };
};

const getFlywayDetails = async (): Promise<FlywayDetails> => {
  const { listener, getOutput } = createStdoutListener();
  try {
    await exec.exec("flyway", ["version", "-outputType=json"], { silent: true, listeners: { stdout: listener } });

    const result = JSON.parse(getOutput()) as FlywayVersionOutput;
    return { installed: true, edition: (result.edition?.toLowerCase() as FlywayEdition) ?? "community" };
  } catch (error) {
    if (error instanceof Error) {
      core.error(error.message);
    } else {
      core.error(String(error));
    }
    return { installed: false };
  }
};

export { getFlywayDetails, maskArgsForLog, parseExtraArgs, runFlyway };
