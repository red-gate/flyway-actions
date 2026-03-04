import type { CodeErrorOutput, FlywayCheckOutput } from "./types.js";

const parseCheckOutput = (stdout: string): FlywayCheckOutput | undefined => {
  try {
    return JSON.parse(stdout) as FlywayCheckOutput;
  } catch {
    return undefined;
  }
};

const parseCodeErrorOutput = (stdout: string): CodeErrorOutput | undefined => {
  try {
    return JSON.parse(stdout) as CodeErrorOutput;
  } catch {
    return undefined;
  }
};

export { parseCheckOutput, parseCodeErrorOutput };
