import type { FlywayCheckOutput } from "./types.js";

const parseCheckOutput = (stdout: string): FlywayCheckOutput | undefined => {
  try {
    return JSON.parse(stdout) as FlywayCheckOutput;
  } catch {
    return undefined;
  }
};

export { parseCheckOutput };
