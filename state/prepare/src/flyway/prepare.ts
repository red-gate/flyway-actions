import type { FlywayStatePrepareInputs } from "../types.js";
import * as core from "@actions/core";
import { parseErrorOutput, runFlyway } from "@flyway-actions/shared/flyway-runner";
import { getPrepareArgs } from "./arg-builders.js";

type PrepareOutput = {
  scriptFilename?: string;
  undoFilename?: string;
};

const parsePrepareOutput = (stdout: string): PrepareOutput | undefined => {
  try {
    return JSON.parse(stdout) as PrepareOutput;
  } catch {
    return undefined;
  }
};

type PrepareResult = {
  scriptPath?: string;
};

const prepare = async (inputs: FlywayStatePrepareInputs): Promise<PrepareResult> => {
  core.startGroup("Running state-based prepare");
  try {
    const args = getPrepareArgs(inputs);
    const result = await runFlyway(args, inputs.workingDirectory);

    if (result.exitCode !== 0) {
      const errorOutput = parseErrorOutput(result.stdout);
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      setOutput(result.exitCode);
      throw new Error(`Flyway prepare failed with exit code ${result.exitCode}`);
    }

    const output = parsePrepareOutput(result.stdout);
    setOutput(result.exitCode, output?.scriptFilename, output?.undoFilename);
    return { scriptPath: output?.scriptFilename };
  } finally {
    core.endGroup();
  }
};

const setOutput = (exitCode: number, scriptFilename?: string, undoFilename?: string) => {
  core.setOutput("exit-code", exitCode.toString());
  if (scriptFilename) {
    core.setOutput("script-path", scriptFilename);
  }
  if (undoFilename) {
    core.setOutput("undo-script-path", undoFilename);
  }
};

export { prepare };
