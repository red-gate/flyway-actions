import type { FlywayStatePrepareInputs } from "../types.js";
import type { ErrorOutput } from "@flyway-actions/shared/types";
import * as core from "@actions/core";
import { parseOutput, runFlyway } from "@flyway-actions/shared/flyway-runner";
import { getPrepareArgs } from "./arg-builders.js";

type PrepareOutput = {
  scriptFilename?: string;
  undoFilename?: string;
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
      const errorOutput = parseOutput<ErrorOutput>(result.stdout);
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      setOutput(result.exitCode);
      throw new Error(`Flyway prepare failed with exit code ${result.exitCode}`);
    }

    const output = parseOutput<PrepareOutput>(result.stdout);
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
