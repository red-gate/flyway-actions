import type { FlywayMigrationsGenerateInputs } from "../types.js";
import type { ErrorOutput } from "@flyway-actions/shared/types";
import * as core from "@actions/core";
import { parseOutput, runFlyway } from "@flyway-actions/shared/flyway-runner";
import { getDiffArgs } from "./arg-builders.js";

const diff = async (inputs: FlywayMigrationsGenerateInputs): Promise<void> => {
  core.startGroup("Running diff");
  try {
    const args = getDiffArgs(inputs);
    const result = await runFlyway(args, inputs.workingDirectory);

    if (result.exitCode !== 0) {
      const errorOutput = parseOutput<ErrorOutput>(result.stdout);
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      core.setOutput("exit-code", result.exitCode.toString());
      throw new Error(`Flyway diff failed with exit code ${result.exitCode}`);
    }
  } finally {
    core.endGroup();
  }
};

export { diff };
