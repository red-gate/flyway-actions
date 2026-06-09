import type { FlywayAggregateReportsInputs } from "../types.js";
import type { ErrorOutput } from "@flyway-actions/shared/types";
import * as core from "@actions/core";
import { parseExtraArgs, parseOutput, runFlyway } from "@flyway-actions/shared/flyway-runner";

const getAggregateArgs = (inputs: FlywayAggregateReportsInputs): string[] => {
  const args: string[] = [
    "aggregate",
    `-aggregate.reportsFolder=${inputs.reportsFolder}`,
    `-reportFilename=${inputs.reportPath}`,
  ];
  if (inputs.workingDirectory) {
    args.push(`-workingDirectory=${inputs.workingDirectory}`);
  }
  if (inputs.extraArgs) {
    args.push(...parseExtraArgs(inputs.extraArgs));
  }
  return args;
};

const aggregate = async (inputs: FlywayAggregateReportsInputs): Promise<void> => {
  core.startGroup("Running Flyway aggregate-reports");
  try {
    const args = getAggregateArgs(inputs);
    const result = await runFlyway(args, inputs.workingDirectory);

    setOutput(result.exitCode, inputs.reportPath);

    if (result.exitCode !== 0) {
      const errorOutput = parseOutput<ErrorOutput>(result.stdout);
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      throw new Error(`Flyway aggregate failed with exit code ${result.exitCode}`);
    }
  } finally {
    core.endGroup();
  }
};

const setOutput = (exitCode: number, reportPath: string) => {
  core.setOutput("exit-code", exitCode.toString());
  core.setOutput("report-path", reportPath);
};

export { aggregate, getAggregateArgs };
