import type { FlywayAggregateReportsInputs } from "./types.js";
import * as path from "path";
import * as core from "@actions/core";

const getInputs = (): FlywayAggregateReportsInputs => {
  const reportsFolder = core.getInput("reports-folder", { required: true });
  const rawWorkingDirectory = core.getInput("working-directory");
  const workingDirectory = rawWorkingDirectory ? path.resolve(rawWorkingDirectory) : undefined;
  const extraArgs = core.getInput("extra-args") || undefined;
  const reportPath = path.resolve(workingDirectory ?? process.cwd(), "aggregate-report.html");

  return {
    reportsFolder,
    reportPath,
    workingDirectory,
    extraArgs,
  };
};

export { getInputs };
