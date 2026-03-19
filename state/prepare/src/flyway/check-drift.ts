import type { FlywayStatePrepareInputs } from "../types.js";
import { checkForDrift } from "@flyway-actions/shared/check-for-drift";
import { getCommonArgs } from "./arg-builders.js";

const getDriftArgs = (inputs: FlywayStatePrepareInputs): string[] => [
  "check",
  "-drift",
  "-check.failOnDrift=true",
  ...getCommonArgs(inputs),
  ...(inputs.preDeploymentReportName ? [`-reportFilename=${inputs.preDeploymentReportName}`] : []),
];

const runCheckDrift = async (inputs: FlywayStatePrepareInputs) =>
  checkForDrift(getDriftArgs(inputs), inputs.workingDirectory);

export { runCheckDrift };
