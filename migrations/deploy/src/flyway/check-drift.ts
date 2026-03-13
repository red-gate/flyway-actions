import type { FlywayMigrationsDeploymentInputs } from "../types.js";
import { checkForDrift } from "@flyway-actions/shared/check-for-drift";
import { getCommonArgs } from "./arg-builders.js";

const getDriftArgs = (inputs: FlywayMigrationsDeploymentInputs): string[] => [
  "check",
  "-drift",
  "-check.failOnDrift=true",
  ...getCommonArgs(inputs),
  ...(inputs.driftReportName ? [`-reportFilename=${inputs.driftReportName}`] : []),
];

const runCheckDrift = async (inputs: FlywayMigrationsDeploymentInputs) =>
  checkForDrift(getDriftArgs(inputs), inputs.workingDirectory);

export { runCheckDrift };
