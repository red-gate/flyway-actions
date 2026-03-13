import type { FlywayMigrationsUndoInputs } from "../types.js";
import { checkForDrift } from "@flyway-actions/shared/check-for-drift";
import { getCommonArgs } from "./arg-builders.js";

const getDriftArgs = (inputs: FlywayMigrationsUndoInputs): string[] => [
  "check",
  "-drift",
  "-check.failOnDrift=true",
  ...getCommonArgs(inputs),
  ...(inputs.driftReportName ? [`-reportFilename=${inputs.driftReportName}`] : []),
];

const runCheckDrift = async (inputs: FlywayMigrationsUndoInputs) =>
  checkForDrift(getDriftArgs(inputs), inputs.workingDirectory);

export { runCheckDrift };
