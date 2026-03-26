import * as core from "@actions/core";
import { pluralize } from "@flyway-actions/shared/pluralize";

type ChecksSummaryData = {
  dryrun?: { exitCode: number };
  code?: { exitCode: number; violationCount: number };
  driftStatus?: string;
  changes?: { exitCode: number; changedObjectCount: number };
};

const formatDryrun = (result?: { exitCode: number }): string => {
  if (!result) {
    return "Skipped";
  }
  return result.exitCode === 0 ? "Dry run script generated" : "Failed";
};

const formatCode = (result?: { exitCode: number; violationCount: number }): string => {
  if (!result) {
    return "Skipped";
  }
  return result.exitCode === 0
    ? `Passed - ${pluralize("violation", result.violationCount)}`
    : `Failed${result.violationCount > 0 ? ` - ${pluralize("violation", result.violationCount)}` : ""}`;
};

const formatChanges = (result?: { exitCode: number; changedObjectCount: number }): string => {
  if (!result) {
    return "Skipped";
  }
  if (result.exitCode !== 0) {
    return "Failed";
  }
  return pluralize("changed object", result.changedObjectCount);
};

const writeSummary = async (data: ChecksSummaryData): Promise<void> => {
  await core.summary
    .addHeading("Flyway Checks", 2)
    .addTable([
      [
        { data: "Check", header: true },
        { data: "Result", header: true },
      ],
      ["Deployment Script Review", formatDryrun(data.dryrun)],
      ["Code Review", formatCode(data.code)],
      ["Drift", data.driftStatus ?? "Skipped"],
      ["Deployment Changes", formatChanges(data.changes)],
    ])
    .write();
};

export { writeSummary };
export type { ChecksSummaryData };
