import * as core from "@actions/core";
import { pluralize } from "@flyway-actions/shared/pluralize";

type PrepareSummaryData = {
  driftStatus?: string;
  code?: { exitCode: number; violationCount: number };
  changes?: { exitCode: number; changedObjectCount: number };
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

const writeSummary = async (data: PrepareSummaryData): Promise<void> => {
  await core.summary
    .addHeading("Flyway State Prepare", 2)
    .addTable([
      [
        { data: "Check", header: true },
        { data: "Result", header: true },
      ],
      ["Drift", data.driftStatus ?? "Skipped"],
      ["Code Review", formatCode(data.code)],
      ["Deployment Changes", formatChanges(data.changes)],
    ])
    .write();
};

export { writeSummary };
export type { PrepareSummaryData };
