import * as core from "@actions/core";

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
    ? `Passed - ${result.violationCount} violations`
    : `Failed${result.violationCount > 0 ? ` - ${result.violationCount} violations` : ""}`;
};

const formatChanges = (result?: { exitCode: number; changedObjectCount: number }): string => {
  if (!result) {
    return "Skipped";
  }
  if (result.exitCode !== 0) {
    return "Failed";
  }
  return `${result.changedObjectCount} changed objects`;
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
