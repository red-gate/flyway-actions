import * as core from "@actions/core";

type DeploySummaryData = {
  driftChecked: boolean;
  driftDetected: boolean;
  migrationsApplied: number;
  schemaVersion: string;
};

const writeSummary = async (data: DeploySummaryData): Promise<void> => {
  const driftText = !data.driftChecked ? "Not checked" : data.driftDetected ? "Detected" : "Not detected";

  await core.summary
    .addHeading("Flyway Deploy", 2)
    .addTable([
      [{ data: "Migrations Applied", header: true }, data.migrationsApplied.toString()],
      [{ data: "Schema Version", header: true }, data.schemaVersion],
      [{ data: "Drift", header: true }, driftText],
    ])
    .write();
};

export { writeSummary };
export type { DeploySummaryData };
