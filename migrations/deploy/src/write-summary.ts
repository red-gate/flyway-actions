import * as core from "@actions/core";

type DeploySummaryData = {
  driftStatus?: string;
  migrationsApplied: number;
  schemaVersion: string;
};

const writeSummary = async (data: DeploySummaryData): Promise<void> => {
  await core.summary
    .addHeading("Flyway Deploy", 2)
    .addTable([
      [{ data: "Migrations Applied", header: true }, data.migrationsApplied.toString()],
      [{ data: "Schema Version", header: true }, data.schemaVersion],
      ...(data.driftStatus ? [[{ data: "Drift", header: true }, data.driftStatus]] : []),
    ])
    .write();
};

export { writeSummary };
export type { DeploySummaryData };
