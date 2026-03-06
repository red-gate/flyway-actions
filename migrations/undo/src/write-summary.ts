import * as core from "@actions/core";

type UndoSummaryData = {
  driftStatus?: string;
  migrationsUndone: number;
  schemaVersion: string;
};

const writeSummary = async (data: UndoSummaryData): Promise<void> => {
  await core.summary
    .addHeading("Flyway Undo", 2)
    .addTable([
      [{ data: "Migrations Undone", header: true }, data.migrationsUndone.toString()],
      [{ data: "Schema Version", header: true }, data.schemaVersion],
      ...(data.driftStatus ? [[{ data: "Drift", header: true }, data.driftStatus]] : []),
    ])
    .write();
};

export { writeSummary };
export type { UndoSummaryData };
