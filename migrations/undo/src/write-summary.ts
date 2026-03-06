import * as core from "@actions/core";

type UndoSummaryData = {
  driftChecked: boolean;
  driftDetected: boolean;
  migrationsUndone: number;
  schemaVersion: string;
};

const writeSummary = async (data: UndoSummaryData): Promise<void> => {
  const driftText = !data.driftChecked ? "Not checked" : data.driftDetected ? "Detected" : "Not detected";

  await core.summary
    .addHeading("Flyway Undo", 2)
    .addTable([
      [{ data: "Migrations Undone", header: true }, data.migrationsUndone.toString()],
      [{ data: "Schema Version", header: true }, data.schemaVersion],
      [{ data: "Drift", header: true }, driftText],
    ])
    .write();
};

export { writeSummary };
export type { UndoSummaryData };
