import * as core from "@actions/core";
import { pluralize } from "@flyway-actions/shared/pluralize";

type UndoSummaryData = {
  driftStatus?: string;
  migrationsUndone: number;
  schemaVersion: string;
};

const writeSummary = async (data: UndoSummaryData): Promise<void> => {
  await core.summary
    .addHeading("Flyway Undo", 2)
    .addTable([
      [{ data: "Migrations Undone", header: true }, pluralize("migration", data.migrationsUndone)],
      [{ data: "Schema Version", header: true }, data.schemaVersion],
      [{ data: "Drift", header: true }, data.driftStatus ?? "Skipped"],
    ])
    .write();
};

export { writeSummary };
export type { UndoSummaryData };
