import type { Migration } from "./types.js";
import * as core from "@actions/core";
import { pluralize } from "@flyway-actions/shared/pluralize";

type DeploySummaryData = {
  driftStatus?: string;
  migrationsApplied: number;
  schemaVersion: string;
  migrations: Required<Migration>[];
};

const writeSummary = async (data: DeploySummaryData): Promise<void> => {
  const summary = core.summary.addHeading("Flyway Deploy", 2).addTable([
    [
      { data: "Migrations Applied", header: true },
      { data: "Schema Version", header: true },
      { data: "Drift", header: true },
    ],
    [pluralize("migration", data.migrationsApplied), data.schemaVersion, data.driftStatus ?? "Skipped"],
  ]);

  if (data.migrations.length > 0) {
    summary.addTable([
      [
        { data: "Category", header: true },
        { data: "Version", header: true },
        { data: "Description", header: true },
        { data: "Execution Time (ms)", header: true },
        { data: "Type", header: true },
        { data: "Filepath", header: true },
      ],
      ...data.migrations.map((m) => [m.category, m.version, m.description, `${m.executionTime}ms`, m.type, m.filepath]),
    ]);
  }

  await summary.write();
};

export { writeSummary };
export type { DeploySummaryData };
