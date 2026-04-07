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
  await core.summary
    .addHeading("Flyway Deploy", 2)
    .addTable([
      [
        { data: "Migrations Applied", header: true },
        { data: "Schema Version", header: true },
        { data: "Drift", header: true },
      ],
      [pluralize("migration", data.migrationsApplied), data.schemaVersion, data.driftStatus ?? "Skipped"],
    ])
    .write();
};

export { writeSummary };
export type { DeploySummaryData };
