import type { Script } from "./flyway/generate.js";
import * as core from "@actions/core";
import { pluralize } from "@flyway-actions/shared/pluralize";

type GenerateSummaryData = {
  scripts: Script[];
};

const CHANGE_HEADERS = [
  { data: "Object", header: true },
  { data: "Object Type", header: true },
  { data: "Difference Type", header: true },
];

const writeSummary = async (data: GenerateSummaryData): Promise<void> => {
  const builder = core.summary
    .addHeading("Flyway Migrations Generate", 2)
    .addRaw(`${pluralize("migration", data.scripts.length)} generated`)
    .addEOL();

  for (const script of data.scripts) {
    builder.addHeading(`${script.location} (${script.type})`, 3);

    if (script.changes.length > 0) {
      builder.addTable([
        CHANGE_HEADERS,
        ...script.changes.map((change) => [change.name, change.objectType, change.differenceType]),
      ]);
    } else {
      builder.addRaw("No changes captured").addEOL();
    }

    if (script.warnings.length > 0) {
      builder
        .addHeading(pluralize("Warning", script.warnings.length), 4)
        .addList(script.warnings.map((warning) => formatWarning(warning)));
    }
  }

  await builder.write();
};

const formatWarning = (warning: { type: string; message: string }): string => {
  if (warning.type && warning.message) {
    return `${warning.type}: ${warning.message}`;
  }
  return warning.type || warning.message;
};

export { writeSummary };
export type { GenerateSummaryData };
