type FlywayMigrationsUndoInputs = {
  targetEnvironment?: string;
  targetUrl?: string;
  targetUser?: string;
  targetPassword?: string;
  targetSchemas?: string;
  targetMigrationVersion?: string;
  cherryPick?: string;
  skipDriftCheck?: boolean;
  workingDirectory?: string;
  extraArgs?: string;
  undoReportName?: string;
  saveSnapshot?: boolean;
};

type FlywayUndoOutput = { migrationsUndone?: number; targetSchemaVersion?: string };

export type { FlywayMigrationsUndoInputs, FlywayUndoOutput };
