type FlywayMigrationsDeploymentInputs = {
  targetEnvironment?: string;
  targetUrl?: string;
  targetUser?: string;
  targetPassword?: string;
  targetSchemas?: string;
  targetMigrationVersion?: string;
  cherryPick?: string;
  baselineOnMigrate?: boolean;
  skipDriftCheck?: boolean;
  provisionMode?: string;
  workingDirectory?: string;
  extraArgs?: string;
  deploymentReportName?: string;
  saveSnapshot?: boolean;
};

type Migration = {
  category?: string;
  version?: string;
  description?: string;
  type?: string;
  filepath?: string;
  executionTime?: number;
};

type FlywayMigrateOutput = { migrationsExecuted?: number; targetSchemaVersion?: string; migrations?: Migration[] };

export type { FlywayMigrateOutput, FlywayMigrationsDeploymentInputs, Migration };
