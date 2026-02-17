import type { FlywayDetails, FlywayEdition, FlywayRunResult } from "@flyway-actions/shared";

type FlywayMigrationsChecksInputs = {
  targetEnvironment?: string;
  targetUrl?: string;
  targetUser?: string;
  targetPassword?: string;
  targetSchemas?: string;
  buildEnvironment?: string;
  buildUrl?: string;
  buildUser?: string;
  buildPassword?: string;
  buildSchemas?: string;
  generateReport: boolean;
  failOnDrift: boolean;
  failOnCodeReview: boolean;
  targetMigrationVersion?: string;
  cherryPick?: string;
  workingDirectory?: string;
  extraArgs?: string;
};

export type { FlywayDetails, FlywayEdition, FlywayMigrationsChecksInputs, FlywayRunResult };
