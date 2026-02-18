type FlywayMigrationsChecksInputs = {
  targetEnvironment?: string;
  targetUrl?: string;
  targetUser?: string;
  targetPassword?: string;
  targetSchemas?: string;
  targetMigrationVersion?: string;
  cherryPick?: string;
  buildEnvironment?: string;
  buildUrl?: string;
  buildUser?: string;
  buildPassword?: string;
  buildSchemas?: string;
  buildOkToErase?: boolean;
  failOnCodeReview?: boolean;
  failOnDrift?: boolean;
  workingDirectory?: string;
  extraArgs?: string;
};

export type { FlywayMigrationsChecksInputs };
