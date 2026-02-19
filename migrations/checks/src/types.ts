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
  skipCodeReview?: boolean;
  skipDriftCheck?: boolean;
  skipDeploymentChangesReport?: boolean;
  skipDeploymentScriptReview?: boolean;
  failOnCodeReview?: boolean;
  failOnDrift?: boolean;
  workingDirectory?: string;
  extraArgs?: string;
};

type ErrorOutput = { error?: { errorCode?: string; message?: string } };

export type { ErrorOutput, FlywayMigrationsChecksInputs };
