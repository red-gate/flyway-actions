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

type Drift = { operation?: "drift"; onlyInSource?: unknown[]; onlyInTarget?: unknown[]; differences?: unknown[] };

type Changes = { operation?: "changes"; onlyInSource?: unknown[]; onlyInTarget?: unknown[]; differences?: unknown[] };

type Code = { operation?: "code"; results?: { violations?: { code?: string }[] }[] };

type Dryrun = { operation?: "dryrun" };

type FlywayCheckOutput = { individualResults?: (Drift | Changes | Code | Dryrun)[] };

export type { Changes, Code, Drift, FlywayCheckOutput, FlywayMigrationsChecksInputs };
