/**
 * Flyway migrate action inputs
 */
export interface FlywayMigrateInputs {
  // Connection
  url: string;
  user?: string;
  password?: string;
  driver?: string;
  connectRetries?: number;
  connectRetriesInterval?: number;
  initSql?: string;

  // General
  locations?: string;
  schemas?: string;
  defaultSchema?: string;
  table?: string;
  tablespace?: string;
  target?: string;

  // Behavior
  baselineOnMigrate?: boolean;
  baselineVersion?: string;
  baselineDescription?: string;
  outOfOrder?: boolean;
  validateOnMigrate?: boolean;
  validateMigrationNaming?: boolean;
  mixed?: boolean;
  group?: boolean;
  installedBy?: string;
  skipExecutingMigrations?: boolean;

  // Teams/Enterprise
  cherryPick?: string;
  dryRunOutput?: string;
  batch?: boolean;
  stream?: boolean;
  errorOverrides?: string;
  failOnMissingTarget?: boolean;

  // Placeholders
  placeholderReplacement?: boolean;
  placeholderPrefix?: string;
  placeholderSuffix?: string;
  placeholderSeparator?: string;
  placeholders?: Record<string, string>;
  scriptPlaceholderPrefix?: string;
  scriptPlaceholderSuffix?: string;

  // Migration naming
  sqlMigrationPrefix?: string;
  sqlMigrationSeparator?: string;
  sqlMigrationSuffixes?: string;
  repeatableSqlMigrationPrefix?: string;
  undoSqlMigrationPrefix?: string;

  // Secrets - Vault
  vaultUrl?: string;
  vaultToken?: string;
  vaultSecrets?: string;

  // Secrets - GCSM
  gcsmProject?: string;
  gcsmSecrets?: string;

  // Secrets - Dapr
  daprUrl?: string;
  daprSecrets?: string;

  // Database-specific - Oracle
  oracleSqlplus?: boolean;
  oracleSqlplusWarn?: boolean;
  oracleWalletLocation?: string;
  oracleKerberosCacheFile?: string;

  // Database-specific - PostgreSQL
  postgresqlTransactionalLock?: boolean;

  // Database-specific - SQL Server
  sqlserverKerberosLoginFile?: string;

  // Advanced
  configFiles?: string;
  workingDirectory?: string;
  jarDirs?: string;
  encoding?: string;
  callbacks?: string;
  loggers?: string;
  outputType?: string;
  color?: boolean;
  edition?: string;
  environment?: string;
  detectEncoding?: boolean;
  executeInTransaction?: boolean;
  lockRetryCount?: number;
  failOnMissingLocations?: boolean;
  reportFilename?: string;
  reportEnabled?: boolean;
  skipDefaultCallbacks?: boolean;
  skipDefaultResolvers?: boolean;
  cleanDisabled?: boolean;
  cleanOnValidationError?: boolean;
  communityDbSupportEnabled?: boolean;

  // Extra arguments
  extraArgs?: string;
}

/**
 * Flyway migrate action outputs
 */
export interface FlywayMigrateOutputs {
  exitCode: number;
  flywayVersion: string;
  migrationsApplied: number;
  schemaVersion: string;
}

/**
 * Input parameter definition for mapping
 */
export interface InputDefinition {
  inputName: string;
  flywayArg: string;
  type: 'string' | 'boolean' | 'number' | 'placeholders';
  isSecret?: boolean;
}

/**
 * Result from running Flyway
 */
export interface FlywayRunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}
