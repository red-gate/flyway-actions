type FlywayEdition = 'community' | 'teams' | 'enterprise';

interface FlywayVersionDetails {
  version: string;
  edition: FlywayEdition;
}

interface FlywayMigrateInputs {
  url?: string;
  user?: string;
  password?: string;
  environment?: string;
  target?: string;
  cherryPick?: string;
  baselineOnMigrate: boolean;
  saveSnapshot?: boolean;
  workingDirectory?: string;
  extraArgs?: string;
}

interface FlywayMigrateOutputs {
  exitCode: number;
  flywayVersion: string;
  migrationsApplied: number;
  schemaVersion: string;
}

interface FlywayRunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export {
  FlywayEdition,
  FlywayVersionDetails,
  FlywayMigrateInputs,
  FlywayMigrateOutputs,
  FlywayRunResult,
};
