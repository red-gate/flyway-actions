type FlywayEdition = 'community' | 'teams' | 'enterprise';

type FlywayDetails = { installed: false } | { installed: true; edition: FlywayEdition };

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
  migrationsApplied: number;
  schemaVersion: string;
}

interface FlywayRunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export { FlywayEdition, FlywayDetails, FlywayMigrateInputs, FlywayMigrateOutputs, FlywayRunResult };
