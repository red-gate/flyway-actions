type FlywayEdition = 'community' | 'teams' | 'enterprise';

type FlywayDetails = { installed: false } | { installed: true; edition: FlywayEdition };

interface FlywayMigrationsDeploymentInputs {
  url?: string;
  user?: string;
  password?: string;
  environment?: string;
  target?: string;
  cherryPick?: string;
  saveSnapshot?: boolean;
  workingDirectory?: string;
  extraArgs?: string;
}

interface FlywayMigrationsDeploymentOutputs {
  exitCode: number;
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
  FlywayDetails,
  FlywayMigrationsDeploymentInputs,
  FlywayMigrationsDeploymentOutputs,
  FlywayRunResult,
};
