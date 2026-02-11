type FlywayEdition = "community" | "teams" | "enterprise";

type FlywayDetails = { installed: false } | { installed: true; edition: FlywayEdition };

type FlywayMigrationsDeploymentInputs = {
  environment?: string;
  url?: string;
  user?: string;
  password?: string;
  target?: string;
  cherryPick?: string;
  workingDirectory?: string;
  extraArgs?: string;
  saveSnapshot?: boolean;
};

type FlywayMigrationsDeploymentOutputs = {
  exitCode: number;
  migrationsApplied: number;
  schemaVersion: string;
};

type FlywayRunResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
};

export type {
  FlywayEdition,
  FlywayDetails,
  FlywayMigrationsDeploymentInputs,
  FlywayMigrationsDeploymentOutputs,
  FlywayRunResult,
};
