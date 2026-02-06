interface FlywayMigrateInputs {
  url: string;
  user?: string;
  password?: string;

  configFiles?: string;
  workingDirectory?: string;

  extraArgs?: string;
}

interface FlywayMigrateOutputs {
  exitCode: number;
  migrationsApplied: number;
  schemaVersion: string;
}

interface InputDefinition {
  inputName: string;
  flywayArg: string;
  type: 'string' | 'boolean';
  isSecret?: boolean;
}

interface FlywayRunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export { FlywayMigrateInputs, FlywayMigrateOutputs, InputDefinition, FlywayRunResult };
