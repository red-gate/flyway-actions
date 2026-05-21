type FlywayMigrationsGenerateInputs = {
  source?: string;
  types?: string;
  description?: string;
  buildEnvironment?: string;
  buildUrl?: string;
  buildUser?: string;
  buildPassword?: string;
  buildSchemas?: string;
  workingDirectory?: string;
  extraArgs?: string;
  commitMigrations?: boolean;
  commitMessage?: string;
  commitUserName?: string;
  commitUserEmail?: string;
  commitBranch?: string;
};

export type { FlywayMigrationsGenerateInputs };
