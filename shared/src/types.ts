type FlywayEdition = "community" | "teams" | "enterprise";

type FlywayDetails = { installed: false } | { installed: true; edition: FlywayEdition };

type FlywayRunResult = { exitCode: number; stdout: string; stderr: string };

type FlywayVersionOutput = { edition?: string };

export type { FlywayDetails, FlywayEdition, FlywayRunResult, FlywayVersionOutput };
