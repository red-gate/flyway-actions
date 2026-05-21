import type { FlywayMigrationsGenerateInputs } from "../types.js";
import type { ErrorOutput } from "@flyway-actions/shared/types";
import * as core from "@actions/core";
import { parseOutput, runFlyway } from "@flyway-actions/shared/flyway-runner";
import { getGenerateArgs } from "./arg-builders.js";

type DiffObjectRef = { fullyQualifiedName?: string; schema?: string; name?: string };

type RawDifference = {
  from?: DiffObjectRef | null;
  to?: DiffObjectRef | null;
  differenceType?: string;
  objectType?: string;
};

type RawWarning = { type?: string; message?: string };

type RawScript = {
  type?: string;
  location?: string;
  differences?: RawDifference[];
  warnings?: RawWarning[];
};

type GenerateOutput = { scripts?: RawScript[] };

type Change = { name: string; differenceType: string; objectType: string };

type Warning = { type: string; message: string };

type Script = {
  type: string;
  location: string;
  changes: Change[];
  warnings: Warning[];
};

type GenerateResult = { scripts: Script[] };

const generate = async (inputs: FlywayMigrationsGenerateInputs): Promise<GenerateResult> => {
  core.startGroup("Running generate");
  try {
    const args = getGenerateArgs(inputs);
    const result = await runFlyway(args, inputs.workingDirectory);

    if (result.exitCode !== 0) {
      const errorOutput = parseOutput<ErrorOutput>(result.stdout);
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      setOutput(result.exitCode, []);
      throw new Error(`Flyway generate failed with exit code ${result.exitCode}`);
    }

    const output = parseOutput<GenerateOutput>(result.stdout);
    const scripts = extractScripts(output);
    setOutput(
      result.exitCode,
      scripts.map((s) => s.location),
    );
    return { scripts };
  } finally {
    core.endGroup();
  }
};

const extractScripts = (output: GenerateOutput | undefined): Script[] => {
  if (!output?.scripts?.length) {
    return [];
  }
  return output.scripts
    .filter((s) => !!s.location)
    .map((s) => ({
      type: s.type ?? "unknown",
      location: s.location ?? "",
      changes: (s.differences ?? []).map(toChange),
      warnings: (s.warnings ?? []).map(toWarning),
    }));
};

const toChange = (diff: RawDifference): Change => ({
  name: diff.to?.name ?? diff.from?.name ?? "",
  differenceType: diff.differenceType ?? "",
  objectType: diff.objectType ?? "",
});

const toWarning = (warning: RawWarning): Warning => ({
  type: warning.type ?? "",
  message: warning.message ?? "",
});

const setOutput = (exitCode: number, scriptPaths: string[]): void => {
  core.setOutput("exit-code", exitCode.toString());
  core.setOutput("script-paths", JSON.stringify(scriptPaths));
};

export { extractScripts, generate };
export type { Change, GenerateResult, Script, Warning };
