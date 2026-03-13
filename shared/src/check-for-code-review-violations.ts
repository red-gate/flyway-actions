import * as core from "@actions/core";
import { runFlyway } from "./flyway-runner.js";

type CodeResultItem = { violations?: { code?: string }[] };

type CodeReviewSuccessOutput = {
  htmlReport?: string;
  individualResults?: { operation?: string; results?: CodeResultItem[] }[];
};

type CodeReviewErrorOutput = {
  error?: { errorCode?: string; message?: string; results?: CodeResultItem[]; htmlReport?: string };
};

type CheckForCodeReviewResult = {
  exitCode: number;
  reportPath?: string;
  violationCount: number;
  violationCodes: string[];
};

const checkForCodeReviewViolations = async (
  args: string[],
  workingDirectory?: string,
): Promise<CheckForCodeReviewResult> => {
  core.startGroup("Running code review");
  try {
    const result = await runFlyway(args, workingDirectory);

    if (result.exitCode !== 0) {
      const errorOutput = parseErrorOutput(result.stdout);
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      const violations = extractViolations(errorOutput?.error?.results ?? []);
      setOutput(violations);
      return { exitCode: result.exitCode, reportPath: errorOutput?.error?.htmlReport, ...violations };
    }

    const output = parseSuccessOutput(result.stdout);
    const codeResults = output?.individualResults?.filter((r) => r.operation === "code");
    const resultItems = codeResults?.flatMap((r) => r.results ?? []) ?? [];
    const violations = extractViolations(resultItems);
    setOutput(violations);
    return { exitCode: result.exitCode, reportPath: output?.htmlReport, ...violations };
  } finally {
    core.endGroup();
  }
};

const extractViolations = (results: CodeResultItem[]): { violationCount: number; violationCodes: string[] } => {
  const codes = results
    .flatMap((r) => r.violations ?? [])
    .map((v) => v.code)
    .filter((c): c is string => !!c);
  return { violationCount: codes.length, violationCodes: [...new Set(codes)] };
};

const setOutput = (violations: { violationCount: number; violationCodes: string[] }) => {
  core.setOutput("code-violation-count", violations.violationCount.toString());
  core.setOutput("code-violation-codes", violations.violationCodes.join(","));
};

const parseSuccessOutput = (stdout: string): CodeReviewSuccessOutput | undefined => {
  try {
    return JSON.parse(stdout) as CodeReviewSuccessOutput;
  } catch {
    return undefined;
  }
};

const parseErrorOutput = (stdout: string): CodeReviewErrorOutput | undefined => {
  try {
    return JSON.parse(stdout) as CodeReviewErrorOutput;
  } catch {
    return undefined;
  }
};

export { checkForCodeReviewViolations };
export type { CheckForCodeReviewResult };
