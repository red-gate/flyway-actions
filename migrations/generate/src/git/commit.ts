import type { CommitInputs } from "../types.js";
import * as core from "@actions/core";
import * as exec from "@actions/exec";

type CommitResult = { committed: boolean };

const commitAndPush = async (
  commit: CommitInputs,
  workingDirectory: string | undefined,
  scriptPaths: string[],
): Promise<CommitResult> => {
  if (!commit.migrations) {
    setOutput(false);
    return { committed: false };
  }
  if (!scriptPaths.length) {
    core.info("No generated migrations to commit.");
    setOutput(false);
    return { committed: false };
  }

  const branch = commit.branch || process.env.GITHUB_REF_NAME;
  if (!branch) {
    throw new Error(
      'Could not determine the branch to push to. Set the "commit-branch" input or run from a branch context.',
    );
  }

  core.startGroup("Committing generated migrations");
  try {
    const options = { cwd: workingDirectory };

    await exec.exec("git", ["config", "user.name", commit.userName], options);
    await exec.exec("git", ["config", "user.email", commit.userEmail], options);
    await exec.exec("git", ["add", "--", ...scriptPaths], options);

    const diffExit = await exec.exec("git", ["diff", "--cached", "--quiet"], {
      ...options,
      ignoreReturnCode: true,
    });
    if (diffExit === 0) {
      core.info("No staged changes after add. Skipping commit.");
      setOutput(false);
      return { committed: false };
    }

    await exec.exec("git", ["commit", "-m", commit.message], options);
    await exec.exec("git", ["push", "origin", `HEAD:${branch}`], options);

    setOutput(true);
    return { committed: true };
  } finally {
    core.endGroup();
  }
};

const setOutput = (committed: boolean): void => {
  core.setOutput("committed", committed.toString());
};

export { commitAndPush };
export type { CommitResult };
