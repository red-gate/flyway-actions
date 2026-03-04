import * as path from "node:path";

const resolvePath = (relativePath: string | undefined, workingDirectory: string | undefined): string | undefined => {
  if (!relativePath) {
    return undefined;
  }
  if (path.isAbsolute(relativePath)) {
    return relativePath;
  }
  return workingDirectory ? path.join(workingDirectory, relativePath) : relativePath;
};

export { resolvePath };
