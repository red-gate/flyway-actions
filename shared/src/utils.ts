import type { JsonLogModel } from "./types.js";
import * as path from "node:path";
import * as core from "@actions/core";

const createStdoutListener = (): { listener: (data: Buffer) => void; getOutput: () => string } => {
  let output = "";
  return {
    listener: (data: Buffer) => (output += data.toString()),
    getOutput: () => output,
  };
};

const createStdoutStderrListeners = (): {
  listeners: { stdout: (data: Buffer) => void; stderr: (data: Buffer) => void };
  getOutput: () => { stdout: string; stderr: string };
} => {
  let stdout = "";
  let stderr = "";
  return {
    listeners: {
      stdout: (data: Buffer) => (stdout += data.toString()),
      stderr: (data: Buffer) => (stderr += data.toString()),
    },
    getOutput: () => ({ stdout, stderr }),
  };
};

const createJsonStderrListener = (): ((data: Buffer) => void) => {
  let buffer = "";
  return (data: Buffer) => {
    buffer += data.toString();
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      try {
        const parsed = JSON.parse(line.trim()) as JsonLogModel;
        parsed.message && (parsed.level === "ERROR" ? core.error(parsed.message) : core.info(parsed.message));
      } catch {
        // Not valid JSON, skip
      }
    }
  };
};

const resolvePath = (relativePath: string | undefined, workingDirectory: string | undefined): string | undefined => {
  if (!relativePath) {
    return undefined;
  }
  if (path.isAbsolute(relativePath)) {
    return relativePath;
  }
  return workingDirectory ? path.join(workingDirectory, relativePath) : relativePath;
};

export { createJsonStderrListener, createStdoutListener, createStdoutStderrListeners, resolvePath };
