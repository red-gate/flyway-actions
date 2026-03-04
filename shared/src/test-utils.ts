import type { ExecOptions } from "@actions/exec";

type StringOrObject = string | Record<string, unknown>;

type MockExecOptions = { stdout?: StringOrObject; stderr?: StringOrObject; exitCode?: number };

const toBuffer = (value: StringOrObject) => Buffer.from(typeof value === "string" ? value : JSON.stringify(value));

const mockExec =
  ({ stdout, stderr, exitCode = 0 }: MockExecOptions = {}) =>
  (_cmd: string, _args?: string[], options?: ExecOptions) => {
    if (stdout) {
      options?.listeners?.stdout?.(toBuffer(stdout));
    }
    if (stderr) {
      options?.listeners?.stderr?.(toBuffer(stderr));
    }
    return Promise.resolve(exitCode);
  };

// used in another workspace
// noinspection JSUnusedGlobalSymbols
const mockExecSequence = (calls: MockExecOptions[]) => {
  let callIndex = 0;
  return (_cmd: string, _args?: string[], options?: ExecOptions) => {
    const call = calls[callIndex] ?? calls[calls.length - 1];
    callIndex++;
    if (call.stdout) {
      options?.listeners?.stdout?.(toBuffer(call.stdout));
    }
    if (call.stderr) {
      options?.listeners?.stderr?.(toBuffer(call.stderr));
    }
    return Promise.resolve(call.exitCode ?? 0);
  };
};

export { mockExec, mockExecSequence };
export type { MockExecOptions };
