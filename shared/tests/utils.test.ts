import { createStdoutListener, createStdoutStderrListeners } from "../src/utils.js";

describe("createStdoutListener", () => {
  it("should return empty string before any data", () => {
    const { getOutput } = createStdoutListener();

    expect(getOutput()).toBe("");
  });

  it("should accumulate buffer data", () => {
    const { listener, getOutput } = createStdoutListener();
    listener(Buffer.from("hello"));

    expect(getOutput()).toBe("hello");
  });

  it("should accumulate multiple chunks", () => {
    const { listener, getOutput } = createStdoutListener();
    listener(Buffer.from("hello "));
    listener(Buffer.from("world"));

    expect(getOutput()).toBe("hello world");
  });
});

describe("createStdoutStderrListeners", () => {
  it("should return empty strings before any data", () => {
    const { getOutput } = createStdoutStderrListeners();

    expect(getOutput()).toEqual({ stdout: "", stderr: "" });
  });

  it("should accumulate stdout separately from stderr", () => {
    const { listeners, getOutput } = createStdoutStderrListeners();
    listeners.stdout(Buffer.from("out"));
    listeners.stderr(Buffer.from("err"));

    expect(getOutput()).toEqual({ stdout: "out", stderr: "err" });
  });

  it("should accumulate multiple chunks to both streams", () => {
    const { listeners, getOutput } = createStdoutStderrListeners();
    listeners.stdout(Buffer.from("line1\n"));
    listeners.stdout(Buffer.from("line2\n"));
    listeners.stderr(Buffer.from("warn1\n"));
    listeners.stderr(Buffer.from("warn2\n"));

    expect(getOutput()).toEqual({ stdout: "line1\nline2\n", stderr: "warn1\nwarn2\n" });
  });
});
