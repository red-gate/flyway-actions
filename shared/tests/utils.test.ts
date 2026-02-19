const info = vi.fn();
const error = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error,
}));

const { createJsonStderrListener, createStdoutListener, createStdoutStderrListeners } = await import("../src/utils.js");

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

describe("createJsonStderrListener", () => {
  it("should parse and log JSON stderr lines", () => {
    const listener = createJsonStderrListener();
    const jsonLine = JSON.stringify({ level: "INFO", message: "Starting migration" });

    listener(Buffer.from(`${jsonLine}\n`));

    expect(info).toHaveBeenCalledWith("Starting migration");
  });

  it("should parse and log JSON stderr error lines", () => {
    const listener = createJsonStderrListener();
    const jsonLine = JSON.stringify({ level: "ERROR", message: "err" });

    listener(Buffer.from(`${jsonLine}\n`));

    expect(error).toHaveBeenCalledWith("err");
  });

  it("should parse multiple JSON stderr lines", () => {
    const listener = createJsonStderrListener();
    const lines = [
      JSON.stringify({ level: "INFO", message: "Starting migration" }),
      JSON.stringify({ level: "WARN", message: "Schema missing" }),
    ].join("\n");

    listener(Buffer.from(`${lines}\n`));

    expect(info).toHaveBeenCalledWith("Starting migration");
    expect(info).toHaveBeenCalledWith("Schema missing");
  });

  it("should skip non-JSON stderr lines", () => {
    const listener = createJsonStderrListener();

    listener(Buffer.from("plain text warning\n"));

    expect(info).not.toHaveBeenCalled();
  });
});
