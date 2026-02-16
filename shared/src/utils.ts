const toCamelCase = (str: string): string => str.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());

const createStdoutListener = (): {
  listener: (data: Buffer) => void;
  getOutput: () => string;
} => {
  let output = "";
  return {
    listener: (data: Buffer) => {
      output += data.toString();
    },
    getOutput: () => output,
  };
};

const createStdoutStderrListeners = (): {
  listeners: {
    stdout: (data: Buffer) => void;
    stderr: (data: Buffer) => void;
  };
  getOutput: () => { stdout: string; stderr: string };
} => {
  let stdout = "";
  let stderr = "";
  return {
    listeners: {
      stdout: (data: Buffer) => {
        stdout += data.toString();
      },
      stderr: (data: Buffer) => {
        stderr += data.toString();
      },
    },
    getOutput: () => ({ stdout, stderr }),
  };
};

export { createStdoutListener, createStdoutStderrListeners, toCamelCase };
