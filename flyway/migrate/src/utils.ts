const toCamelCase = (str: string): string => {
  return str.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
};

const createStdoutStderrListeners = (): {
  listeners: {
    stdout: (data: Buffer) => void;
    stderr: (data: Buffer) => void;
  };
  getOutput: () => { stdout: string; stderr: string };
} => {
  let stdout = '';
  let stderr = '';
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

export { toCamelCase, createStdoutStderrListeners };
