import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { parseBoolean, getInputs, maskSecrets } from '../src/inputs.js';
import * as core from '@actions/core';

vi.mock('@actions/core');

describe('parseBoolean', () => {
  it('should return undefined for empty string', () => {
    expect(parseBoolean('')).toBeUndefined();
  });

  it('should return undefined for undefined', () => {
    expect(parseBoolean(undefined)).toBeUndefined();
  });

  it('should parse "true" as true', () => {
    expect(parseBoolean('true')).toBe(true);
  });

  it('should parse "TRUE" as true (case insensitive)', () => {
    expect(parseBoolean('TRUE')).toBe(true);
  });

  it('should parse "yes" as true', () => {
    expect(parseBoolean('yes')).toBe(true);
  });

  it('should parse "1" as true', () => {
    expect(parseBoolean('1')).toBe(true);
  });

  it('should parse "false" as false', () => {
    expect(parseBoolean('false')).toBe(false);
  });

  it('should parse "FALSE" as false (case insensitive)', () => {
    expect(parseBoolean('FALSE')).toBe(false);
  });

  it('should parse "no" as false', () => {
    expect(parseBoolean('no')).toBe(false);
  });

  it('should parse "0" as false', () => {
    expect(parseBoolean('0')).toBe(false);
  });

  it('should throw for invalid value', () => {
    expect(() => parseBoolean('invalid')).toThrow('Invalid boolean value: invalid');
  });
});

describe('getInputs', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  it('should get required url input', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      if (name === 'url') return 'jdbc:postgresql://localhost/db';
      return '';
    });

    const inputs = getInputs();
    expect(inputs.url).toBe('jdbc:postgresql://localhost/db');
  });

  it('should get optional string inputs', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      const values: Record<string, string> = {
        url: 'jdbc:postgresql://localhost/db',
        user: 'admin',
        password: 'secret',
      };
      return values[name] || '';
    });

    const inputs = getInputs();
    expect(inputs.url).toBe('jdbc:postgresql://localhost/db');
    expect(inputs.user).toBe('admin');
    expect(inputs.password).toBe('secret');
  });

  it('should get config files and working directory', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      const values: Record<string, string> = {
        url: 'jdbc:postgresql://localhost/db',
        'config-files': 'flyway.conf,flyway-local.conf',
        'working-directory': '/app/db',
      };
      return values[name] || '';
    });

    const inputs = getInputs();
    expect(inputs.configFiles).toBe('flyway.conf,flyway-local.conf');
    expect(inputs.workingDirectory).toBe('/app/db');
  });

  it('should get extra args', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      const values: Record<string, string> = {
        url: 'jdbc:postgresql://localhost/db',
        'extra-args': '-X -someFlag=value',
      };
      return values[name] || '';
    });

    const inputs = getInputs();
    expect(inputs.extraArgs).toBe('-X -someFlag=value');
  });
});

describe('maskSecrets', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('should mask password', () => {
    const inputs = {
      url: 'jdbc:postgresql://localhost/db',
      password: 'secret123',
    };

    maskSecrets(inputs);

    expect(core.setSecret).toHaveBeenCalledWith('secret123');
  });

  it('should not call setSecret when no secrets present', () => {
    const inputs = {
      url: 'jdbc:postgresql://localhost/db',
      user: 'admin',
    };

    maskSecrets(inputs);

    expect(core.setSecret).not.toHaveBeenCalled();
  });
});
