import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  parseBoolean,
  parseNumber,
  parsePlaceholders,
  getInputs,
  maskSecrets,
} from '../src/inputs.js';
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

describe('parseNumber', () => {
  it('should return undefined for empty string', () => {
    expect(parseNumber('')).toBeUndefined();
  });

  it('should return undefined for undefined', () => {
    expect(parseNumber(undefined)).toBeUndefined();
  });

  it('should parse valid number', () => {
    expect(parseNumber('42')).toBe(42);
  });

  it('should parse zero', () => {
    expect(parseNumber('0')).toBe(0);
  });

  it('should parse negative number', () => {
    expect(parseNumber('-5')).toBe(-5);
  });

  it('should throw for non-numeric value', () => {
    expect(() => parseNumber('abc')).toThrow('Invalid number value: abc');
  });

  it('should throw for float when expecting integer', () => {
    expect(parseNumber('3.14')).toBe(3);
  });
});

describe('parsePlaceholders', () => {
  it('should return undefined for empty string', () => {
    expect(parsePlaceholders('')).toBeUndefined();
  });

  it('should return undefined for undefined', () => {
    expect(parsePlaceholders(undefined)).toBeUndefined();
  });

  it('should parse single placeholder', () => {
    expect(parsePlaceholders('key=value')).toEqual({ key: 'value' });
  });

  it('should parse multiple placeholders', () => {
    expect(parsePlaceholders('key1=value1,key2=value2')).toEqual({
      key1: 'value1',
      key2: 'value2',
    });
  });

  it('should handle whitespace', () => {
    expect(parsePlaceholders(' key1 = value1 , key2 = value2 ')).toEqual({
      key1: 'value1',
      key2: 'value2',
    });
  });

  it('should handle values with equals sign', () => {
    expect(parsePlaceholders('key=value=with=equals')).toEqual({
      key: 'value=with=equals',
    });
  });

  it('should handle empty values', () => {
    expect(parsePlaceholders('key=')).toEqual({ key: '' });
  });

  it('should skip empty entries', () => {
    expect(parsePlaceholders('key1=value1,,key2=value2')).toEqual({
      key1: 'value1',
      key2: 'value2',
    });
  });

  it('should throw for invalid format (no equals)', () => {
    expect(() => parsePlaceholders('invalidformat')).toThrow(
      'Invalid placeholder format: invalidformat. Expected key=value'
    );
  });

  it('should throw for empty key', () => {
    expect(() => parsePlaceholders('=value')).toThrow('Empty placeholder key in: =value');
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
        locations: 'filesystem:sql',
      };
      return values[name] || '';
    });

    const inputs = getInputs();
    expect(inputs.url).toBe('jdbc:postgresql://localhost/db');
    expect(inputs.user).toBe('admin');
    expect(inputs.password).toBe('secret');
    expect(inputs.locations).toBe('filesystem:sql');
  });

  it('should get boolean inputs', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      const values: Record<string, string> = {
        url: 'jdbc:postgresql://localhost/db',
        'baseline-on-migrate': 'true',
        'out-of-order': 'false',
      };
      return values[name] || '';
    });

    const inputs = getInputs();
    expect(inputs.baselineOnMigrate).toBe(true);
    expect(inputs.outOfOrder).toBe(false);
  });

  it('should get number inputs', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      const values: Record<string, string> = {
        url: 'jdbc:postgresql://localhost/db',
        'connect-retries': '5',
        'connect-retries-interval': '10',
      };
      return values[name] || '';
    });

    const inputs = getInputs();
    expect(inputs.connectRetries).toBe(5);
    expect(inputs.connectRetriesInterval).toBe(10);
  });

  it('should get placeholder inputs', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      const values: Record<string, string> = {
        url: 'jdbc:postgresql://localhost/db',
        placeholders: 'env=prod,version=1.0',
      };
      return values[name] || '';
    });

    const inputs = getInputs();
    expect(inputs.placeholders).toEqual({ env: 'prod', version: '1.0' });
  });

  it('should get working directory and extra args', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      const values: Record<string, string> = {
        url: 'jdbc:postgresql://localhost/db',
        'working-directory': '/app/db',
        'extra-args': '-X -someFlag=value',
      };
      return values[name] || '';
    });

    const inputs = getInputs();
    expect(inputs.workingDirectory).toBe('/app/db');
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

  it('should mask vault token', () => {
    const inputs = {
      url: 'jdbc:postgresql://localhost/db',
      vaultToken: 'hvs.token123',
    };

    maskSecrets(inputs);

    expect(core.setSecret).toHaveBeenCalledWith('hvs.token123');
  });

  it('should mask multiple secrets', () => {
    const inputs = {
      url: 'jdbc:postgresql://localhost/db',
      password: 'secret123',
      vaultToken: 'hvs.token123',
    };

    maskSecrets(inputs);

    expect(core.setSecret).toHaveBeenCalledTimes(2);
    expect(core.setSecret).toHaveBeenCalledWith('secret123');
    expect(core.setSecret).toHaveBeenCalledWith('hvs.token123');
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
