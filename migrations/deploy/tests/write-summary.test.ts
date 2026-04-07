import type { DeploySummaryData } from "../src/write-summary.js";

const summary = {
  addHeading: vi.fn(),
  addTable: vi.fn(),
  write: vi.fn().mockResolvedValue(undefined),
};
summary.addHeading.mockReturnValue(summary);
summary.addTable.mockReturnValue(summary);

vi.doMock("@actions/core", () => ({
  summary,
}));

const { addHeading, addTable, write } = summary;

const { writeSummary } = await import("../src/write-summary.js");

beforeEach(() => {
  vi.clearAllMocks();
  summary.addHeading.mockReturnValue(summary);
  summary.addTable.mockReturnValue(summary);
});

describe("writeSummary", () => {
  it("should write heading and table on success", async () => {
    const data: DeploySummaryData = {
      driftStatus: "No drift",
      migrationsApplied: 3,
      schemaVersion: "2.0",
      migrations: [],
    };

    await writeSummary(data);

    expect(addHeading).toHaveBeenCalledWith("Flyway Deploy", 2);
    expect(addTable).toHaveBeenCalledWith([
      [
        { data: "Migrations Applied", header: true },
        { data: "Schema Version", header: true },
        { data: "Drift", header: true },
      ],
      ["3 migrations", "2.0", "No drift"],
    ]);
    expect(write).toHaveBeenCalled();
  });

  it("should show drift as detected", async () => {
    const data: DeploySummaryData = {
      driftStatus: "Drift detected",
      migrationsApplied: 0,
      schemaVersion: "unknown",
      migrations: [],
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith([
      [
        { data: "Migrations Applied", header: true },
        { data: "Schema Version", header: true },
        { data: "Drift", header: true },
      ],
      ["0 migrations", "unknown", "Drift detected"],
    ]);
  });

  it("should default drift status to 'Skipped' when driftStatus is undefined", async () => {
    const data: DeploySummaryData = {
      migrationsApplied: 5,
      schemaVersion: "4.0",
      migrations: [],
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith([
      [
        { data: "Migrations Applied", header: true },
        { data: "Schema Version", header: true },
        { data: "Drift", header: true },
      ],
      ["5 migrations", "4.0", "Skipped"],
    ]);
  });

  it("should show zero migrations applied", async () => {
    const data: DeploySummaryData = {
      migrationsApplied: 0,
      schemaVersion: "1.0",
      migrations: [],
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith([
      [
        { data: "Migrations Applied", header: true },
        { data: "Schema Version", header: true },
        { data: "Drift", header: true },
      ],
      ["0 migrations", "1.0", "Skipped"],
    ]);
  });

  it("should show singular migration when one applied", async () => {
    const data: DeploySummaryData = {
      migrationsApplied: 1,
      schemaVersion: "1.0",
      migrations: [],
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith([
      [
        { data: "Migrations Applied", header: true },
        { data: "Schema Version", header: true },
        { data: "Drift", header: true },
      ],
      ["1 migration", "1.0", "Skipped"],
    ]);
  });

  it("should not add migrations table when migrations array is empty", async () => {
    const data: DeploySummaryData = {
      migrationsApplied: 0,
      schemaVersion: "1.0",
      migrations: [],
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledTimes(1);
  });

  it("should add migrations table when migrations are present", async () => {
    const data: DeploySummaryData = {
      migrationsApplied: 2,
      schemaVersion: "3.0",
      migrations: [
        {
          category: "Versioned",
          version: "2",
          description: "create users table",
          type: "SQL",
          filepath: "V2__create_users_table.sql",
          executionTime: 120,
        },
        {
          category: "Versioned",
          version: "3",
          description: "add email column",
          type: "SQL",
          filepath: "V3__add_email_column.sql",
          executionTime: 45,
        },
      ],
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledTimes(2);
    expect(addTable).toHaveBeenCalledWith([
      [
        { data: "Category", header: true },
        { data: "Version", header: true },
        { data: "Description", header: true },
        { data: "Execution Time (ms)", header: true },
        { data: "Type", header: true },
        { data: "Filepath", header: true },
      ],
      ["Versioned", "2", "create users table", "120ms", "SQL", "V2__create_users_table.sql"],
      ["Versioned", "3", "add email column", "45ms", "SQL", "V3__add_email_column.sql"],
    ]);
  });
});
