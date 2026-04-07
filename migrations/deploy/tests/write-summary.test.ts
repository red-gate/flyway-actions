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
});
