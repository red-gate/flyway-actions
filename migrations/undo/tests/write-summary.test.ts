import type { UndoSummaryData } from "../src/write-summary.js";

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
    const data: UndoSummaryData = {
      driftStatus: "No drift",
      migrationsUndone: 3,
      schemaVersion: "2.0",
    };

    await writeSummary(data);

    expect(addHeading).toHaveBeenCalledWith("Flyway Undo", 2);
    expect(addTable).toHaveBeenCalledWith([
      [{ data: "Migrations Undone", header: true }, "3 migrations"],
      [{ data: "Schema Version", header: true }, "2.0"],
      [{ data: "Drift", header: true }, "No drift"],
    ]);
    expect(write).toHaveBeenCalled();
  });

  it("should show drift as detected", async () => {
    const data: UndoSummaryData = {
      driftStatus: "Drift detected",
      migrationsUndone: 0,
      schemaVersion: "unknown",
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(
      expect.arrayContaining([[{ data: "Drift", header: true }, "Drift detected"]]),
    );
  });

  it("should default drift status to 'Skipped' when driftStatus is undefined", async () => {
    const data: UndoSummaryData = {
      migrationsUndone: 5,
      schemaVersion: "4.0",
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith([
      [{ data: "Migrations Undone", header: true }, "5 migrations"],
      [{ data: "Schema Version", header: true }, "4.0"],
      [{ data: "Drift", header: true }, "Skipped"],
    ]);
  });

  it("should show zero migrations undone", async () => {
    const data: UndoSummaryData = {
      migrationsUndone: 0,
      schemaVersion: "1.0",
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(
      expect.arrayContaining([[{ data: "Migrations Undone", header: true }, "0 migrations"]]),
    );
  });

  it("should show singular migration when one undone", async () => {
    const data: UndoSummaryData = {
      migrationsUndone: 1,
      schemaVersion: "1.0",
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(
      expect.arrayContaining([[{ data: "Migrations Undone", header: true }, "1 migration"]]),
    );
  });
});
