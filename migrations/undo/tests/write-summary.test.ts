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
      driftChecked: true,
      driftDetected: false,
      migrationsUndone: 3,
      schemaVersion: "2.0",
    };

    await writeSummary(data);

    expect(addHeading).toHaveBeenCalledWith("Flyway Undo", 2);
    expect(addTable).toHaveBeenCalledWith([
      [{ data: "Migrations Undone", header: true }, "3"],
      [{ data: "Schema Version", header: true }, "2.0"],
      [{ data: "Drift", header: true }, "Not detected"],
    ]);
    expect(write).toHaveBeenCalled();
  });

  it("should show drift as detected", async () => {
    const data: UndoSummaryData = {
      driftChecked: true,
      driftDetected: true,
      migrationsUndone: 0,
      schemaVersion: "unknown",
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([[{ data: "Drift", header: true }, "Detected"]]));
  });

  it("should show drift as not checked", async () => {
    const data: UndoSummaryData = {
      driftChecked: false,
      driftDetected: false,
      migrationsUndone: 5,
      schemaVersion: "4.0",
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([[{ data: "Drift", header: true }, "Not checked"]]));
  });

  it("should show zero migrations undone", async () => {
    const data: UndoSummaryData = {
      driftChecked: false,
      driftDetected: false,
      migrationsUndone: 0,
      schemaVersion: "1.0",
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([[{ data: "Migrations Undone", header: true }, "0"]]));
  });
});
