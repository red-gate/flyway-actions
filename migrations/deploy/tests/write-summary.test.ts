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
      driftChecked: true,
      driftDetected: false,
      migrationsApplied: 3,
      schemaVersion: "2.0",
    };

    await writeSummary(data);

    expect(addHeading).toHaveBeenCalledWith("Flyway Deploy", 2);
    expect(addTable).toHaveBeenCalledWith([
      [{ data: "Migrations Applied", header: true }, "3"],
      [{ data: "Schema Version", header: true }, "2.0"],
      [{ data: "Drift", header: true }, "Not detected"],
    ]);
    expect(write).toHaveBeenCalled();
  });

  it("should show drift as detected", async () => {
    const data: DeploySummaryData = {
      driftChecked: true,
      driftDetected: true,
      migrationsApplied: 0,
      schemaVersion: "unknown",
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([[{ data: "Drift", header: true }, "Detected"]]));
  });

  it("should show drift as not checked", async () => {
    const data: DeploySummaryData = {
      driftChecked: false,
      driftDetected: false,
      migrationsApplied: 5,
      schemaVersion: "4.0",
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([[{ data: "Drift", header: true }, "Not checked"]]));
  });

  it("should show zero migrations applied", async () => {
    const data: DeploySummaryData = {
      driftChecked: false,
      driftDetected: false,
      migrationsApplied: 0,
      schemaVersion: "1.0",
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(
      expect.arrayContaining([[{ data: "Migrations Applied", header: true }, "0"]]),
    );
  });
});
