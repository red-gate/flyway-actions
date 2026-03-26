import type { PrepareSummaryData } from "../src/write-summary.js";

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
  it("should write heading and table with all checks passed", async () => {
    const data: PrepareSummaryData = {
      driftStatus: "No drift",
      code: { exitCode: 0, violationCount: 0 },
      changes: { exitCode: 0, changedObjectCount: 5 },
    };

    await writeSummary(data);

    expect(addHeading).toHaveBeenCalledWith("Flyway State Prepare", 2);
    expect(addTable).toHaveBeenCalledWith([
      [
        { data: "Check", header: true },
        { data: "Result", header: true },
      ],
      ["Drift", "No drift"],
      ["Code Review", "Passed - 0 violations"],
      ["Deployment Changes", "5 changed objects"],
    ]);
    expect(write).toHaveBeenCalled();
  });

  it("should show skipped for undefined results", async () => {
    const data: PrepareSummaryData = {};

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith([
      [
        { data: "Check", header: true },
        { data: "Result", header: true },
      ],
      ["Drift", "Skipped"],
      ["Code Review", "Skipped"],
      ["Deployment Changes", "Skipped"],
    ]);
  });

  it("should show violation count for code review", async () => {
    const data: PrepareSummaryData = {
      code: { exitCode: 1, violationCount: 3 },
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([["Code Review", "Failed - 3 violations"]]));
  });

  it("should show failed for code review with no violations", async () => {
    const data: PrepareSummaryData = {
      code: { exitCode: 1, violationCount: 0 },
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([["Code Review", "Failed"]]));
  });

  it("should show drift detected", async () => {
    const data: PrepareSummaryData = {
      driftStatus: "Drift detected",
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([["Drift", "Drift detected"]]));
  });

  it("should show failed for changes", async () => {
    const data: PrepareSummaryData = {
      changes: { exitCode: 1, changedObjectCount: 0 },
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([["Deployment Changes", "Failed"]]));
  });

  it("should show singular violation", async () => {
    const data: PrepareSummaryData = {
      code: { exitCode: 1, violationCount: 1 },
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([["Code Review", "Failed - 1 violation"]]));
  });

  it("should show singular changed object on success", async () => {
    const data: PrepareSummaryData = {
      changes: { exitCode: 0, changedObjectCount: 1 },
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([["Deployment Changes", "1 changed object"]]));
  });

  it("should show zero changed objects on success", async () => {
    const data: PrepareSummaryData = {
      changes: { exitCode: 0, changedObjectCount: 0 },
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([["Deployment Changes", "0 changed objects"]]));
  });
});
