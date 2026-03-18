import type { ChecksSummaryData } from "../src/write-summary.js";

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
    const data: ChecksSummaryData = {
      dryrun: { exitCode: 0 },
      code: { exitCode: 0, violationCount: 0 },
      drift: { exitCode: 0, driftDetected: false },
      changes: { exitCode: 0, changedObjectCount: 5 },
    };

    await writeSummary(data);

    expect(addHeading).toHaveBeenCalledWith("Flyway Checks", 2);
    expect(addTable).toHaveBeenCalledWith([
      [
        { data: "Check", header: true },
        { data: "Result", header: true },
      ],
      ["Deployment Script Review", "Passed"],
      ["Code Review", "Passed"],
      ["Drift", "Not detected"],
      ["Deployment Changes", "5 changed objects"],
    ]);
    expect(write).toHaveBeenCalled();
  });

  it("should show skipped for undefined results", async () => {
    const data: ChecksSummaryData = {};

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith([
      [
        { data: "Check", header: true },
        { data: "Result", header: true },
      ],
      ["Deployment Script Review", "Skipped"],
      ["Code Review", "Skipped"],
      ["Drift", "Skipped"],
      ["Deployment Changes", "Skipped"],
    ]);
  });

  it("should show violation count for code review", async () => {
    const data: ChecksSummaryData = {
      code: { exitCode: 1, violationCount: 3 },
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([["Code Review", "3 violations"]]));
  });

  it("should show failed for code review with no violations", async () => {
    const data: ChecksSummaryData = {
      code: { exitCode: 1, violationCount: 0 },
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([["Code Review", "Failed"]]));
  });

  it("should show drift detected", async () => {
    const data: ChecksSummaryData = {
      drift: { exitCode: 1, driftDetected: true },
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([["Drift", "Detected"]]));
  });

  it("should show failed for dryrun", async () => {
    const data: ChecksSummaryData = {
      dryrun: { exitCode: 1 },
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([["Deployment Script Review", "Failed"]]));
  });

  it("should show failed for changes", async () => {
    const data: ChecksSummaryData = {
      changes: { exitCode: 1, changedObjectCount: 0 },
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([["Deployment Changes", "Failed"]]));
  });

  it("should show zero changed objects on success", async () => {
    const data: ChecksSummaryData = {
      changes: { exitCode: 0, changedObjectCount: 0 },
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith(expect.arrayContaining([["Deployment Changes", "0 changed objects"]]));
  });
});
