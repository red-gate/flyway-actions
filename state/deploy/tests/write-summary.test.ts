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
  it("should write heading and drift status", async () => {
    const data: DeploySummaryData = {
      driftStatus: "No drift",
    };

    await writeSummary(data);

    expect(addHeading).toHaveBeenCalledWith("Flyway State Deploy", 2);
    expect(addTable).toHaveBeenCalledWith([[{ data: "Drift", header: true }, "No drift"]]);
    expect(write).toHaveBeenCalled();
  });

  it("should show drift as detected", async () => {
    const data: DeploySummaryData = {
      driftStatus: "Drift detected",
    };

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith([[{ data: "Drift", header: true }, "Drift detected"]]);
  });

  it("should not include drift row when driftStatus is undefined", async () => {
    const data: DeploySummaryData = {};

    await writeSummary(data);

    expect(addTable).toHaveBeenCalledWith([]);
  });
});
