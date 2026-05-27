import type { GenerateSummaryData } from "../src/write-summary.js";

const summary = {
  addHeading: vi.fn(),
  addTable: vi.fn(),
  addRaw: vi.fn(),
  addEOL: vi.fn(),
  addList: vi.fn(),
  write: vi.fn().mockResolvedValue(undefined),
};
summary.addHeading.mockReturnValue(summary);
summary.addTable.mockReturnValue(summary);
summary.addRaw.mockReturnValue(summary);
summary.addEOL.mockReturnValue(summary);
summary.addList.mockReturnValue(summary);

vi.doMock("@actions/core", () => ({
  summary,
}));

const { addHeading, addTable, addRaw, addList, write } = summary;

const { writeSummary } = await import("../src/write-summary.js");

beforeEach(() => {
  vi.clearAllMocks();
  summary.addHeading.mockReturnValue(summary);
  summary.addTable.mockReturnValue(summary);
  summary.addRaw.mockReturnValue(summary);
  summary.addEOL.mockReturnValue(summary);
  summary.addList.mockReturnValue(summary);
});

describe("writeSummary", () => {
  it("should write top-level heading and migration count", async () => {
    await writeSummary({ scripts: [] });

    expect(addHeading).toHaveBeenCalledWith("Flyway Migrations Generate", 2);
    expect(addRaw).toHaveBeenCalledWith("0 migrations generated");
    expect(write).toHaveBeenCalled();
  });

  it("should use singular form for one migration", async () => {
    await writeSummary({
      scripts: [{ type: "versioned", location: "V001.sql", changes: [], warnings: [] }],
    });

    expect(addRaw).toHaveBeenCalledWith("1 migration generated");
  });

  it("should write a heading and changes table for each script", async () => {
    const data: GenerateSummaryData = {
      scripts: [
        {
          type: "versioned",
          location: "migrations/V001__add.sql",
          changes: [
            { name: "Orders", objectType: "Table", differenceType: "Add" },
            { name: "Customers", objectType: "Table", differenceType: "Modify" },
          ],
          warnings: [],
        },
      ],
    };

    await writeSummary(data);

    expect(addHeading).toHaveBeenCalledWith("migrations/V001__add.sql (versioned)", 3);
    expect(addTable).toHaveBeenCalledWith([
      [
        { data: "Object", header: true },
        { data: "Object Type", header: true },
        { data: "Difference Type", header: true },
      ],
      ["Orders", "Table", "Add"],
      ["Customers", "Table", "Modify"],
    ]);
  });

  it("should note when a script has no captured changes", async () => {
    await writeSummary({
      scripts: [{ type: "versioned", location: "V001.sql", changes: [], warnings: [] }],
    });

    expect(addRaw).toHaveBeenCalledWith("No changes captured");
    expect(addTable).not.toHaveBeenCalled();
  });

  it("should list warnings under a Warnings heading", async () => {
    await writeSummary({
      scripts: [
        {
          type: "versioned",
          location: "V001.sql",
          changes: [],
          warnings: [
            { type: "DEP", message: "deprecated thing" },
            { type: "PERF", message: "slow thing" },
          ],
        },
      ],
    });

    expect(addHeading).toHaveBeenCalledWith("2 Warnings", 4);
    expect(addList).toHaveBeenCalledWith(["DEP: deprecated thing", "PERF: slow thing"]);
  });

  it("should use singular Warning heading for one warning", async () => {
    await writeSummary({
      scripts: [
        {
          type: "versioned",
          location: "V001.sql",
          changes: [],
          warnings: [{ type: "DEP", message: "deprecated" }],
        },
      ],
    });

    expect(addHeading).toHaveBeenCalledWith("1 Warning", 4);
  });

  it("should format warnings without a type as just the message", async () => {
    await writeSummary({
      scripts: [
        {
          type: "versioned",
          location: "V001.sql",
          changes: [],
          warnings: [{ type: "", message: "just a message" }],
        },
      ],
    });

    expect(addList).toHaveBeenCalledWith(["just a message"]);
  });
});
