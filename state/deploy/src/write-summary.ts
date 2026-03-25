import * as core from "@actions/core";

type DeploySummaryData = {
  driftStatus?: string;
};

const writeSummary = async (data: DeploySummaryData): Promise<void> => {
  await core.summary
    .addHeading("Flyway State Deploy", 2)
    .addTable([...(data.driftStatus ? [[{ data: "Drift", header: true }, data.driftStatus]] : [])])
    .write();
};

export { writeSummary };
export type { DeploySummaryData };
