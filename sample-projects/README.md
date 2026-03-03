# Sample Projects for Tests

Sample projects used for testing the Flyway GitHub Actions

- `sqlite`
  - Database files
    - **`no-drift.db`**
      - Contains Flyway tables (`flyway_schema_history` baselined at version 0, `snapshot_history_table` with an empty snapshot); otherwise empty
    - **`drift.db`**
      - Like `no-drift.db`, but contains a `drifted_table`
- `h2`
