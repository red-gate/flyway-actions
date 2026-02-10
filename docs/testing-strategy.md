# Testing strategy

## End-to-end tests

We want to minimize the number of these tests as they are slow and expensive.

They should be written as GitHub workflows using the latest version of the action from the branch you are on.

These tests should be ran against Windows, Linux and MacOS.

These tests should use a sample project located in flyway/sample-project.

These tests should run against SQLite, changes in behavior based on database type should be covered by the existing Flyway test suite.