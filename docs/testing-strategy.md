# Testing strategy

## End-to-end tests

We want to minimize the number of these tests as they are slow and expensive.

They should be written as GitHub workflows using the latest version of the action from the branch you are on.

These tests should be ran against Windows, Linux and MacOS.

These tests should use a sample project located in flyway/sample-project.

These tests should run against SQLite, changes in behavior based on database type should be covered by the existing Flyway test suite.

## Unit tests

Unit tests should cover the behavior of individual functions and modules in isolation.

Tests must live alongside the source code in a `tests/` directory within each action.

Test files must use the `.test.ts` suffix and be run by Vitest.

Mock external dependencies such as `@actions/core` and `@actions/exec` at the module level to test behavior in isolation.

Tests should not perform real filesystem writes, web requests, or database interactions.

Aim for high code coverage, and reproduce all bugs with a failing test before fixing.

Test classes should be parallelizable and repeatable.

Tests should be written against the interface, not the implementation.
