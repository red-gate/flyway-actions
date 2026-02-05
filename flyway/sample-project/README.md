# Sample Project for End-to-End Tests

This sample project contains SQLite migrations used for end-to-end testing of the Flyway GitHub Actions.

## Migrations

- **V1__create_users_table.sql**: Creates the users table with basic user information
- **V2__create_posts_table.sql**: Creates the posts table with a foreign key to users
- **V3__add_user_status.sql**: Adds a status column to the users table

## Database

These migrations are designed for SQLite and use SQLite-specific syntax (e.g., `INTEGER PRIMARY KEY AUTOINCREMENT`).
