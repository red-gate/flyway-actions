-- Add status column to users table
ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active';

-- Triggers a code review violation
SELECT * FROM users;
