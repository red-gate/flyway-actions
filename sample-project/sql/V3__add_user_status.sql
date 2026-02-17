-- Add status column to users table
ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active';

-- 'SELECT *' to trigger code violation
SELECT * FROM users;
