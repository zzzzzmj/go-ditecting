-- Local Compose credentials only. Production credentials must come from a secret manager.
CREATE USER IF NOT EXISTS 'diting'@'%' IDENTIFIED BY 'diting_password';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'diting'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON diting.* TO 'diting'@'%';

CREATE USER IF NOT EXISTS 'diting_migrator'@'%' IDENTIFIED BY 'diting_migrate_password';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'diting_migrator'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES ON diting.* TO 'diting_migrator'@'%';

FLUSH PRIVILEGES;
