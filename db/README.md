# Database migrations

Go-Ditecting uses `golang-migrate` and immutable, sequential SQL files in
`db/migrations`. API and Detector processes never create tables or seed data.
Only the one-shot migration job has DDL privileges; application accounts have
`SELECT`, `INSERT`, `UPDATE`, and `DELETE` privileges.

## Rules

1. Never edit a migration that has reached any shared environment. Create the
   next numbered `*.up.sql` file instead.
2. Keep migrations backward compatible with the currently deployed application.
3. Do not add destructive down migrations. Roll back the application first and
   prefer a new forward migration. Use a verified backup or point-in-time recovery
   for destructive data loss.
4. Do not seed demo assets during application startup. Versioned dictionaries and
   built-in rules may be initialized with idempotent SQL; real assets arrive via
   import or event discovery.

## Commands

The migration process accepts `up`, `up N`, and `version` only:

```bash
MIGRATION_DATABASE_URL='mysql://diting_migrator:secret@tcp(mysql:3306)/diting?multiStatements=true' \
  go run ./cmd/migrate up
```

`golang-migrate` records the current version and dirty state in
`schema_migrations`. A dirty version fails the job and blocks application rollout.
The MySQL driver also obtains a database lock; the deployment platform must still
run the job with one completion and one parallel worker.

The Compose MySQL initialization scripts create the DML and DDL identities only
when the data directory is empty. For an existing development volume, apply the
grants manually or recreate that disposable local volume after backing up anything
you need; never remove a production volume to update privileges.

## Production rollout gate

Before running the migration job:

- create a database backup and restore it into an isolated instance;
- record the largest tables and expected DDL algorithm/lock behavior;
- inspect long-running transactions and terminate or wait for unsafe ones;
- verify database-host free space is comfortably above the estimated temporary
  space needed by the largest altered table;
- check replica health and replication delay;
- confirm the migration identity has DDL privileges and the application identity
  has DML-only privileges.

Example MySQL checks:

```sql
SELECT table_name,
       ROUND((data_length + index_length) / 1024 / 1024, 2) AS size_mb,
       table_rows
FROM information_schema.tables
WHERE table_schema = DATABASE()
ORDER BY data_length + index_length DESC;

SELECT trx_id, trx_mysql_thread_id, trx_started, trx_state,
       TIMESTAMPDIFF(SECOND, trx_started, NOW()) AS age_seconds,
       trx_query
FROM information_schema.innodb_trx
ORDER BY trx_started;

SHOW REPLICA STATUS;
```

Also check filesystem capacity on the database host with the platform's storage
monitoring or `df -h`. Test a real restore, not just successful backup creation.

After migration, require `schema_migrations.dirty = 0` and the expected version
before deploying API and Detector. Any migration failure stops the release.

## Zero-downtime changes

Use expand-contract across separate releases:

1. Expand: add nullable columns or new tables. Prefer MySQL Online DDL only after
   confirming the supported `ALGORITHM` and `LOCK` for the exact MySQL version.
2. Deploy code that reads old and new representations and writes the new one.
3. Backfill in small, observable, idempotent batches with retry checkpoints.
4. Verify every instance uses the new representation and the backfill is complete.
5. Contract in a later migration by adding constraints or removing obsolete data.

Even Online DDL can wait on metadata locks. Monitor open transactions and rehearse
large-table changes with production-like data before release.

## CI upgrade coverage

CI creates two isolated databases. The first runs all migrations from empty and
executes store integration tests. The second imports
`db/testdata/legacy_schema.sql`, preserves a legacy asset, upgrades to the latest
version, and verifies both the schema version and data. Update the legacy fixture
when a new production release becomes the supported upgrade baseline.
