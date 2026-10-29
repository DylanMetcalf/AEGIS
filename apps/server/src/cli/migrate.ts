import { migrate } from '../db/migrate.js';

/**
 * Apply pending migrations as the schema owner.
 * Requires DATABASE_MIGRATION_URL (the owner role), which the API process
 * does not need and should not be given.
 */
const url = process.env.DATABASE_MIGRATION_URL;
if (!url) {
  console.error('DATABASE_MIGRATION_URL is required');
  process.exit(1);
}
migrate(url, { log: (m) => console.log(m) })
  .then(({ applied }) => {
    console.log(applied.length ? `Applied ${applied.length} migration(s)` : 'Schema is up to date');
  })
  .catch((err: Error) => {
    console.error(`Migration failed: ${err.name}: ${err.message}`);
    process.exit(1);
  });
