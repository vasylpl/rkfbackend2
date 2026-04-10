const { Pool } = require('pg');

const pool = new Pool({
  connectionString: 'postgresql://postgres.fdywfvbywftkdlwfpfgo:oytmCs5oPmqRYWr2@aws-1-eu-west-1.pooler.supabase.com:5432/postgres',
  ssl: { rejectUnauthorized: false }
});

module.exports = pool;