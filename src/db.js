const { Client } = require('pg');

const db = new Client({
  host: 'localhost',
  port: 5432,
  database: 'CryptoExchange',
  user: 'postgres',
  password: '528491'
});

db.connect()
  .then(() => console.log('Connected to database'))
  .catch(console.error);

module.exports = {
  query: (text, params) => db.query(text, params),
};
