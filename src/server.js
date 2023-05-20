const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');
const cors = require('cors');
const { createLogger, format, transports } = require("winston")

const crypto = require('crypto');
const secret_key = crypto.randomBytes(32).toString('hex');

const logger = createLogger({
  level: "debug",
  format: format.combine(
      format.colorize(),
      format.printf((info) => `[ ${info.level} ] => ${info.message}`)
  ),
  transports: [new transports.Console()],
})

const app = express();
const corsOptions = {
  origin: 'http://localhost:3000',
  credentials: true,
  methods: 'GET, POST'
};

app.use(express.json());
app.use(cors(corsOptions));

app.post('/api/register', async (req, res) => {
    try {
      const { username, password, first_name, last_name } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
      const result = await db.query('INSERT INTO users (username, password, first_name, last_name) VALUES ($1, $2, $3, $4) RETURNING id', [username, hashedPassword, first_name, last_name]);
      const userId = result.rows[0].id;
      await db.query('INSERT INTO wallets (name, balance, user_id) VALUES ($1, $2, $3)', [`USD`, 10000, userId]);
      res.json({ message: 'User registered successfully' });
      logger.info('User registered successfully');
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
      logger.error('Internal Server Error');
    }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await db.query('SELECT id, password FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    const passwordMatches = await bcrypt.compare(password, user.password);
    if (!passwordMatches) {
      res.status(401).json({ error: 'Incorrect password' });
      logger.warn('Incorrect password');
    } else {
      const token = jwt.sign({ userId: user.id }, secret_key, { expiresIn: '1h' });
      res.setHeader('Set-Cookie', `token=${token}; HttpOnly`);
      res.status(200).json({ token: token });
      logger.info('Generate Token');
    }
  } catch (error) {
    res.status(401).json({ error: 'User not found' });
    logger.error('User not found');
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token').send('Logged out successfully');
  logger.info('Logged out successfully');
});

app.post('/api/wallets', async (req, res) => {
  const { name, balance } = req.body;
  try {
    const token = req.headers.authorization.split(' ')[1];
    const { userId } = jwt.verify(token, secret_key);
    const result = await db.query('INSERT INTO wallets (name, balance, user_id) VALUES ($1, $2, $3) RETURNING *', [name, balance, userId]);
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: 'Unauthorized' });
  }
});

app.post('/api/buy', async (req, res) => {
  const { walletId, amount, price } = req.body;
  try {
    const token = req.headers.authorization.split(' ')[1];
    const { userId } = jwt.verify(token, secret_key);
    const walletResult = await db.query('SELECT * FROM wallets WHERE id = $1 AND user_id = $2', [walletId, userId]);
    const wallet = walletResult.rows[0];
    const newBalance = wallet.balance + amount / price;
    const transactionResult = await db.query('INSERT INTO transactions (wallet_id, amount, price) VALUES ($1, $2, $3) RETURNING *', [walletId, amount, price]);
    const walletUpdateResult = await db.query('UPDATE wallets SET balance = $1 WHERE id = $2 RETURNING *', [newBalance, walletId]);
    const updatedWallet = walletUpdateResult.rows[0];
    res.json({
      transaction: transactionResult.rows[0],
      wallet: updatedWallet,
    });
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: 'Unauthorized' });
  }
});

app.get('/api/wallets/:id/balance', async (req, res) => {
  const walletId = req.params.id
  try {
    const token = req.headers.authorization.split(' ')[1];
    const { userId } = jwt.verify(token, secret_key);
    const result = await db.query('SELECT * FROM wallets WHERE id = $1 AND user_id = $2', [walletId, userId]);
    const wallet = result.rows[0];
    res.json({ balance: wallet.balance });
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: 'Unauthorized' });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));