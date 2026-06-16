require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_this';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway')
    ? { rejectUnauthorized: false }
    : false
});

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ─── DB INIT ────────────────────────────────────────────────────────────────

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id         SERIAL PRIMARY KEY,
      username   TEXT UNIQUE NOT NULL,
      password   TEXT NOT NULL,
      goal       INTEGER DEFAULT 2000,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS days (
      id            SERIAL PRIMARY KEY,
      user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
      date          DATE NOT NULL,
      weight        NUMERIC(5,1),
      bp_systolic   INTEGER,
      bp_diastolic  INTEGER,
      heart_rate    INTEGER,
      water_oz      NUMERIC(5,1),
      UNIQUE(user_id, date)
    );

    CREATE TABLE IF NOT EXISTS meals (
      id         SERIAL PRIMARY KEY,
      day_id     INTEGER REFERENCES days(id) ON DELETE CASCADE,
      name       TEXT NOT NULL,
      calories   INTEGER NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Add metric columns to existing tables if upgrading
  await pool.query(`
    ALTER TABLE days ADD COLUMN IF NOT EXISTS bp_systolic  INTEGER;
    ALTER TABLE days ADD COLUMN IF NOT EXISTS bp_diastolic INTEGER;
    ALTER TABLE days ADD COLUMN IF NOT EXISTS heart_rate   INTEGER;
    ALTER TABLE days ADD COLUMN IF NOT EXISTS water_oz     NUMERIC(5,1);
  `).catch(() => {});

  console.log('Database ready');
}

// ─── AUTH MIDDLEWARE ─────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username, goal',
      [username.toLowerCase().trim(), hash]
    );
    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '90d' });
    res.json({ token, username: user.username, goal: user.goal });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username already taken' });
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username.toLowerCase().trim()]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid username or password' });
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '90d' });
    res.json({ token, username: user.username, goal: user.goal });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── USER ROUTES ─────────────────────────────────────────────────────────────

app.put('/api/goal', authMiddleware, async (req, res) => {
  const { goal } = req.body;
  if (!goal || isNaN(goal) || goal < 1) return res.status(400).json({ error: 'Invalid goal' });
  await pool.query('UPDATE users SET goal = $1 WHERE id = $2', [goal, req.userId]);
  res.json({ goal });
});

// ─── DAY HELPERS ─────────────────────────────────────────────────────────────

async function getOrCreateDay(userId, date) {
  let result = await pool.query('SELECT * FROM days WHERE user_id = $1 AND date = $2', [userId, date]);
  if (result.rows.length === 0) {
    result = await pool.query('INSERT INTO days (user_id, date) VALUES ($1, $2) RETURNING *', [userId, date]);
  }
  return result.rows[0];
}

// ─── DAY ROUTES ──────────────────────────────────────────────────────────────

app.get('/api/days/:date', authMiddleware, async (req, res) => {
  const { date } = req.params;
  try {
    const day = await getOrCreateDay(req.userId, date);
    const meals = await pool.query('SELECT id, name, calories FROM meals WHERE day_id = $1 ORDER BY created_at', [day.id]);
    res.json({
      date,
      weight: day.weight,
      bp_systolic: day.bp_systolic,
      bp_diastolic: day.bp_diastolic,
      heart_rate: day.heart_rate,
      water_oz: day.water_oz,
      meals: meals.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/week/:startDate', authMiddleware, async (req, res) => {
  const { startDate } = req.params;
  try {
    const result = await pool.query(`
      SELECT gs.date, COALESCE(SUM(m.calories), 0) AS total_calories
      FROM generate_series($1::date, $1::date + interval '6 days', interval '1 day') AS gs(date)
      LEFT JOIN days d ON d.date = gs.date AND d.user_id = $2
      LEFT JOIN meals m ON m.day_id = d.id
      GROUP BY gs.date ORDER BY gs.date
    `, [startDate, req.userId]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── METRIC HISTORY ROUTES ────────────────────────────────────────────────────

app.get('/api/metrics/weight', authMiddleware, async (req, res) => {
  const result = await pool.query(
    'SELECT date, weight FROM days WHERE user_id=$1 AND weight IS NOT NULL ORDER BY date',
    [req.userId]
  );
  res.json(result.rows);
});

app.get('/api/metrics/bp', authMiddleware, async (req, res) => {
  const result = await pool.query(
    'SELECT date, bp_systolic, bp_diastolic FROM days WHERE user_id=$1 AND bp_systolic IS NOT NULL ORDER BY date',
    [req.userId]
  );
  res.json(result.rows);
});

app.get('/api/metrics/heart-rate', authMiddleware, async (req, res) => {
  const result = await pool.query(
    'SELECT date, heart_rate FROM days WHERE user_id=$1 AND heart_rate IS NOT NULL ORDER BY date',
    [req.userId]
  );
  res.json(result.rows);
});

app.get('/api/metrics/water', authMiddleware, async (req, res) => {
  const result = await pool.query(
    'SELECT date, water_oz FROM days WHERE user_id=$1 AND water_oz IS NOT NULL ORDER BY date',
    [req.userId]
  );
  res.json(result.rows);
});

// ─── LOG METRICS ─────────────────────────────────────────────────────────────

app.put('/api/days/:date/metrics', authMiddleware, async (req, res) => {
  const { date } = req.params;
  const { weight, bp_systolic, bp_diastolic, heart_rate, water_oz } = req.body;
  try {
    const day = await getOrCreateDay(req.userId, date);
    const updates = [];
    const vals = [day.id];
    let idx = 2;
    if (weight      !== undefined) { updates.push(`weight=$${idx++}`);       vals.push(weight); }
    if (bp_systolic !== undefined) { updates.push(`bp_systolic=$${idx++}`);  vals.push(bp_systolic); }
    if (bp_diastolic!== undefined) { updates.push(`bp_diastolic=$${idx++}`); vals.push(bp_diastolic); }
    if (heart_rate  !== undefined) { updates.push(`heart_rate=$${idx++}`);   vals.push(heart_rate); }
    if (water_oz    !== undefined) { updates.push(`water_oz=$${idx++}`);     vals.push(water_oz); }
    if (updates.length === 0) return res.status(400).json({ error: 'No metrics provided' });
    await pool.query(`UPDATE days SET ${updates.join(', ')} WHERE id=$1`, vals);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── MEAL ROUTES ─────────────────────────────────────────────────────────────

app.post('/api/days/:date/meals', authMiddleware, async (req, res) => {
  const { date } = req.params;
  const { name, calories } = req.body;
  if (!name || !calories || isNaN(calories)) return res.status(400).json({ error: 'Name and calories required' });
  try {
    const day = await getOrCreateDay(req.userId, date);
    const result = await pool.query(
      'INSERT INTO meals (day_id, name, calories) VALUES ($1, $2, $3) RETURNING id, name, calories',
      [day.id, name, calories]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/meals/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const check = await pool.query(`
      SELECT m.id FROM meals m JOIN days d ON d.id = m.day_id
      WHERE m.id=$1 AND d.user_id=$2
    `, [id, req.userId]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    await pool.query('DELETE FROM meals WHERE id=$1', [id]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── FOOD SEARCH (USDA FoodData Central) ────────────────────────────────────

app.get('/api/food-search', authMiddleware, async (req, res) => {
  const { q } = req.query;
  if (!q || q.length < 2) return res.json([]);
  const USDA_KEY = process.env.USDA_API_KEY;
  if (!USDA_KEY) return res.status(500).json({ error: 'USDA API key not configured' });
  try {
    // Search Foundation + SR Legacy first (whole foods, most accurate)
    // then fall back to Branded/Survey if needed
    const searchFoundation = `https://api.nal.usda.gov/fdc/v1/foods/search?query=${encodeURIComponent(q)}&pageSize=10&api_key=${USDA_KEY}&dataType=Foundation,SR%20Legacy`;
    const searchBranded = `https://api.nal.usda.gov/fdc/v1/foods/search?query=${encodeURIComponent(q)}&pageSize=8&api_key=${USDA_KEY}&dataType=Branded,Survey%20(FNDDS)`;

    const [r1, r2] = await Promise.all([fetch(searchFoundation), fetch(searchBranded)]);
    const [d1, d2] = await Promise.all([r1.json(), r2.json()]);

    // Combine: Foundation/SR Legacy first, then Branded
    const foods = [...(d1.foods || []), ...(d2.foods || [])];

    function extractKcal(nutrients) {
      const e = (nutrients || []).find(n =>
        n.nutrientId === 1008 || n.nutrientId === 2047 || n.nutrientId === 2048 ||
        n.nutrientNumber === '208' ||
        (n.nutrientName && n.nutrientName.toLowerCase() === 'energy')
      );
      return e ? (e.value ?? e.amount ?? 0) : 0;
    }

    const results = foods
      .map(f => {
        const kcalPer100g = extractKcal(f.foodNutrients);
        if (!kcalPer100g) return null;
        const brand = f.brandOwner || f.brandName || null;
        const dataLabel = f.dataType === 'Foundation' || f.dataType === 'SR Legacy' ? null : brand;
        const name = f.description + (dataLabel ? ` (${dataLabel})` : '');
        return {
          fdcId: f.fdcId,
          name,
          dataType: f.dataType,
          kcalPer100g: Math.round(kcalPer100g),
          portions: buildFallbackPortions(kcalPer100g, f.servingSize, f.servingSizeUnit)
        };
      })
      .filter(Boolean)
      .slice(0, 12);

    res.json(results);
  } catch (err) {
    console.error('Food search error:', err);
    res.json([]);
  }
});

function buildFallbackPortions(kcalPer100g, servingSize, servingSizeUnit) {
  const portions = [];
  if (servingSize && servingSizeUnit) {
    const unit = servingSizeUnit.toLowerCase();
    if ((unit === 'g' || unit === 'ml') && servingSize > 0) {
      portions.push({
        label: `1 serving (${servingSize}${servingSizeUnit})`,
        grams: servingSize,
        kcal: Math.round((kcalPer100g * servingSize) / 100)
      });
    }
  }
  // These are fallbacks — pushed to the end
  portions.push({ label: '100g', grams: 100, kcal: Math.round(kcalPer100g) });
  portions.push({ label: '1 oz (28g)', grams: 28, kcal: Math.round((kcalPer100g * 28) / 100) });
  return portions;
}

// Fetch full food detail including measures (called when user selects a result)
app.get('/api/food-detail/:fdcId', authMiddleware, async (req, res) => {
  const { fdcId } = req.params;
  const USDA_KEY = process.env.USDA_API_KEY;
  try {
    const url = `https://api.nal.usda.gov/fdc/v1/food/${fdcId}?api_key=${USDA_KEY}`;
    const response = await fetch(url);
    const f = await response.json();

    const nutrients = f.foodNutrients || [];
    const energy = nutrients.find(n =>
      n.nutrient && (n.nutrient.id === 1008 || n.nutrient.number === '208')
    );
    const kcalPer100g = energy ? (energy.amount || 0) : 0;

    const portions = [];

    // Named measures first — these are what people actually use (e.g. "1 large egg", "1 cup")
    if (f.foodPortions && f.foodPortions.length > 0) {
      f.foodPortions.forEach(p => {
        const label = p.modifier || p.measureUnit?.name || null;
        if (label && p.gramWeight && label.toLowerCase() !== 'quantity not specified') {
          portions.push({
            label: `1 ${label}`,
            grams: p.gramWeight,
            kcal: Math.round((kcalPer100g * p.gramWeight) / 100)
          });
        }
      });
    }

    // Serving size from branded foods
    if (f.servingSize && f.servingSizeUnit) {
      const unit = f.servingSizeUnit.toLowerCase();
      if ((unit === 'g' || unit === 'ml') && f.servingSize > 0) {
        portions.push({
          label: `1 serving (${f.servingSize}${f.servingSizeUnit})`,
          grams: f.servingSize,
          kcal: Math.round((kcalPer100g * f.servingSize) / 100)
        });
      }
    }

    // 100g and oz go at the END as fallbacks only
    portions.push({ label: '100g', grams: 100, kcal: Math.round(kcalPer100g) });
    portions.push({ label: '1 oz (28g)', grams: 28, kcal: Math.round((kcalPer100g * 28) / 100) });

    // Dedupe
    const seen = new Set();
    const uniquePortions = portions.filter(p => {
      if (seen.has(p.label)) return false;
      seen.add(p.label); return true;
    });

    res.json({ fdcId, kcalPer100g: Math.round(kcalPer100g), portions: uniquePortions });
  } catch (err) {
    console.error('Food detail error:', err);
    res.status(500).json({ error: 'Failed to fetch food detail' });
  }
});

// ─── CATCH-ALL ───────────────────────────────────────────────────────────────

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── START ───────────────────────────────────────────────────────────────────

initDB().then(() => {
  app.listen(PORT, () => console.log(`Calorie tracker running on port ${PORT}`));
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
