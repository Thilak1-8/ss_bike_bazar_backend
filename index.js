import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import cors from "cors";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = process.env.PORT || 10000;

// PostgreSQL Client Setup
const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Required for Render PostgreSQL
});

db.connect((err) => {
  if (err) {
    console.error("Database connection error:", err.stack);
    process.exit(1);
  }
  console.log("✅ Connected to padmasai_db");
});

// Middleware
app.use(cors({
  origin: ["https://ss-bike-bazar-frontend.vercel.app", "http://localhost:3000"],
  credentials: true,
}));
app.use(express.json());

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "default_secret_key";

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error("Token verification error:", err);
    res.status(401).json({ error: "Invalid token" });
  }
};

// Routes

app.get("/", (req, res) => {
  res.send("🚀 Backend server is running.");
});

// Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await db.query(
      "SELECT * FROM admins WHERE LOWER(username) = LOWER($1)",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.status(200).json({ message: "Login successful", token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Token Verification
app.post("/api/verify-token", (req, res) => {
  const { token } = req.body;

  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.status(200).json({ valid: true, user: decoded });
  } catch (err) {
    console.error("Token verification error:", err);
    res.status(401).json({ error: "Invalid token" });
  }
});

// Add a new bike (protected)
app.post("/api/bikes", verifyToken, async (req, res) => {
  const { url, name, model, engine, fuel, color, warranty } = req.body;

  if (!url || !name || !model || !engine || !fuel || !color || !warranty) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const result = await db.query(
      "INSERT INTO bikes (url, name, model, engine, fuel, color, warranty) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
      [url, name, model, engine, fuel, color, warranty]
    );
    res.status(201).json({ message: "Bike added successfully", bike: result.rows[0] });
  } catch (err) {
    console.error("Error adding bike:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Update bike (protected)
app.put("/api/bikes/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { url, name, model, engine, fuel, color, warranty } = req.body;

  if (!url || !name || !model || !engine || !fuel || !color || !warranty) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const result = await db.query(
      "UPDATE bikes SET url = $1, name = $2, model = $3, engine = $4, fuel = $5, color = $6, warranty = $7 WHERE id = $8 RETURNING *",
      [url, name, model, engine, fuel, color, warranty, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Bike not found" });
    }
    res.status(200).json({ message: "Bike updated successfully", bike: result.rows[0] });
  } catch (err) {
    console.error("Error updating bike:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get all bikes (public)
app.get("/api/bikes", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM bikes");
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("Error fetching bikes:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get bike by ID (public)
app.get("/api/bikes/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query("SELECT * FROM bikes WHERE id = $1", [parseInt(id)]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Bike not found" });
    }
    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error("Error fetching bike:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Delete bike (protected)
app.delete("/api/bikes/:id", verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await db.query("DELETE FROM bikes WHERE id = $1 RETURNING *", [parseInt(id)]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Bike not found" });
    }
    res.status(200).json({ message: "Bike deleted successfully" });
  } catch (err) {
    console.error("Error deleting bike:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Submit contact form
app.post("/api/contact", async (req, res) => {
  const { name, phone, email, query } = req.body;

  if (!name || !phone || !email || !query) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const result = await db.query(
      "INSERT INTO contact_submissions (name, phone, email, query) VALUES ($1, $2, $3, $4) RETURNING *",
      [name, phone, email, query]
    );
    res.status(201).json({ message: "Contact form submitted successfully", submission: result.rows[0] });
  } catch (err) {
    console.error("Error saving contact submission:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get all contact submissions (protected)
app.get("/api/contact-submissions", verifyToken, async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM contact_submissions ORDER BY submitted_at DESC");
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("Error fetching contact submissions:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});
