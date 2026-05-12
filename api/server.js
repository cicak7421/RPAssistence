// TicketForge — Backend API
// Handles: Discord OAuth, guild configs, API for dashboard

import express from "express";
import cors from "cors";
import session from "express-session";
import fetch from "node-fetch";
import { JsonDB, Config } from "node-json-db";
import { mkdirSync } from "fs";
import { dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Pastikan folder data/ ada sebelum JsonDB init
mkdirSync(new URL("../../../data", import.meta.url).pathname, { recursive: true });

const app = express();
const db = new JsonDB(new Config("data/ticketforge", true, true, "/"));

// ── CONFIG ───────────────────────────────────────────────────────────────────
const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI = "http://localhost:3001/auth/callback",
  SESSION_SECRET = "change_this_secret",
  DASHBOARD_URL = "http://localhost:5173",
  PORT = 3001,
} = process.env;

// ── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(cors({ origin: DASHBOARD_URL, credentials: true }));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === "production", httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 },
}));

// ── HELPERS ───────────────────────────────────────────────────────────────────
async function discordRequest(endpoint, token) {
  const res = await fetch(`https://discord.com/api/v10${endpoint}`, {
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`Discord API error: ${res.status}`);
  return res.json();
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Unauthorized" });
  next();
}

async function dbGet(path, fallback = null) {
  try { return await db.getData(path); } catch { return fallback; }
}

// ── OAUTH ─────────────────────────────────────────────────────────────────────
// GET /auth/url → return Discord OAuth URL
app.get("/auth/url", (req, res) => {
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: "code",
    scope: "identify guilds",
  });
  res.json({ url: `https://discord.com/oauth2/authorize?${params}` });
});

// GET /auth/callback — exchange code → token → session
app.get("/auth/callback", async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).json({ error: "No code" });

  try {
    // Exchange code for token
    const tokenRes = await fetch("https://discord.com/api/v10/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: DISCORD_REDIRECT_URI,
      }),
    });
    const tokenData = await tokenRes.json();
    if (tokenData.error) throw new Error(tokenData.error);

    // Fetch user
    const user = await discordRequest("/users/@me", tokenData.access_token);
    const guilds = await discordRequest("/users/@me/guilds", tokenData.access_token);

    // Store session
    req.session.user = { id: user.id, username: user.username, discriminator: user.discriminator, avatar: user.avatar };
    req.session.guilds = guilds;

    // Redirect to dashboard
    res.redirect(`${DASHBOARD_URL}?login=success`);
  } catch (err) {
    console.error("OAuth error:", err);
    res.redirect(`${DASHBOARD_URL}?error=auth_failed`);
  }
});

// GET /auth/me
app.get("/auth/me", requireAuth, (req, res) => {
  res.json(req.session.user);
});

// POST /auth/logout
app.post("/auth/logout", (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// ── GUILDS ────────────────────────────────────────────────────────────────────
// GET /guilds — user's guilds where they're admin
app.get("/guilds", requireAuth, (req, res) => {
  const guilds = req.session.guilds || [];
  // Filter: user has ADMINISTRATOR (0x8) or MANAGE_GUILD (0x20)
  const adminGuilds = guilds.filter(g => (parseInt(g.permissions) & 0x8) || (parseInt(g.permissions) & 0x20));
  res.json(adminGuilds);
});

// ── TICKET CONFIGS ────────────────────────────────────────────────────────────
// GET /guilds/:guildId/configs
app.get("/guilds/:guildId/configs", requireAuth, async (req, res) => {
  const { guildId } = req.params;
  const configs = await dbGet(`/guilds/${guildId}/configs`, []);
  res.json(configs);
});

// POST /guilds/:guildId/configs — create
app.post("/guilds/:guildId/configs", requireAuth, async (req, res) => {
  const { guildId } = req.params;
  const config = {
    id: `cfg_${Date.now()}`,
    createdBy: req.session.user.id,
    createdAt: new Date().toISOString(),
    ...req.body,
  };

  try {
    let configs = await dbGet(`/guilds/${guildId}/configs`, []);
    configs.push(config);
    await db.push(`/guilds/${guildId}/configs`, configs);
    res.json(config);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /guilds/:guildId/configs/:configId — update
app.put("/guilds/:guildId/configs/:configId", requireAuth, async (req, res) => {
  const { guildId, configId } = req.params;
  try {
    let configs = await dbGet(`/guilds/${guildId}/configs`, []);
    const idx = configs.findIndex(c => c.id === configId);
    if (idx === -1) return res.status(404).json({ error: "Config not found" });

    configs[idx] = { ...configs[idx], ...req.body, updatedAt: new Date().toISOString() };
    await db.push(`/guilds/${guildId}/configs`, configs);
    res.json(configs[idx]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /guilds/:guildId/configs/:configId
app.delete("/guilds/:guildId/configs/:configId", requireAuth, async (req, res) => {
  const { guildId, configId } = req.params;
  try {
    let configs = await dbGet(`/guilds/${guildId}/configs`, []);
    configs = configs.filter(c => c.id !== configId);
    await db.push(`/guilds/${guildId}/configs`, configs);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── BOT INTERNAL API (called by bot, not dashboard) ────────────────────────────
// GET /internal/guilds/:guildId/configs — bot fetch config
app.get("/internal/guilds/:guildId/configs", async (req, res) => {
  const { guildId } = req.params;
  if (req.headers["x-bot-secret"] !== process.env.BOT_SECRET) {
    return res.status(403).json({ error: "Forbidden" });
  }
  const configs = await dbGet(`/guilds/${guildId}/configs`, []);
  res.json(configs);
});

// POST /internal/tickets — log ticket event from bot
app.post("/internal/tickets", async (req, res) => {
  if (req.headers["x-bot-secret"] !== process.env.BOT_SECRET) {
    return res.status(403).json({ error: "Forbidden" });
  }
  const { guildId, event } = req.body;
  try {
    let tickets = await dbGet(`/guilds/${guildId}/tickets`, []);
    tickets.push({ id: `t_${Date.now()}`, ...event, timestamp: new Date().toISOString() });
    // Keep last 1000
    if (tickets.length > 1000) tickets = tickets.slice(-1000);
    await db.push(`/guilds/${guildId}/tickets`, tickets);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /internal/guilds/:guildId/tickets — stats for dashboard
app.get("/guilds/:guildId/tickets", requireAuth, async (req, res) => {
  const { guildId } = req.params;
  const tickets = await dbGet(`/guilds/${guildId}/tickets`, []);
  res.json({
    total: tickets.length,
    open: tickets.filter(t => t.status === "open").length,
    closed: tickets.filter(t => t.status === "closed").length,
    recent: tickets.slice(-10).reverse(),
  });
});

app.listen(PORT, () => console.log(`✅ TicketForge API running on :${PORT}`));
