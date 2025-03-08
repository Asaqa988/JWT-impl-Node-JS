const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");
require("dotenv").config();

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.SECRET_KEY || "supersecretkey";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "refreshsupersecret";
const TOKEN_EXPIRY = "1h";
const REFRESH_EXPIRY = "7d";

const users = [];
const refreshTokens = new Map();

app.post("/register", async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ message: "All fields are required" });
  }

  if (users.some((u) => u.username === username)) {
    return res.status(400).json({ message: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ id: uuidv4(), username, password: hashedPassword, role });

  res.status(201).json({ message: "User registered successfully" });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  refreshTokens.set(refreshToken, user.username);
  res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: false });
  res.json({ accessToken });
});

const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(403).json({ message: "Access denied" });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid token" });
    req.user = decoded;
    next();
  });
};

const authorize = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden: Insufficient permissions" });
    }
    next();
  };
};

app.get("/admin", verifyToken, authorize(["admin"]), (req, res) => {
  res.json({ message: `Welcome, admin ${req.user.username}` });
});

app.post("/refresh", (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken || !refreshTokens.has(refreshToken)) {
    return res.status(403).json({ message: "Invalid refresh token" });
  }

  jwt.verify(refreshToken, REFRESH_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid refresh token" });

    const newAccessToken = generateAccessToken({ id: decoded.id, username: decoded.username, role: decoded.role });
    res.json({ accessToken: newAccessToken });
  });
});

app.post("/logout", (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (refreshToken) {
    refreshTokens.delete(refreshToken);
  }
  res.clearCookie("refreshToken");
  res.json({ message: "Logged out successfully" });
});

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: TOKEN_EXPIRY });
};

const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRY });
};

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
