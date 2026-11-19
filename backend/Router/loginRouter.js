const express = require("express");
const bcrypt = require("bcryptjs");
const Account = require("../model/Account");
const authenticateToken = require("../middleware/authenticateToken");
const { setAuthCookie, clearAuthCookie } = require("../utils/authCookie");

const router = express.Router();

router.post("/login", async (req, res) => {
  const { username, password } = req.body || {};

  if (
    typeof username !== "string" ||
    !username.trim() ||
    typeof password !== "string" ||
    !password
  ) {
    return res.status(400).json({
      success: false,
      message: "Username and password are required",
    });
  }

  try {
    const account = await Account.findOne({
      username: username.trim().toLowerCase(),
    });

    if (!account || !(await bcrypt.compare(password, account.passwordHash))) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password",
      });
    }

    await setAuthCookie(res, account);
    return res.json({
      success: true,
      message: "Login successful",
      user: { username: account.username, role: account.role },
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({
      success: false,
      message: "Unable to log in",
    });
  }
});


router.get("/session", authenticateToken, (req, res) => {
  res.json({ success: true, user: req.user });
});


router.post("/logout", (req, res) => {
  clearAuthCookie(res);
  return res.json({ success: true, message: "Logged out successfully" });
});

module.exports = router;