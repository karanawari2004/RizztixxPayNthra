const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const Session = require("../model/Session");

const isProd = process.env.NODE_ENV === "production";
const sessionDurationMs = 8 * 60 * 60 * 1000;

const cookieOptions = {
  httpOnly: true,
  secure: isProd,
  sameSite: isProd ? "none" : "lax",
  path: "/",
  maxAge: sessionDurationMs,
};

async function setAuthCookie(res, account) {
  const tokenId = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + sessionDurationMs);
  const token = jwt.sign(
    {
      sub: account._id.toString(),
      username: account.username,
      role: account.role,
      jti: tokenId,
    },
    process.env.JWT_SECRET,
    {
      algorithm: "HS256",
      expiresIn: "8h",
    }
  );

  await Session.create({
    tokenId,
    accountId: account._id,
    expiresAt,
  });

  res.cookie("access_token", token, cookieOptions);
}

function clearAuthCookie(res) {
  res.clearCookie("access_token", {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
    path: "/",
  });
}

module.exports = { setAuthCookie, clearAuthCookie };
