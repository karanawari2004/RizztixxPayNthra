const jwt = require("jsonwebtoken");
const isProd = process.env.NODE_ENV === "production";
const sessionDurationMs = 8 * 60 * 60 * 1000;

const cookieOptions = {
  httpOnly: true,
  secure: isProd,
  sameSite: isProd ? "none" : "lax",
  path: "/",
  maxAge: sessionDurationMs,
};

function setAuthCookie(res, account) {
  const token = jwt.sign(
    {
      sub: account._id.toString(),
      username: account.username,
      role: account.role,
    },
    process.env.JWT_SECRET,
    {
      algorithm: "HS256",
      expiresIn: "8h",
    }
  );

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
