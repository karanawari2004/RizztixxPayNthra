const assert = require("node:assert/strict");
const { test } = require("node:test");

process.env.JWT_SECRET = "test-jwt-secret-that-is-at-least-32-characters";
process.env.NODE_ENV = "test";

const { setAuthCookie } = require("../utils/authCookie");
const authenticateToken = require("../middleware/authenticateToken");

test("auth cookie creation and JWT authentication work without a database session", () => {
  let cookie;
  setAuthCookie(
      {
        cookie: (_name, value) => {
          cookie = value;
        },
      },
      {
        _id: { toString: () => "account-123" },
        username: "admin",
        role: "admin",
      }
    );

    assert.ok(cookie);

    const req = { cookies: { access_token: cookie } };
    const res = {
      statusCode: null,
      clearedCookie: false,
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(body) {
        this.body = body;
      },
      clearCookie() {
        this.clearedCookie = true;
      },
    };
    let nextCalled = false;

    authenticateToken(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, true);
    assert.equal(req.user.id, "account-123");
});

test("missing and invalid JWT cookies are rejected", () => {
  const missingRes = {
    statusCode: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
    },
  };
  let missingNextCalled = false;

  authenticateToken({ cookies: {} }, missingRes, () => {
    missingNextCalled = true;
  });

  assert.equal(missingNextCalled, false);
  assert.equal(missingRes.statusCode, 401);
  assert.equal(missingRes.body.message, "Please log in");

  const invalidRes = {
    statusCode: null,
    clearedCookie: false,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
    },
    clearCookie() {
      this.clearedCookie = true;
    },
  };
  let invalidNextCalled = false;

  authenticateToken(
    { cookies: { access_token: "invalid.jwt.token" } },
    invalidRes,
    () => {
      invalidNextCalled = true;
    }
  );

  assert.equal(invalidNextCalled, false);
  assert.equal(invalidRes.statusCode, 401);
  assert.equal(invalidRes.clearedCookie, true);
});
