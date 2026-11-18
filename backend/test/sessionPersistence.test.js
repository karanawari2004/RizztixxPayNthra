const assert = require("node:assert/strict");
const { test } = require("node:test");

process.env.JWT_SECRET = "test-jwt-secret-that-is-at-least-32-characters";
process.env.NODE_ENV = "test";

const Session = require("../model/Session");
const { setAuthCookie } = require("../utils/authCookie");
const authenticateToken = require("../middleware/authenticateToken");

test("auth cookie creation stores a session that is required for authentication", async () => {
  const originalCreate = Session.create;
  const originalFindOne = Session.findOne;
  const records = [];
  let cookie;

  Session.create = async (record) => {
    records.push(record);
    return record;
  };
  Session.findOne = async (query) =>
    records.find(
      (record) =>
        record.tokenId === query.tokenId &&
        String(record.accountId) === query.accountId &&
        record.expiresAt > query.expiresAt.$gt
    ) || null;

  try {
    await setAuthCookie(
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

    assert.equal(records.length, 1);
    assert.equal(records[0].accountId.toString(), "account-123");
    assert.ok(records[0].expiresAt > new Date());
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

    await authenticateToken(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, true);
    assert.equal(req.user.id, "account-123");
    assert.equal(req.sessionId, records[0].tokenId);

    records.length = 0;
    nextCalled = false;
    await authenticateToken(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 401);
    assert.equal(res.clearedCookie, true);
  } finally {
    Session.create = originalCreate;
    Session.findOne = originalFindOne;
  }
});
