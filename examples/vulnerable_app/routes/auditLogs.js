// ⚠️ 故意有漏洞:展示 SAST 偵測用,請勿用於正式環境。
const express = require('express');
const router = express.Router();
const db = require('../db');

// 二階 SQL Injection:guard.branch 直接內插進 SQL
router.get('/audit-logs', async (req, res) => {
  const guard = req.user;
  // 漏洞:樣板字串內插使用者可控的 branch 值
  const sql = `SELECT * FROM audit_logs WHERE branch = '${guard.branch}' ORDER BY ts DESC`;
  const rows = await db.query(sql);
  res.json(rows);
});

// 另一處字串串接組 SQL
router.get('/search', async (req, res) => {
  const rows = await db.query("SELECT * FROM logs WHERE msg LIKE '%" + req.query.q + "%'");
  res.json(rows);
});

module.exports = router;
