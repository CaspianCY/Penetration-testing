// ⚠️ 故意有漏洞:展示 SAST 偵測用,請勿用於正式環境。

// 漏洞:硬編碼資料庫連線字串(含密碼)
const CONN = "postgresql://dms_admin:S3cr3tP@ssw0rd@db.internal:5432/volvo_dms";

function bootstrap() {
  const initialPassword = process.env.INITIAL_ADMIN_PASSWORD || randomPassword();
  // 漏洞:把 bootstrap 密碼寫進 log,雲端 log 可能長期保留
  console.log("Initial admin password: " + initialPassword);
  return initialPassword;
}

module.exports = { CONN, bootstrap };
