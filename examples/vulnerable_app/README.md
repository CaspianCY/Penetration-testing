# ⚠️ 故意有漏洞的範例程式(Intentionally Vulnerable)

本目錄是**故意寫成有漏洞**的範例程式碼,僅用於展示 Sentinel 白箱 SAST 引擎能
偵測哪些漏洞型樣(類似 DVWA / WebGoat 的用途)。

**請勿部署到任何正式環境。**

涵蓋的示範漏洞:SQL injection(樣板字串內插)、Stored XSS(innerHTML)、
硬編碼資料庫連線字串、敏感資訊寫入 log、已知 CVE 的相依套件、命令注入。
