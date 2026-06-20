# Sentinel — Web 弱點掃描與報告平台

一個以 Flask 打造的網頁式安全測試平台。你指定一個目標網址,平台會對它執行
**非破壞性**的弱點掃描,即時回報進度,列出弱點與對應的修補建議,並可產出
HTML / Markdown / JSON 報告。內建一個 AI 模組(由 Claude 驅動),會分析掃描
結果、排定修補優先序,並產生可執行的修補計畫。

> ⚠️ **僅供授權測試使用。** 請只掃描你**擁有**或已**取得書面授權**測試的系統。
> 詳見 [`AUTHORIZATION.md`](AUTHORIZATION.md)。

## 功能

- **指定目標** — 在網頁輸入一個 URL 即可開始。
- **被動弱掃** — 只做讀取式檢查,不送出攻擊 payload、不嘗試利用漏洞:
  - 安全回應標頭(CSP、HSTS、X-Frame-Options、X-Content-Type-Options…)
  - TLS / 憑證(到期、協定版本、自簽)
  - Cookie 旗標(Secure / HttpOnly / SameSite)
  - 資訊外洩 / 敏感檔案(`.git`、`.env`、`server-status`…)
  - 表單與 CSRF / 密碼欄位處理
- **主動測試(opt-in)** — 對表單與參數送出**非破壞性**探測 payload,驗證
  「是否打得進來、是否可能竄改資料」:
  - SQL Injection(錯誤型 / 布林型 / 進階時間延遲型)
  - 反射型 XSS(標記反射偵測)
  - 開放轉址(Open Redirect)
  - 僅**證明漏洞存在**,不執行 UPDATE / DELETE / DROP 去更動資料
- **深度掃描 / 工具編排(opt-in)** — 呼叫業界真實工具,依 PTES 階段編排,
  主控台即時輸出;有裝就跑、沒裝自動退回內建檢查:
  - **Nmap**(埠/服務)、**WhatWeb**(技術指紋)、**wafw00f**(WAF 偵測)、
    **ffuf**(內容探索)、**sslscan**(TLS 深掃)、**Nuclei**(模板掃描)、
    **Nikto**(Web 伺服器)、**WPScan**(WordPress)、**sqlmap**(SQLi,安全模式)
  - findings 映射到 OWASP / CWE / **CVSS 3.1 向量** / **MITRE ATT&CK** 技術
  - 工具輸出與這些對應一併寫入 .docx 報告(含「使用的工具」一節)
- **即時進度儀表板** — 攻擊方(測試者)可即時看到每一項檢查的進度。
- **弱點報告** — 依嚴重度分類,每項弱點都附修補建議與參考連結。
- **修補指引** — 直接告訴你「怎麼修」。
- **AI 模組** — Claude 分析整體弱點態勢、排優先序、產生修補計畫。
- **低衝擊模式** — 限速、降低併發、自訂 User-Agent,減少對目標負載。
- **資料持久化** — 掃描任務、弱點、授權紀錄、AI 分析皆寫入資料庫(PostgreSQL,
  本機可退回 SQLite),程式重啟後仍可查閱歷史。
- **白箱 SAST** — 對提供的原始碼做靜態分析,找出 SQLi / XSS / 硬編碼機密 /
  弱雜湊 / 命令注入 / 已知 CVE 相依套件,帶「檔案:行號」位置。
- **灰箱測試** — 帶認證(Cookie / 標頭)掃描登入後的端點。
- **案件編排(PTES)** — 依偵察→弱點分析→漏洞利用驗證→權限提升評估→報告(含清理)
  的階段組織測試;對應 PTES / OSSTMM / OWASP WSTG / OWASP Top 10。
- **專業 .docx 報告** — 文件管控、管理摘要、Findings 統計、OWASP 覆蓋率矩陣、
  每個 finding 帶 OWASP / CWE / CVSS / PoC / 修補成本、P0–P3 修補路線圖、
  跨次稽核 New / Recurring / Fixed 追蹤、清理與機密聲明。

## 設計上刻意「不做」的事

本平台**不提供**規避偵測 / 反鑑識 / 清除日誌 / IDS-WAF 規避這類功能,也**不**
對目標發送破壞性或阻斷服務(DoS)流量。「低衝擊模式」是為了減少對目標的負載,
不是為了躲避對方的防禦監控。

關於主動測試:本工具採「**無害驗證**」原則——只證明漏洞是否存在(例如以單引號觸發
DB 錯誤、用布林真假/時間延遲判斷注入),據此回報「攻擊者可能讀取甚至**竄改**資料」
的風險,但**不會**實際執行 `UPDATE` / `DELETE` / `DROP` 等會破壞或更動目標資料的語句,
XSS 也僅檢查標記是否被未跳脫反射、不執行實際攻擊。所有請求受 `max_requests` 上限保護。

## 快速開始

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 選用:安裝業界工具以啟用「深度掃描」(沒裝會自動退回內建檢查)
sudo apt-get install -y nmap nikto sqlmap        # Debian/Ubuntu
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
nuclei -update-templates                          # 首次需下載模板

# 選用:設定 Claude API 金鑰以啟用 AI 模組(未設定時自動退回規則式分析)
export ANTHROPIC_API_KEY="sk-ant-..."

# 選用:指向 PostgreSQL(未設定時退回單檔 SQLite)
export DATABASE_URL="postgresql+psycopg://user:pass@localhost:5432/sentinel"

python app.py
# 開啟 http://127.0.0.1:5000
```

### Kali 工具環境(Docker — 推薦的完整部署)

最完整的跑法是用 **Kali Linux 容器**:內建所有編排器會用到的工具,並一起帶起
PostgreSQL(資料持久化)。在任何有 Docker 的主機上:

```bash
docker compose up --build
# 開啟 http://localhost:5000 —— 8 個工具全部就緒
```

- 基底為 `kalilinux/kali-rolling`,從 Kali repo 安裝:
  `nmap nikto sqlmap whatweb wafw00f sslscan gobuster ffuf nuclei wfuzz dirb dnsrecon`
- 資料存於具名 volume(`sentinel-db`),容器重啟仍在。
- 要啟用 AI 模組:在 `docker-compose.yml` 取消 `ANTHROPIC_API_KEY` 註解並填金鑰。

> 「深度掃描」的設計是**有裝就用、沒裝退回內建檢查**——所以不在 Kali 容器、
> 只裝部分工具時也能跑,缺的工具會在主控台標示「未安裝」。

### 部署到 Zeabur / 雲端平台

平台會自動 build 根目錄的 `Dockerfile`。需要設定的環境變數:

| 變數 | 用途 |
|---|---|
| `SENTINEL_PASSWORD`(或 `PASSWORD`) | **啟用登入保護**。公開部署**務必設定**,否則任何人都能用它掃描任意目標。 |
| `DATABASE_URL` | PostgreSQL 連線字串。或改設下列 `POSTGRES_*`。 |
| `POSTGRES_HOST` / `POSTGRES_PORT` / `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | 未給 `DATABASE_URL` 時由這些自動組合(需要 `POSTGRES_HOST`)。 |
| `PORT`(平台注入)/ `SENTINEL_PORT` | 監聽埠;`entrypoint.sh` 會自動套用。 |
| `ANTHROPIC_API_KEY` | 選用,啟用 AI 模組。 |

> ⚠️ **公開部署的安全須知**:這是一個會主動對目標送出掃描/攻擊流量的工具。
> 公開在網路上而**不設 `SENTINEL_PASSWORD`**,等於讓任何人拿你的伺服器去攻擊
> 任意目標——務必設定登入密碼,並考慮以 `SENTINEL_ALLOWED_HOSTS` 限制可掃目標。
> 環境變數請只在平台的設定介面填寫,**切勿提交進版控**。

### 案件編排與專業報告(engage.py)

`engage.py` 依 PTES 階段執行一次完整案件並產出 `.docx` 報告:

```bash
# 白箱 SAST(分析原始碼)
python engage.py --name "Volvo DMS" --sast ./examples/vulnerable_app \
    --methodology white-box --test-type SAST --tester "你的名字" --out volvo.docx

# 灰箱 DAST(帶 session cookie 掃登入後端點)
python engage.py --name "My App" --dast https://staging.example.com \
    --methodology grey-box --test-type DAST --cookie "session=abc" --active

# 深度 DAST(編排真實工具,輸出寫進 .docx 報告)
python engage.py --name "My App" --dast https://staging.example.com \
    --test-type DAST --deep --out report.docx

# hybrid(同時 SAST + DAST),並用 DATABASE_URL 做跨次稽核比對
python engage.py --name "My App" --sast ./src --dast https://staging.example.com \
    --test-type hybrid --db "$DATABASE_URL"
```

設定 `--db`(或 `DATABASE_URL`)後,報告會以穩定 ID 跨次比對,標示
🆕 New / 🔁 Recurring / ✅ Fixed。`examples/vulnerable_app/` 是**故意有漏洞**的
範例程式,供展示 SAST 偵測用(請勿部署)。

### 方法論與界線

- **漏洞利用**:採無害驗證 + PoC(證明可利用),不對 production 執行實際入侵。
- **權限提升**:以偵測 + 影響評估呈現(IDOR / 橫向越權等),不做自動化提權。
- **清除測試痕跡**:清理測試方自身產物 + 完整性聲明,**不**竄改目標稽核日誌 / 反鑑識。

### 資料庫

- 正式部署:設定 `DATABASE_URL` 為 PostgreSQL 連線字串(驅動用 `psycopg` v3)。
- 本機/測試:不設定即使用 `sentinel.db`(SQLite,絕對路徑錨定在專案目錄),免裝資料庫。
- 資料表(SQLAlchemy 自動建立):`scans`、`findings`、`scope_records`、`engagements`。
- AI 分析結果存於 `scans` 列(`ai_summary` / `ai_model` / `ai_generated_at`)。

> ⚠️ **資料保存重要說明**
> 預設的 SQLite 是**本機檔案**,且被 `.gitignore` 忽略(不會進版控)。在**會被回收或
> 重新 clone 的臨時環境(雲端容器、CI、Claude Code web 等)**中,容器重啟後這個檔會
> **消失**,先前的掃描/案件就不見了。
>
> 要**長期保存或多人共用**,請設定 `DATABASE_URL` 指向**外部 PostgreSQL**:
> ```bash
> export DATABASE_URL="postgresql+psycopg://user:pass@db-host:5432/sentinel"
> ```
> 啟動時 `python app.py` 會印出目前使用的資料庫與現有筆數,可據此確認資料是否讀到。

## 使用流程

1. 開啟首頁,輸入目標 URL。
2. 勾選授權確認(我擁有此目標或已獲授權測試)。
3. (選用)開啟低衝擊模式、調整檢查項目。
4. 按「開始掃描」→ 進入儀表板看即時進度。
5. 掃描完成後檢視弱點清單與修補建議。
6. 按「AI 分析」讓 Claude 排優先序、產生修補計畫。
7. 下載 HTML / Markdown / JSON 報告。

## 專案結構

```
app.py                  Flask 進入點與路由
pentest/
  authorization.py      授權關卡與範圍記錄
  scanner.py            掃描排程、任務狀態、進度
  checks/               各項非破壞性檢查模組
  report.py             報告產生(HTML / MD / JSON)
  docx_report.py        專業 .docx 報告(對齊業界格式)
  ai_advisor.py         AI 模組(Claude,含規則式 fallback)
  storage.py            持久化層(SQLAlchemy:PostgreSQL / SQLite)
  standards.py          OWASP / CWE / CVSS / PTES / WSTG 對應
  engagement.py         案件模型與整合性/清理紀錄
  sast/                 白箱靜態分析引擎與規則
engage.py               案件編排 CLI(SAST / DAST / hybrid → .docx)
examples/vulnerable_app 故意有漏洞的 SAST 示範程式
templates/  static/     前端
tests/                  單元測試
```

## 授權測試與法律

未經授權對系統進行掃描或測試在多數司法管轄區屬於違法行為。使用本工具即表示
你同意 [`AUTHORIZATION.md`](AUTHORIZATION.md) 的條款。
