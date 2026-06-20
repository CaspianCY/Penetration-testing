# Sentinel — Web 弱點掃描與報告平台

一個以 Flask 打造的網頁式安全測試平台。你指定一個目標網址,平台會對它執行
**非破壞性**的弱點掃描,即時回報進度,列出弱點與對應的修補建議,並可產出
HTML / Markdown / JSON 報告。內建一個 AI 模組(由 Claude 驅動),會分析掃描
結果、排定修補優先序,並產生可執行的修補計畫。

> ⚠️ **僅供授權測試使用。** 請只掃描你**擁有**或已**取得書面授權**測試的系統。
> 詳見 [`AUTHORIZATION.md`](AUTHORIZATION.md)。

## 功能

- **指定目標** — 在網頁輸入一個 URL 即可開始。
- **非破壞性弱掃** — 只做讀取式檢查,不送出攻擊 payload、不嘗試利用漏洞:
  - 安全回應標頭(CSP、HSTS、X-Frame-Options、X-Content-Type-Options…)
  - TLS / 憑證(到期、協定版本、自簽)
  - Cookie 旗標(Secure / HttpOnly / SameSite)
  - 資訊外洩 / 敏感檔案(`.git`、`.env`、`server-status`…)
  - 表單與 CSRF / 密碼欄位處理
- **即時進度儀表板** — 攻擊方(測試者)可即時看到每一項檢查的進度。
- **弱點報告** — 依嚴重度分類,每項弱點都附修補建議與參考連結。
- **修補指引** — 直接告訴你「怎麼修」。
- **AI 模組** — Claude 分析整體弱點態勢、排優先序、產生修補計畫。
- **低衝擊模式** — 限速、降低併發、自訂 User-Agent,減少對目標負載。

## 設計上刻意「不做」的事

本平台**不提供**規避偵測 / 反鑑識 / 清除日誌 / IDS-WAF 規避這類功能,也**不**
對目標發送破壞性或阻斷服務(DoS)流量。掃描全程非破壞性。「低衝擊模式」是
為了減少對目標的負載,不是為了躲避對方的防禦監控。

## 快速開始

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 選用:設定 Claude API 金鑰以啟用 AI 模組(未設定時自動退回規則式分析)
export ANTHROPIC_API_KEY="sk-ant-..."

python app.py
# 開啟 http://127.0.0.1:5000
```

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
  ai_advisor.py         AI 模組(Claude,含規則式 fallback)
templates/  static/     前端
tests/                  單元測試
```

## 授權測試與法律

未經授權對系統進行掃描或測試在多數司法管轄區屬於違法行為。使用本工具即表示
你同意 [`AUTHORIZATION.md`](AUTHORIZATION.md) 的條款。
