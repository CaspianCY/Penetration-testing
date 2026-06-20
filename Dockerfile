# Sentinel on Kali Linux —— 內建業界滲透測試工具的執行環境。
#
# 以 Kali rolling 為基底,安裝編排器會用到的工具,再跑 Sentinel 平台。
# 在任何有 Docker 的主機上:
#   docker compose up --build
# 即可在 http://localhost:5000 使用,所有工具(nmap/nuclei/ffuf/nikto/sqlmap/
# whatweb/wafw00f/sslscan…)都已就緒。
#
# ⚠️ 僅供你擁有或已獲授權測試的目標。詳見 AUTHORIZATION.md。

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    SENTINEL_HOST=0.0.0.0 \
    SENTINEL_PORT=5000

# 業界工具(來自 Kali repo)+ Python 執行環境
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        nmap nikto sqlmap whatweb wafw00f sslscan wpscan \
        gobuster ffuf nuclei wfuzz dirb dnsrecon \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt gunicorn

# headless 瀏覽器(動態爬取 JS 導覽 / SPA 後台);失敗不擋 build,執行期會自動退回靜態爬取
RUN playwright install --with-deps chromium || true

COPY . .
RUN chmod +x entrypoint.sh

# 預先下載 nuclei 模板(失敗不擋 build,執行期仍可更新)
RUN nuclei -update-templates || true

EXPOSE 5000 8080

# entrypoint 會綁定到平台指派的埠(Zeabur 注入 PORT;否則 SENTINEL_PORT;預設 5000)
CMD ["./entrypoint.sh"]
