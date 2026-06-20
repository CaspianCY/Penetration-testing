/* ============================================================
   Sentinel SPA — Vue 3(免 build / CDN 版)
   hash router + 應用外框 + 方法論分頁掃描表單 + 即時掃描檢視
   ============================================================ */
const { createApp, ref, reactive, computed, onMounted, onUnmounted, watch } = Vue;

/* ---------- 小工具 ---------- */
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL = { critical: "嚴重", high: "高", medium: "中", low: "低", info: "資訊" };

async function postForm(action, data) {
  const fd = new FormData();
  for (const [k, v] of Object.entries(data)) {
    if (v === false || v === null || v === undefined || v === "") continue;
    fd.append(k, v === true ? "on" : v);
  }
  const r = await fetch(action, { method: "POST", body: fd, headers: { Accept: "application/json" } });
  let body = {};
  try { body = await r.json(); } catch (_) { /* 非 JSON */ }
  if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
  return body;
}
async function getJSON(url) {
  const r = await fetch(url, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
function parseHash() {
  const h = (location.hash || "#/").replace(/^#/, "");
  const parts = h.split("/").filter(Boolean);     // ["scan","<id>"]
  if (parts[0] === "scan" && parts[1]) return { name: "scan", id: parts[1] };
  if (parts[0] === "scans") return { name: "scans" };
  if (parts[0] === "learning") return { name: "learning" };
  if (parts[0] === "sast") return { name: "sast" };
  return { name: "new" };
}

/* ============================================================
   外框:Header + Nav + Footer
   ============================================================ */
const AppShell = {
  props: ["route"],
  emits: ["go"],
  template: `
  <header class="app-header">
    <div class="header-row">
      <div class="brand" @click="$emit('go','#/')">
        <div class="brand-mark">🛡️</div>
        <div>
          <div class="brand-name">Sentinel</div>
          <div class="brand-sub">Pentest Console</div>
        </div>
      </div>
      <nav class="nav">
        <a :class="{active: route.name==='new'}" @click="$emit('go','#/')">＋ 新掃描</a>
        <a :class="{active: route.name==='scans'}" @click="$emit('go','#/scans')">掃描紀錄</a>
        <a :class="{active: route.name==='learning'}" @click="$emit('go','#/learning')">🧠 學習</a>
        <a :class="{active: route.name==='sast'}" @click="$emit('go','#/sast')">白箱</a>
        <a href="/dashboard">儀表板</a>
        <a href="/classic">經典介面</a>
      </nav>
    </div>
  </header>`,
};

/* ============================================================
   新掃描:方法論分頁(黑箱 / 灰箱 / 白箱)
   ============================================================ */
const NewScan = {
  emits: ["go"],
  setup(_, { emit }) {
    const METHODS = [
      { key: "black", title: "🕶️ 黑箱", sub: "無帳號 · 外部視角" },
      { key: "grey", title: "🔐 灰箱", sub: "用你自己的帳密 · 登入後" },
      { key: "white", title: "📄 白箱", sub: "上傳原始碼 · SAST" },
    ];
    const method = ref("black");
    const tools = ref({});
    const submitting = ref(false);
    const error = ref("");

    // 黑/灰箱共用的掃描設定
    const f = reactive({
      target: "", polite: true, crawl: true, max_pages: 40,
      capture: false, browser: false, proxy: "",
      active: false, aggressive: false, deep: false, ai_autotest: false,
      attested: false, active_attested: false,
      // 灰箱
      login_url: "", login_user: "", login_pass: "", login_api: "",
      resilience: false, login_cookie: "", auth_header: "", api_endpoints: "",
    });
    // 白箱
    const w = reactive({ source: null, fileName: "" });

    const needActiveAttest = computed(() =>
      f.active || f.deep || f.resilience || f.ai_autotest);

    onMounted(async () => {
      try { tools.value = (await getJSON("/api/tools")).tools || {}; } catch (_) {}
    });

    function pickFile(e) {
      const file = e.target.files[0];
      w.source = file || null;
      w.fileName = file ? file.name : "";
    }

    async function submit() {
      error.value = "";
      submitting.value = true;
      try {
        if (method.value === "white") {
          if (!w.source) throw new Error("請選擇要分析的原始碼壓縮檔(.zip)。");
          if (!f.attested) throw new Error("請先確認你擁有此程式碼或已獲授權。");
          const fd = new FormData();
          fd.append("source_zip", w.source);
          fd.append("attested", "on");
          const r = await fetch("/sast", { method: "POST", body: fd, headers: { Accept: "application/json" } });
          const body = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
          location.href = body.url || `/engagements/${body.engagement_id}`;
          return;
        }
        // 黑箱 / 灰箱 → POST /scan
        const payload = { ...f };
        if (method.value === "black") {
          // 黑箱:不送灰箱欄位
          for (const k of ["login_url", "login_user", "login_pass", "login_api",
            "resilience", "login_cookie", "auth_header", "api_endpoints"]) payload[k] = "";
          payload.resilience = false;
        }
        const body = await postForm("/scan", payload);
        emit("go", `#/scan/${body.id}`);
      } catch (e) {
        error.value = e.message || String(e);
      } finally {
        submitting.value = false;
      }
    }

    const engineReady = computed(() => !!tools.value["chromium(動態)"]);
    return { METHODS, method, tools, f, w, error, submitting, needActiveAttest, pickFile, submit, engineReady };
  },
  template: `
  <div class="enginebar" :class="engineReady ? 'ok' : 'warn'">
    <span class="dot"></span>
    <span v-if="engineReady"><strong>動態測試引擎(Chromium):就緒</strong> — 灰箱掃描會自動執行 JS、攔截真正的 API 呼叫。</span>
    <span v-else><strong>動態測試引擎(Chromium):未安裝</strong> — 灰箱將退回靜態爬取 + 後端 API 內容探索;部署執行 <code>playwright install --with-deps chromium</code> 以啟用動態。</span>
  </div>
  <section class="card">
    <h2>開始新測試</h2>
    <p class="hint">選擇測試方法論 — 系統依方法論只顯示相關欄位。</p>
    <div class="tabs">
      <div v-for="m in METHODS" :key="m.key" class="tab" :class="{active: method===m.key}" @click="method=m.key">
        <div class="tab-title">{{ m.title }}</div>
        <div class="tab-sub">{{ m.sub }}</div>
      </div>
    </div>

    <div v-if="error" class="alert">⚠️ {{ error }}</div>

    <!-- 黑箱 / 灰箱 共用目標 + 偵察設定 -->
    <template v-if="method !== 'white'">
      <div class="field">
        <label>目標網址</label>
        <input class="input" v-model="f.target" placeholder="https://example.com" inputmode="url" autocomplete="off">
      </div>

      <label class="check"><input type="checkbox" v-model="f.polite">
        <span>低衝擊模式 <span class="muted">(限速、降低對目標負載 — 建議開啟)</span></span></label>
      <label class="check"><input type="checkbox" v-model="f.crawl">
        <span>爬取整站 <span class="muted">(探索同網域的多頁面、表單與端點)</span></span></label>
      <div v-if="f.crawl" class="field" style="max-width:12rem">
        <label>爬取頁數上限</label>
        <input class="input" type="number" v-model.number="f.max_pages" min="1" max="100">
      </div>
      <label class="check"><input type="checkbox" v-model="f.capture">
        <span>流量側錄 <span class="muted">(記錄掃描器自己送出的請求/回應軌跡;敏感值遮罩)</span></span></label>
      <label class="check"><input type="checkbox" v-model="f.browser">
        <span>🌐 瀏覽器動態爬取 <span class="muted">(headless Chromium 執行 JS、攔截 API;部署需 playwright)</span></span></label>

      <div class="field">
        <label>出口 Proxy / VPN(選用)</label>
        <input class="input" v-model="f.proxy" autocomplete="off"
          placeholder="socks5://127.0.0.1:1080 或 http://user:pass@host:3128">
        <p class="hint">掃描流量改從此出口送出(來源 IP 控管,<strong>非匿名規避</strong>);留空用本機出口。</p>
      </div>

      <!-- 灰箱專屬:已認證掃描 -->
      <div v-if="method === 'grey'" class="box info">
        <div class="box-legend" style="color:var(--accent-2)">🔐 已認證掃描(用你自己的帳密)</div>
        <p class="hint">填你<strong>自己的</strong>帳密,平台先登入再掃登入後頁面。帳號/密碼欄位由系統<strong>自動偵測</strong>;
          密碼只用於登入、不明文寫入紀錄。SPA/JS 應用若自動登入失敗,改貼下方 Cookie / Token。</p>
        <div class="field"><label>登入頁網址(選用,留空自動尋找)</label>
          <input class="input" v-model="f.login_url" autocomplete="off" placeholder="留空 → 系統自動找登入頁"></div>
        <div class="row">
          <div class="field"><label>帳號</label><input class="input" v-model="f.login_user" autocomplete="off"></div>
          <div class="field"><label>密碼</label><input class="input" v-model="f.login_pass" type="text" autocomplete="off"></div>
        </div>
        <div class="field"><label>登入 API(JSON,選用;SPA 最佳解)</label>
          <input class="input" v-model="f.login_api" autocomplete="off" placeholder="https://example.com/api/login(留空會自動探測)">
          <p class="hint">SPA 登入填這:平台 <code>POST {username,password}</code> 取 token 帶上,像前端 JS 一樣;你的 server log 才看得到真正登入。</p></div>
        <label class="check"><input type="checkbox" v-model="f.resilience">
          <span>登入韌性測試 <span class="muted">(對上面帳號試一份<strong>有上限</strong>的常見弱密碼,測擋不擋得住線上猜測 + 是否缺鎖定;非大字典爆破)</span></span></label>
        <div class="field"><label>已登入 Cookie(SPA 用,選用)</label>
          <input class="input" v-model="f.login_cookie" autocomplete="off" placeholder="sessionid=abc123; token=xyz"></div>
        <div class="field"><label>Authorization 標頭(Token / JWT,選用)</label>
          <input class="input" v-model="f.auth_header" autocomplete="off" placeholder="Bearer eyJhbGci..."></div>
        <div class="field"><label>要主動測試的 API 端點(每行一個,選用)</label>
          <textarea class="input" v-model="f.api_endpoints" rows="3"
            placeholder="https://example.com/api/daily?period=202606"></textarea>
          <p class="hint">SPA 真正攻擊面在它呼叫的 API(F12 → Network)。帶參數端點會被當注入點。<strong>需同時勾『主動測試』。</strong></p></div>
      </div>

      <!-- 主動測試 -->
      <div class="box danger">
        <div class="box-legend">⚡ 主動測試(進階)</div>
        <label class="check"><input type="checkbox" v-model="f.active">
          <span>對表單與參數送出<strong>非破壞性</strong>注入 / XSS / 轉址探測,驗證「是否打得進、是否可能竄改」;並對登入試一份精選預設帳密 + 檢查登入速率限制。</span></label>
        <label class="check" style="margin-left:1.6rem"><input type="checkbox" v-model="f.aggressive">
          <span>併用時間延遲偵測 <span class="muted">(對目標負載較高,偵測較準)</span></span></label>
        <label class="check"><input type="checkbox" v-model="f.deep">
          <span>深度掃描:呼叫業界真實工具 <strong>(nmap / nuclei / ffuf / nikto / sqlmap)</strong>,依 PTES 階段編排。</span></label>
        <label class="check"><input type="checkbox" v-model="f.ai_autotest">
          <span>🤖 AI 閉環自動測試 <span class="muted">(AI 看即時回應鎖定端點 → 平台自動送出探測;雙層把關:白名單只放行<strong>偵測型</strong> payload。需 ANTHROPIC_API_KEY 才用真 AI)</span></span></label>
        <p v-if="Object.keys(tools).length" class="hint">工具狀態:
          <span v-for="(ok,name) in tools" :key="name" class="tag" :style="{opacity: ok?1:.45}">{{ name }}{{ ok?' ✓':' ✕' }}</span></p>
        <label v-if="needActiveAttest" class="check attest"><input type="checkbox" v-model="f.active_attested">
          <span>我了解主動測試 / 深度掃描會<strong>主動送出測試流量</strong>,並確認已獲授權對此目標執行。</span></label>
        <p class="hint">本工具僅<strong>偵測</strong>漏洞(證明竄改可能),<strong>不會</strong>實際 UPDATE / DELETE / DROP 更動資料。</p>
      </div>
    </template>

    <!-- 白箱:上傳原始碼 -->
    <template v-else>
      <div class="box info">
        <div class="box-legend" style="color:var(--accent-2)">📄 白箱 SAST:上傳原始碼</div>
        <p class="hint">上傳專案壓縮檔(.zip),平台做靜態程式碼分析(SAST),產生一份案件報告。原始碼只在分析時於暫存區解壓、用後即刪。</p>
        <div class="field">
          <label>原始碼壓縮檔(.zip)</label>
          <input class="input" type="file" accept=".zip" @change="pickFile">
          <p v-if="w.fileName" class="hint">已選:<code>{{ w.fileName }}</code></p>
        </div>
      </div>
    </template>

    <label class="check attest"><input type="checkbox" v-model="f.attested">
      <span>我確認我<strong>擁有此目標</strong>,或已取得擁有者的<strong>明確授權</strong>進行測試。</span></label>

    <button class="btn" :disabled="submitting" @click="submit">
      {{ submitting ? '送出中…' : (method==='white' ? '🔬 開始分析' : '🔍 開始掃描') }}
    </button>
  </section>`,
};

/* ============================================================
   即時掃描檢視
   ============================================================ */
const ScanView = {
  props: ["id"],
  emits: ["go"],
  setup(props) {
    const snap = ref(null);
    const err = ref("");
    const adaptive = ref(null);
    const adaptiveLoading = ref(false);
    let timer = null;

    async function poll() {
      try {
        snap.value = await getJSON(`/api/scan/${props.id}`);
        err.value = "";
        if (snap.value.status === "done" || snap.value.status === "error") {
          clearInterval(timer); timer = null;
        }
      } catch (e) { err.value = e.message || String(e); }
    }
    async function runAdaptive() {
      adaptiveLoading.value = true;
      try { adaptive.value = await (await fetch(`/api/scan/${props.id}/adaptive`,
        { method: "POST", headers: { Accept: "application/json" } })).json(); }
      catch (e) { adaptive.value = { error: e.message || String(e) }; }
      finally { adaptiveLoading.value = false; }
    }

    onMounted(() => { poll(); timer = setInterval(poll, 1500); });
    onUnmounted(() => { if (timer) clearInterval(timer); });
    watch(() => props.id, () => { snap.value = null; adaptive.value = null; poll(); });

    const sevList = computed(() => {
      const c = (snap.value && snap.value.severity_counts) || {};
      return SEV_ORDER.map((s) => ({ s, label: SEV_LABEL[s], n: c[s] || 0 })).filter((x) => x.n > 0);
    });
    const realFindings = computed(() =>
      ((snap.value && snap.value.findings) || []).filter((x) => x.severity !== "info"));
    const flow = computed(() => (snap.value && snap.value.attack_flow) || null);

    return { snap, err, sevList, realFindings, flow, adaptive, adaptiveLoading, runAdaptive };
  },
  template: `
  <div>
    <div v-if="err" class="alert">⚠️ {{ err }}</div>
    <div v-if="!snap" class="empty">載入掃描中…</div>
    <template v-else>
      <section class="card">
        <h2>
          <a @click="$emit('go','#/scans')" style="cursor:pointer">掃描</a> ›
          <code>{{ snap.target }}</code>
          <span class="tag" style="margin-left:.5rem">{{ snap.status }}</span>
        </h2>
        <div class="progress">
          <div class="bar"><span :style="{width: snap.progress + '%'}"></span></div>
          <div class="pct">{{ snap.progress }}%</div>
        </div>
        <div class="steps">
          <div v-for="st in snap.phase_steps" :key="st.key" class="step" :class="st.state">
            <span>{{ st.icon }}</span><span>{{ st.label }}</span>
          </div>
        </div>
        <div v-if="snap.current_check" class="hint">目前:{{ snap.current_check }}</div>
        <div class="stats" style="margin-top:1rem">
          <div class="stat"><div class="n">{{ snap.war.pages ?? '–' }}</div><div class="c">前端頁面</div></div>
          <div class="stat"><div class="n">{{ snap.war.forms ?? '–' }}</div><div class="c">表單</div></div>
          <div class="stat"><div class="n">{{ snap.war.points ?? '–' }}</div><div class="c">注入點</div></div>
          <div class="stat"><div class="n">{{ snap.war.checks_done }}/{{ snap.war.checks_total }}</div><div class="c">檢查項</div></div>
          <div class="stat"><div class="n">{{ snap.war.findings }}</div><div class="c">弱點</div></div>
        </div>
        <!-- 登入後內部(灰箱)即時覆蓋 -->
        <div v-if="snap.war.authenticated" class="box info" style="margin-top:1rem">
          <div class="box-legend" style="color:var(--accent-2)">🔐 登入後內部(後端 API)</div>
          <div class="stats">
            <div class="stat"><div class="n">{{ snap.war.apis }}</div><div class="c">後端 API 已探出</div></div>
            <div class="stat"><div class="n">{{ snap.war.authz_tested }}</div><div class="c">已測授權</div></div>
            <div class="stat"><div class="n" :style="{color: snap.war.authz_bac ? 'var(--critical)' : 'var(--accent)'}">{{ snap.war.authz_bac }}</div><div class="c">缺少授權</div></div>
          </div>
          <p v-if="snap.status==='done' && snap.war.apis===0" class="hint" style="margin-top:.6rem">
            尚未探出可測的後端 API 端點。若為 JS 應用,請確認<strong>動態引擎已就緒</strong>,或在表單手動指定 API 端點後重掃。</p>
        </div>
      </section>

      <!-- 嚴重度分佈 -->
      <section v-if="sevList.length" class="card">
        <h2>弱點嚴重度</h2>
        <div class="pills">
          <span v-for="x in sevList" :key="x.s" class="sev" :class="'sev-'+x.s">{{ x.label }} · {{ x.n }}</span>
        </div>
      </section>

      <!-- 攻擊路徑:為什麼卡住 -->
      <section v-if="flow" class="card">
        <h2>攻擊路徑與可達深度</h2>
        <div v-if="flow.fully_breached" class="box danger">
          <strong>⚠️ 完整突破:</strong>攻擊鏈各階段皆有可達結果。
        </div>
        <div v-else-if="flow.blocked_summary" class="box">
          <strong>🧱 卡關:</strong>{{ flow.blocked_summary }}
          <p v-if="flow.blocked_detail" class="hint" style="margin-top:.4rem">{{ flow.blocked_detail }}</p>
        </div>
        <div class="steps" style="margin-top:.8rem">
          <div v-for="s in (flow.stages||[])" :key="s.key" class="step"
               :class="{done: s.reached, current: s.key===flow.wall_key}">
            <span>{{ s.icon || '•' }}</span><span>{{ s.label }}</span>
            <span v-if="s.key===flow.wall_key && s.block" class="muted" style="font-size:.74rem">🧱 {{ s.block.reason }}</span>
          </div>
        </div>
      </section>

      <!-- 時間軸 -->
      <section v-if="(snap.timeline||[]).length" class="card">
        <h2>攻擊時間軸</h2>
        <ul class="timeline">
          <li v-for="(e,i) in snap.timeline.slice().reverse()" :key="i" class="tl" :class="e.kind">
            <span class="x">{{ e.icon }}</span><span>{{ e.text }}</span><span class="t">{{ e.t }}</span>
          </li>
        </ul>
      </section>

      <!-- AI 適應性分析 -->
      <section class="card">
        <h2>🤖 AI 適應性分析</h2>
        <button class="btn ghost" :disabled="adaptiveLoading || snap.status!=='done'" @click="runAdaptive">
          {{ adaptiveLoading ? '分析中…' : '產生 AI 建議' }}</button>
        <p v-if="snap.status!=='done'" class="hint" style="margin-top:.5rem">掃描完成後即可分析。</p>
        <div v-if="adaptive" style="margin-top:1rem">
          <div v-if="adaptive.error" class="alert">{{ adaptive.error }}</div>
          <template v-else>
            <p v-if="adaptive.summary">{{ adaptive.summary }}</p>
            <div v-if="(adaptive.focus||[]).length" class="box info">
              <div class="box-legend">建議聚焦</div>
              <ul><li v-for="(x,i) in adaptive.focus" :key="i">{{ x }}</li></ul>
            </div>
            <div v-if="(adaptive.next_steps||[]).length" class="box">
              <div class="box-legend">下一步</div>
              <ol><li v-for="(x,i) in adaptive.next_steps" :key="i">{{ x }}</li></ol>
            </div>
            <p v-if="adaptive.model" class="hint">引擎:{{ adaptive.model }}</p>
          </template>
        </div>
      </section>

      <!-- 弱點清單 -->
      <section class="card">
        <h2>弱點明細({{ realFindings.length }})</h2>
        <div v-if="!realFindings.length" class="empty">
          {{ snap.status==='done' ? '未發現非資訊級弱點。' : '掃描進行中…' }}
        </div>
        <div v-for="(fd,i) in realFindings" :key="i" class="finding"
             :style="{borderLeftColor: 'var(--'+fd.severity+')'}">
          <h3>
            <span class="sev" :class="'sev-'+fd.severity">{{ SEV_LABEL[fd.severity] || fd.severity }}</span>
            {{ fd.title }}
            <span v-if="fd.owasp" class="tag">{{ fd.owasp }}</span>
            <span v-if="fd.cwe" class="tag">{{ fd.cwe }}</span>
          </h3>
          <p>{{ fd.description }}</p>
          <pre v-if="fd.evidence">{{ fd.evidence }}</pre>
          <p v-if="fd.location" class="hint">位置:<code>{{ fd.location }}</code></p>
          <p v-if="fd.remediation" class="hint"><strong>修補:</strong>{{ fd.remediation }}</p>
        </div>
      </section>

      <section class="card">
        <a class="btn ghost" :href="'/scan/'+snap.id+'/report.docx'">⬇️ 下載 Word 報告</a>
        <a class="btn ghost" :href="'/scan/'+snap.id" style="margin-left:.5rem">經典檢視</a>
      </section>
    </template>
  </div>`,
  data() { return { SEV_LABEL }; },
};

/* ============================================================
   掃描紀錄
   ============================================================ */
const ScansList = {
  emits: ["go"],
  setup() {
    const scans = ref([]);
    const loading = ref(true);
    let timer = null;
    async function load() {
      try { scans.value = (await getJSON("/api/scans")).scans || []; } catch (_) {}
      finally { loading.value = false; }
    }
    onMounted(() => { load(); timer = setInterval(load, 3000); });
    onUnmounted(() => { if (timer) clearInterval(timer); });
    return { scans, loading };
  },
  template: `
  <section class="card">
    <h2>掃描紀錄</h2>
    <div v-if="loading" class="empty">載入中…</div>
    <div v-else-if="!scans.length" class="empty">尚無掃描。<a @click="$emit('go','#/')" style="cursor:pointer">開始一個 →</a></div>
    <table v-else class="table">
      <thead><tr><th>目標</th><th>狀態</th><th>進度</th><th></th></tr></thead>
      <tbody>
        <tr v-for="s in scans" :key="s.id">
          <td><code>{{ s.target }}</code></td>
          <td><span class="tag">{{ s.status }}</span></td>
          <td>{{ s.progress }}%</td>
          <td><a @click="$emit('go','#/scan/'+s.id)" style="cursor:pointer">檢視 →</a></td>
        </tr>
      </tbody>
    </table>
  </section>`,
};

/* ============================================================
   學習(知識庫)
   ============================================================ */
const Learning = {
  setup() {
    const data = ref(null);
    onMounted(async () => { try { data.value = await getJSON("/api/learning"); } catch (e) { data.value = { error: String(e) }; } });
    return { data };
  },
  template: `
  <div>
    <section class="card">
      <h2>🧠 自我學習知識庫</h2>
      <p class="hint">平台會記住成功的登入剖析與技術棧→弱點型態,讓下次對相似目標更快上手。</p>
      <div v-if="!data" class="empty">載入中…</div>
      <div v-else-if="data.error" class="alert">{{ data.error }}</div>
      <template v-else>
        <div class="stats">
          <div class="stat"><div class="n">{{ data.total || 0 }}</div><div class="c">學習筆數</div></div>
          <div class="stat"><div class="n">{{ (data.stacks||[]).length }}</div><div class="c">已知技術棧</div></div>
          <div class="stat"><div class="n">{{ (data.login_profiles||[]).length }}</div><div class="c">登入剖析</div></div>
          <div class="stat"><div class="n">{{ (data.effective_payloads||[]).length }}</div><div class="c">有效 payload</div></div>
        </div>
        <div v-if="(data.stacks||[]).length" class="pills" style="margin-top:1rem">
          <span v-for="s in data.stacks" :key="s" class="tag">{{ s }}</span>
        </div>
      </template>
    </section>
    <section v-if="data && (data.login_profiles||[]).length" class="card">
      <h2>登入剖析</h2>
      <table class="table">
        <thead><tr><th>技術棧</th><th>成功</th><th>失敗</th></tr></thead>
        <tbody>
          <tr v-for="(p,i) in data.login_profiles" :key="i">
            <td><code>{{ p.key }}</code></td><td>{{ p.success }}</td><td>{{ p.fail }}</td>
          </tr>
        </tbody>
      </table>
    </section>
    <section v-if="data && (data.effective_payloads||[]).length" class="card">
      <h2>閉環學習:命中過的偵測 payload</h2>
      <p class="hint">AI 閉環自動測試命中後寫回;下次對同類技術棧會優先重試這些 payload。</p>
      <table class="table">
        <thead><tr><th>技術棧</th><th>型態</th><th>payload</th><th>命中次數</th></tr></thead>
        <tbody>
          <tr v-for="(p,i) in data.effective_payloads" :key="i">
            <td><code>{{ p.key }}</code></td>
            <td><span class="tag">{{ (p.value||{}).kind }}</span></td>
            <td><code>{{ (p.value||{}).payload }}</code></td>
            <td>{{ p.success }}</td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>`,
};

/* ============================================================
   白箱導引(SAST 表單在「新掃描 → 白箱」分頁,這裡只導過去)
   ============================================================ */
const SastRedirect = {
  emits: ["go"],
  mounted() { this.$emit("go", "#/"); },
  template: `<div class="empty">前往新掃描的白箱分頁…</div>`,
};

/* ============================================================
   根組件 + 路由
   ============================================================ */
createApp({
  components: { AppShell, NewScan, ScanView, ScansList, Learning, SastRedirect },
  setup() {
    const route = ref(parseHash());
    function onHash() { route.value = parseHash(); window.scrollTo(0, 0); }
    function go(hash) { if (location.hash === hash) onHash(); else location.hash = hash; }
    onMounted(() => window.addEventListener("hashchange", onHash));
    onUnmounted(() => window.removeEventListener("hashchange", onHash));
    return { route, go };
  },
  template: `
  <app-shell :route="route" @go="go"></app-shell>
  <main>
    <new-scan v-if="route.name==='new'" @go="go"></new-scan>
    <scan-view v-else-if="route.name==='scan'" :id="route.id" :key="route.id" @go="go"></scan-view>
    <scans-list v-else-if="route.name==='scans'" @go="go"></scans-list>
    <learning v-else-if="route.name==='learning'"></learning>
    <sast-redirect v-else-if="route.name==='sast'" @go="go"></sast-redirect>
  </main>
  <footer class="footer">Sentinel · 僅供已授權之滲透測試 · 被動弱掃僅讀取式探測,主動測試送出非破壞性 payload。</footer>`,
}).mount("#app");
