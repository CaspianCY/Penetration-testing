// 掃描儀表板:輪詢後端進度、即時渲染弱點與日誌、觸發 AI 分析。
(function () {
  const root = document.getElementById("scan");
  if (!root) return;
  const jobId = root.dataset.jobId;

  const sevLabels = { critical: "嚴重", high: "高", medium: "中", low: "低", info: "資訊" };
  const sevOrder = ["critical", "high", "medium", "low", "info"];

  const el = (id) => document.getElementById(id);
  let aiBtnBound = false;

  function renderSummary(counts) {
    el("sev-summary").innerHTML = sevOrder
      .map((s) => `<span class="sev-pill sev-${s}">${sevLabels[s]} ${counts[s] || 0}</span>`)
      .join("");
  }

  function esc(t) {
    return (t || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function renderFindings(findings) {
    el("findings").innerHTML = findings
      .map((f) => {
        const refs = (f.references || [])
          .map((r) => `<li><a href="${esc(r)}" target="_blank" rel="noopener">${esc(r)}</a></li>`)
          .join("");
        const refsHtml = refs ? `<p><strong>參考</strong></p><ul>${refs}</ul>` : "";
        const ev = f.evidence ? `<p><strong>證據</strong></p><pre>${esc(f.evidence)}</pre>` : "";
        const meta = [
          f.tool ? "🛠 " + esc(f.tool) : "",
          f.owasp ? esc(f.owasp) : "",
          f.cwe ? esc(f.cwe) : "",
          f.cvss ? "CVSS " + f.cvss : "",
          f.attack ? "ATT&CK " + esc(f.attack) : "",
        ].filter(Boolean).join(" · ");
        const metaHtml = meta ? `<p class="meta-line muted">${meta}</p>` : "";
        const vec = f.cvss_vector ? `<p class="muted small"><code>${esc(f.cvss_vector)}</code></p>` : "";
        return `<article class="finding sev-${f.severity}" style="border-left-color:var(--${f.severity})">
          <h3><span class="sev-pill sev-${f.severity}">${sevLabels[f.severity]}</span> ${esc(f.title)}</h3>
          ${metaHtml}
          <p><strong>說明</strong>:${esc(f.description)}</p>
          ${ev}
          <p><strong>修補建議</strong>:${esc(f.remediation)}</p>
          ${vec}
          ${refsHtml}
        </article>`;
      })
      .join("");
  }

  function bindAiButton() {
    if (aiBtnBound) return;
    aiBtnBound = true;
    el("ai-btn").addEventListener("click", async () => {
      const btn = el("ai-btn");
      btn.disabled = true;
      btn.textContent = "🤖 分析中…";
      try {
        const res = await fetch(`/api/scan/${jobId}/ai`, { method: "POST" });
        const data = await res.json();
        if (data.ai_summary) {
          el("ai-card").hidden = false;
          el("ai-summary").textContent = data.ai_summary;
        } else if (data.error) {
          alert(data.error);
        }
      } catch (e) {
        alert("AI 分析失敗:" + e);
      } finally {
        btn.disabled = false;
        btn.textContent = "🤖 AI 分析與修補計畫";
      }
    });
  }

  var sevInitial = { critical: "C", high: "H", medium: "M", low: "L", info: "I" };

  function renderPhases(steps) {
    var box = el("phase-steps");
    if (!box || !steps) return;
    box.innerHTML = steps.map(function (s, i) {
      var arrow = i < steps.length - 1
        ? "<span class='phase-arrow " + (s.state === "done" ? "done" : "") + "'>›</span>" : "";
      return "<span class='phase-step " + s.state + "'>" +
        "<span class='phase-ic'>" + s.icon + "</span>" +
        "<span class='phase-lb'>" + esc(s.label) + "</span></span>" + arrow;
    }).join("");
  }

  function renderWar(w) {
    var box = el("war-stats");
    if (!box || !w) return;
    function cell(num, cap) {
      return "<div class='war-cell'><span class='war-num'>" +
        (num == null ? "—" : num) + "</span><span class='war-cap'>" + cap + "</span></div>";
    }
    box.innerHTML =
      cell(w.pages, "頁面") + cell(w.forms, "表單") + cell(w.points, "可注入端點") +
      cell(w.checks_done + " / " + w.checks_total, "檢查項") + cell(w.findings, "弱點");
  }

  function renderTimeline(events) {
    var box = el("timeline");
    if (!box) return;
    if (!events || !events.length) { box.innerHTML = "<li class='muted'>準備中…</li>"; return; }
    var atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    var last = events.length - 1;
    box.innerHTML = events.map(function (e, i) {
      var cur = (i === last && e.kind === "action") ? " current" : "";
      return "<li class='tl-item tl-" + (e.kind || "info") + cur + "'>" +
        "<span class='tl-ic'>" + (e.icon || "•") + "</span>" +
        "<span class='tl-tx'>" + esc(e.text) + "</span>" +
        "<span class='tl-t'>" + esc(e.t || "") + "</span></li>";
    }).join("");
    if (atBottom) box.scrollTop = box.scrollHeight;   // 自動跟到最新一筆
  }

  function renderFlow(flow) {
    if (!flow) return;
    var steps = flow.stages.map(function (s) {
      var cls = "flow-step " + (s.reached ? "on" : "off") + (s.is_deepest ? " deep" : "");
      var body;
      if (s.reached) {
        body = s.findings.length
          ? "<ul class='flow-find'>" + s.findings.map(function (f) {
              return "<li><span class='mini sev-" + f.severity + "'>" +
                (sevInitial[f.severity] || "?") + "</span> " + esc(f.title) + "</li>";
            }).join("") + "</ul>"
          : "<p class='muted small'>未發現此階段的問題</p>";
      } else if (s.block) {
        body = "<div class='flow-block'><span class='flow-block-tag'>⛔ 打不進來</span> " +
          esc(s.block.reason) + "<span class='flow-block-detail'>" + esc(s.block.detail) + "</span></div>";
      } else {
        body = "<p class='muted small'>未觸及</p>";
      }
      var here = s.is_deepest ? "<span class='flow-here'>← 打到這裡</span>" : "";
      return "<div class='" + cls + "'><div class='flow-step-head'><span class='flow-step-icon'>" +
        s.icon + "</span><span class='flow-step-label'>" + esc(s.label) + "</span>" + here +
        "</div>" + body + "</div>";
    }).join("");
    var chains = (flow.chains || []).map(function (c) {
      return "<div class='chain' style='border-left-color:var(--" + c.severity + ")'><strong>" +
        esc(c.name) + "</strong><ol class='chain-steps'>" +
        c.steps.map(function (st) { return "<li>" + esc(st) + "</li>"; }).join("") + "</ol></div>";
    }).join("");
    var chainTitle = chains ? "<h3 class='flow-chain-title'>可能的攻擊鏈</h3>" : "";
    var wallCls = flow.fully_breached ? "flow-wall breached" : "flow-wall";
    var wallIcon = flow.fully_breached ? "🎯" : "🧱";
    var wall = flow.blocked_summary
      ? "<div class='" + wallCls + "'><div class='flow-wall-head'>" + wallIcon + " " +
          esc(flow.blocked_summary) + "</div><p class='flow-wall-detail'>" +
          esc(flow.blocked_detail || "") + "</p></div>"
      : "";
    document.getElementById("attack-flow").innerHTML =
      "<p class='flow-depth-banner'>可達深度(理論):<strong>" + esc(flow.depth_label) +
      "</strong> <span class='muted'>— 依偵測到的弱點推導,非實際入侵</span></p>" +
      wall + "<div class='flow-steps'>" + steps + "</div>" + chainTitle + chains;
  }

  function renderCrawl(data) {
    var card = document.getElementById("crawl-card");
    var box = document.getElementById("crawl-info");
    var cs = data.crawl_summary;
    if (cs && cs.page_count != null) {
      var pages = (cs.pages || []).map(function (p) { return "<li>" + esc(p) + "</li>"; }).join("");
      var map = pages
        ? "<details><summary>站點地圖（" + cs.page_count + " 頁，點開查看）</summary>" +
          "<ul class='crawl-pages'>" + pages + "</ul></details>"
        : "";
      box.innerHTML =
        "<div class='crawl-stats'>" +
        "<span class='cstat'><b>" + cs.page_count + "</b> 頁</span>" +
        "<span class='cstat'><b>" + cs.form_count + "</b> 表單</span>" +
        "<span class='cstat'><b>" + cs.point_count + "</b> 可注入端點</span></div>" + map;
      card.hidden = false;
      return;
    }
    // 後備:從「攻擊面盤點」finding 取(歷史/重啟後也看得到)
    var surf = (data.findings || []).filter(function (f) { return f.check_id === "surface-coverage"; })[0];
    if (surf) {
      box.innerHTML = "<p>" + esc(surf.description) + "</p><p class='muted'>" + esc(surf.evidence) + "</p>";
      card.hidden = false;
    }
  }

  async function poll() {
    let data;
    try {
      data = await (await fetch(`/api/scan/${jobId}`)).json();
    } catch (e) {
      return setTimeout(poll, 2000);
    }

    el("progress-fill").style.width = data.progress + "%";
    el("progress-text").textContent = data.progress + "%";
    el("status").textContent = data.status;
    el("current-check").textContent = data.current_check || (data.status === "done" ? "已完成" : "—");
    renderPhases(data.phase_steps);
    renderWar(data.war);
    renderTimeline(data.timeline);
    renderSummary(data.severity_counts);
    renderCrawl(data);
    renderFindings(data.findings);
    renderFlow(data.attack_flow);
    el("log").textContent = (data.log || []).join("\n");

    var la = el("live-action");
    if (la) la.classList.toggle("idle", data.status === "done" || data.status === "error");

    if (data.ai_summary) {
      el("ai-card").hidden = false;
      el("ai-summary").textContent = data.ai_summary;
    }

    if (data.status === "done") {
      el("ai-btn").disabled = false;
      bindAiButton();
    } else if (data.status === "error") {
      el("status").textContent = "error: " + data.error;
    } else {
      setTimeout(poll, 1500);
    }
  }

  poll();
})();
