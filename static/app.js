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
        return `<article class="finding sev-${f.severity}" style="border-left-color:var(--${f.severity})">
          <h3><span class="sev-pill sev-${f.severity}">${sevLabels[f.severity]}</span> ${esc(f.title)}</h3>
          <p><strong>說明</strong>:${esc(f.description)}</p>
          ${ev}
          <p><strong>修補建議</strong>:${esc(f.remediation)}</p>
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

  function renderFlow(flow) {
    if (!flow) return;
    var steps = flow.stages.map(function (s) {
      var cls = "flow-step " + (s.reached ? "on" : "off") + (s.is_deepest ? " deep" : "");
      var finds = s.findings.length
        ? "<ul class='flow-find'>" + s.findings.map(function (f) {
            return "<li><span class='mini sev-" + f.severity + "'>" +
              (sevInitial[f.severity] || "?") + "</span> " + esc(f.title) + "</li>";
          }).join("") + "</ul>"
        : "<p class='muted small'>未發現此階段的問題</p>";
      var here = s.is_deepest ? "<span class='flow-here'>← 打到這裡</span>" : "";
      return "<div class='" + cls + "'><div class='flow-step-head'><span class='flow-step-icon'>" +
        s.icon + "</span><span class='flow-step-label'>" + esc(s.label) + "</span>" + here +
        "</div>" + finds + "</div>";
    }).join("");
    var chains = (flow.chains || []).map(function (c) {
      return "<div class='chain' style='border-left-color:var(--" + c.severity + ")'><strong>" +
        esc(c.name) + "</strong><ol class='chain-steps'>" +
        c.steps.map(function (st) { return "<li>" + esc(st) + "</li>"; }).join("") + "</ol></div>";
    }).join("");
    var chainTitle = chains ? "<h3 class='flow-chain-title'>可能的攻擊鏈</h3>" : "";
    document.getElementById("attack-flow").innerHTML =
      "<p class='flow-depth-banner'>可達深度(理論):<strong>" + esc(flow.depth_label) +
      "</strong> <span class='muted'>— 依偵測到的弱點推導,非實際入侵</span></p>" +
      "<div class='flow-steps'>" + steps + "</div>" + chainTitle + chains;
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
    el("current-check").textContent = data.current_check || "—";
    renderSummary(data.severity_counts);
    renderFindings(data.findings);
    renderFlow(data.attack_flow);
    el("log").textContent = (data.log || []).join("\n");

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
