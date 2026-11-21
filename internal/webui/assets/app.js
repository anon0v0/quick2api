(() => {
  "use strict";

  const THEME_STORAGE = "q2a_theme";

  const state = {
    authenticated: false,
    username: "root",
    activeTab: "overview",
    chartMode: "requests",
    autoRefresh: true,
    status: null,
    metrics: null,
    logs: [],
    logTags: [],
    logLatestSeq: 0,
    logTotalBuffered: 0,
    logPaused: false,
    logLevel: "all",
    logTag: "all",
    logSearch: "",
    probeResults: {},
    statusFetchedAt: 0,
    proxyModalAcctId: "",
    oauthSession: null,
    oauthMode: "oauth",
  };

  let pollTimer = null;
  let logTimer = null;
  let tickTimer = null;

  const $ = (id) => document.getElementById(id);

  function esc(v) {
    return String(v == null ? "" : v)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function fmtNum(n) {
    const x = Number(n) || 0;
    return x.toLocaleString("en-US");
  }

  function fmtCompact(n) {
    const x = Number(n) || 0;
    if (x >= 1e9) return (x / 1e9).toFixed(2) + "B";
    if (x >= 1e6) return (x / 1e6).toFixed(2) + "M";
    if (x >= 1e3) return (x / 1e3).toFixed(1) + "K";
    return String(x);
  }

  function fmtDuration(sec) {
    const s = Math.max(0, Math.floor(Number(sec) || 0));
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    const rs = s % 60;
    if (m < 60) return `${m}m ${rs}s`;
    const h = Math.floor(m / 60);
    const rm = m % 60;
    if (h < 24) return `${h}h ${rm}m`;
    const d = Math.floor(h / 24);
    const rh = h % 24;
    return `${d}d ${rh}h`;
  }

  function fmtLatency(ms) {
    const v = Number(ms) || 0;
    if (v <= 0) return "--";
    if (v >= 1000) return (v / 1000).toFixed(2) + "s";
    return Math.round(v) + "ms";
  }

  function fmtClock(unixSec) {
    if (!unixSec) return "--";
    const d = new Date(unixSec * 1000);
    return d.toLocaleTimeString("zh-CN", { hour12: false });
  }

  function fmtDateTime(unixSec) {
    if (!unixSec) return "--";
    const d = new Date(unixSec * 1000);
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    const hh = String(d.getHours()).padStart(2, "0");
    const mi = String(d.getMinutes()).padStart(2, "0");
    return `${mm}-${dd} ${hh}:${mi}`;
  }

  function fmtISOTime(iso) {
    if (!iso) return "--:--:--";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso.slice(11, 19);
    return d.toLocaleTimeString("zh-CN", { hour12: false });
  }

  function cooldownLabel(kind) {
    switch (kind) {
      case "rate_limited": return "限流退避";
      case "session_quota": return "会话配额冷却";
      case "monthly_quota": return "月度配额耗尽";
      case "subscription_expired": return "试用/订阅过期";
      case "auth_failed": return "认证失败冷却";
      default: return kind || "冷却中";
    }
  }

  function formatSubscription(q) {
    if (!q) return { label: "", raw: "" };
    const rawParts = [q.subscription_type, q.trial_status].filter(Boolean);
    const raw = rawParts.join(" · ");
    if (!raw) return { label: "", raw: "" };

    let plan = (q.subscription_type || "").trim();
    if (plan) {
      const clean = plan
        .replace(/^QUICK_/i, "")
        .replace(/_FREE$/i, "")
        .replace(/_TRIAL$/i, "")
        .replace(/_/g, " ")
        .trim();
      plan = clean
        ? clean.toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase())
        : plan;
    }

    let trial = (q.trial_status || "").trim().toUpperCase();
    let trialLabel = "";
    if (trial === "ACTIVE") trialLabel = "试用中";
    else if (trial === "EXPIRED") trialLabel = "试用已过期";
    else if (trial === "ELIGIBLE") trialLabel = "可试用";
    else if (trial && trial !== "NONE" && trial !== "INACTIVE") trialLabel = trial;

    const label = [plan, trialLabel].filter(Boolean).join(" · ") || raw;
    return { label, raw };
  }

  function toast(msg, isError = false) {
    const root = $("toast-root");
    const el = document.createElement("div");
    el.className = "toast" + (isError ? " toast-err" : "");
    el.textContent = msg;
    root.appendChild(el);
    setTimeout(() => {
      el.style.opacity = "0";
      setTimeout(() => el.remove(), 200);
    }, 3200);
  }

  /* Theme */
  function applyTheme(theme) {
    const isDark = theme === "dark";
    document.documentElement.setAttribute("data-theme", isDark ? "dark" : "light");
    const icon = $("theme-icon");
    if (isDark) {
      icon.innerHTML = '<circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"></path>';
    } else {
      icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>';
    }
  }

  function initTheme() {
    const saved = localStorage.getItem(THEME_STORAGE);
    applyTheme(saved === "dark" ? "dark" : "light");
  }

  /* HTTP helper */
  async function apiFetch(path, options = {}) {
    const headers = Object.assign({ "X-Requested-With": "quick2api-ui" }, options.headers || {});
    if (options.body !== undefined && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    const resp = await fetch(path, {
      method: options.method || "GET",
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      credentials: "same-origin",
      cache: "no-store",
    });
    let data = null;
    try {
      data = await resp.json();
    } catch (_) {
      data = null;
    }
    if (resp.status === 401) {
      const wasAuthed = state.authenticated;
      state.authenticated = false;
      if (!options.noAuthGate) {
        showAuthGate(wasAuthed && !options.suppressAuthError ? "登录会话已过期，请重新登录。" : "");
      }
      const authErr = new Error((data && data.error && data.error.message) || "unauthorized");
      authErr.unauthorized = true;
      throw authErr;
    }
    if (!resp.ok) {
      const msg = (data && data.error && data.error.message) || `HTTP ${resp.status}`;
      throw new Error(msg);
    }
    return data;
  }

  /* Auth Gate */
  function showAuthGate(errText) {
    stopTimers();
    $("auth-gate").classList.remove("hidden");
    const errEl = $("auth-error");
    if (errText) {
      errEl.textContent = errText;
      errEl.classList.remove("hidden");
    } else {
      errEl.classList.add("hidden");
    }
    $("auth-pass-input").focus();
  }

  function hideAuthGate() {
    $("auth-gate").classList.add("hidden");
    $("auth-error").classList.add("hidden");
    $("btn-logout").classList.remove("hidden");
  }
  /* Data Fetching */
  async function fetchCore(includeUsage = false) {
    try {
      const statusPath = includeUsage ? "/admin/status?usage=1" : "/admin/status";
      const [statusData, metricsData] = await Promise.all([
        apiFetch(statusPath),
        apiFetch("/admin/metrics"),
      ]);
      state.authenticated = true;
      hideAuthGate();
      state.status = statusData;
      state.statusFetchedAt = Date.now();
      state.metrics = metricsData;
      renderAll();
      $("last-sync-text").textContent = "同步于 " + fmtClock(Math.floor(Date.now() / 1000));
    } catch (err) {
      if (!err.unauthorized) {
        setHealthPill("err", "连接异常");
        toast("获取状态失败: " + err.message, true);
      }
    }
  }

  async function fetchLogs(fullReset = false) {
    if (!state.authenticated) return;
    try {
      const since = fullReset ? 0 : state.logLatestSeq;
      const qs = new URLSearchParams({ limit: "500" });
      if (since > 0) qs.set("since", String(since));
      const data = await apiFetch("/admin/logs?" + qs.toString());
      if (fullReset) {
        state.logs = data.entries || [];
      } else if (data.entries && data.entries.length > 0) {
        state.logs = state.logs.concat(data.entries);
        if (state.logs.length > 1000) {
          state.logs = state.logs.slice(state.logs.length - 1000);
        }
      }
      state.logLatestSeq = data.latest_seq || state.logLatestSeq;
      state.logTotalBuffered = data.total_buffered || 0;
      state.logTags = data.tags || [];
      renderLogs();
    } catch (err) {
      if (!err.unauthorized) {
        // silent on background poll
      }
    }
  }

  /* Rendering helpers */
  function setHealthPill(kind, text) {
    const pill = $("health-pill");
    pill.className = "status-pill pill-" + kind;
    $("health-text").textContent = text;
  }

  function liveCooldownRemaining(acct) {
    const base = Number(acct.cooldown_remaining_sec) || 0;
    if (base <= 0) return 0;
    const elapsed = Math.floor((Date.now() - state.statusFetchedAt) / 1000);
    return Math.max(0, base - Math.max(0, elapsed));
  }

  function accountStateBadge(acct) {
    if (acct.disabled) return { cls: "pill-muted", text: "已禁用", cd: 0 };
    const cd = liveCooldownRemaining(acct);
    if (cd > 0) {
      const isSevere = acct.cooldown_kind === "monthly_quota" || acct.cooldown_kind === "subscription_expired" || acct.cooldown_kind === "auth_failed";
      return {
        cls: isSevere ? "pill-err" : "pill-warn",
        text: `${cooldownLabel(acct.cooldown_kind)} · ${fmtDuration(cd)}`,
        cd,
      };
    }
    return { cls: "pill-ok", text: "就绪", cd: 0 };
  }

  function quotaFillClass(pct) {
    if (pct >= 95) return "fill-err";
    if (pct >= 80) return "fill-warn";
    return "fill-ok";
  }

  function renderAll() {
    renderHealthAndKPIs();
    renderHourlyChart();
    renderOverviewModels();
    renderOverviewAccounts();
    renderOverviewRecent();
    renderAccountsTab();
    renderModelsTab();
  }

  function renderHealthAndKPIs() {
    const st = state.status;
    const mt = state.metrics;
    if (!st || !mt) return;

    const accts = st.accounts || [];
    const enabled = accts.filter((a) => !a.disabled);
    const ready = enabled.filter((a) => liveCooldownRemaining(a) === 0);
    const cooling = enabled.length - ready.length;

    $("nav-acct-count").textContent = String(accts.length);

    if (enabled.length === 0) {
      setHealthPill("err", "无可用账号");
    } else if (ready.length === 0) {
      setHealthPill("warn", "全部冷却中");
    } else {
      setHealthPill("ok", `运行中 · ${ready.length}/${enabled.length}`);
    }

    $("kpi-accounts").textContent = `${ready.length} / ${enabled.length}`;
    $("kpi-accounts-sub").textContent = `WS 连接 ${st.active_connections || 0}` + (cooling > 0 ? ` · 冷却 ${cooling}` : " · 全部健康");

    const t = mt.totals || {};
    $("kpi-requests").textContent = fmtNum(t.requests);
    const succText = t.requests > 0 ? `${t.success_rate_percent.toFixed(1)}%` : "--";
    $("kpi-requests-sub").textContent = `成功率 ${succText} · 进行中 ${mt.active_turns || 0}` + (t.errors > 0 ? ` · 异常 ${t.errors}` : "");

    $("kpi-tokens").textContent = fmtCompact(t.total_tokens);
    const cacheText = t.total_tokens > 0 ? `${t.cache_hit_rate_percent.toFixed(1)}%` : "--";
    $("kpi-tokens-sub").textContent = `缓存命中 ${cacheText} · 输出 ${fmtCompact(t.output_tokens)}`;

    $("kpi-latency").textContent = fmtLatency(t.avg_latency_ms);
    const costStr = t.cost_usd > 0 ? ` · 成本 $${t.cost_usd.toFixed(4)}` : "";
    $("kpi-latency-sub").textContent = `运行 ${fmtDuration(mt.uptime_sec)}${costStr}`;
  }

  /* 24h Tufte SVG Chart */
  function renderHourlyChart() {
    const container = $("hourly-chart");
    const mt = state.metrics;
    if (!mt || !mt.hourly || mt.hourly.length === 0) {
      container.innerHTML = '<div class="empty-state">暂无时段数据</div>';
      return;
    }
    const mode = state.chartMode;
    $("chart-subtitle").textContent = mode === "requests" ? "按小时汇总请求量与异常（悬停查看详情）" : "按小时汇总 Token 消耗（深色：新输入+输出，灰蓝：缓存读取）";

    const data = mt.hourly;
    const W = 640;
    const H = 196;
    const padL = 38;
    const padR = 10;
    const padT = 18;
    const padB = 26;
    const plotW = W - padL - padR;
    const plotH = H - padT - padB;
    const step = plotW / data.length;
    const barW = Math.max(6, Math.min(18, step * 0.56));

    let maxVal = 0;
    for (const d of data) {
      const v = mode === "requests" ? d.requests : (d.input_tokens + d.cache_read_tokens + d.output_tokens);
      if (v > maxVal) maxVal = v;
    }
    if (maxVal === 0) maxVal = 1;

    const parts = [];
    parts.push(`<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="24小时趋势柱状图">`);

    // Subtle Tufte reference hairlines (0, 50%, 100%)
    [0, 0.5, 1].forEach((f) => {
      const y = padT + plotH * (1 - f);
      const label = f === 0 ? "0" : (mode === "requests" ? fmtNum(Math.round(maxVal * f)) : fmtCompact(Math.round(maxVal * f)));
      parts.push(`<line x1="${padL}" y1="${y.toFixed(1)}" x2="${W - padR}" y2="${y.toFixed(1)}" stroke="var(--border)" stroke-width="1" ${f > 0 ? 'stroke-dasharray="2 3"' : ""} />`);
      parts.push(`<text x="${padL - 6}" y="${(y + 3.5).toFixed(1)}" text-anchor="end" font-size="10" fill="var(--ink-muted)" font-family="var(--font-mono)">${esc(label)}</text>`);
    });

    data.forEach((d, i) => {
      const slotX = padL + i * step;
      const barX = slotX + (step - barW) / 2;

      // Hover hit target
      parts.push(`<rect class="chart-bar-bg" data-idx="${i}" x="${slotX.toFixed(1)}" y="${padT}" width="${step.toFixed(1)}" height="${plotH}" rx="3" />`);

      if (mode === "requests") {
        if (d.requests > 0) {
          const totalH = Math.max(2, (d.requests / maxVal) * plotH);
          const errH = d.errors > 0 ? Math.max(2, (d.errors / maxVal) * plotH) : 0;
          const okH = Math.max(0, totalH - errH);
          const yTop = padT + plotH - totalH;
          if (okH > 0) {
            parts.push(`<rect x="${barX.toFixed(1)}" y="${(yTop + errH).toFixed(1)}" width="${barW.toFixed(1)}" height="${okH.toFixed(1)}" rx="2" fill="var(--ink)" pointer-events="none" />`);
          }
          if (errH > 0) {
            parts.push(`<rect x="${barX.toFixed(1)}" y="${yTop.toFixed(1)}" width="${barW.toFixed(1)}" height="${errH.toFixed(1)}" rx="2" fill="var(--signal)" pointer-events="none" />`);
          }
        }
      } else {
        const totalTok = d.input_tokens + d.cache_read_tokens + d.output_tokens;
        if (totalTok > 0) {
          const totalH = Math.max(2, (totalTok / maxVal) * plotH);
          const cacheH = d.cache_read_tokens > 0 ? (d.cache_read_tokens / totalTok) * totalH : 0;
          const activeH = Math.max(0, totalH - cacheH);
          const yTop = padT + plotH - totalH;
          if (cacheH > 0) {
            parts.push(`<rect x="${barX.toFixed(1)}" y="${(yTop + activeH).toFixed(1)}" width="${barW.toFixed(1)}" height="${cacheH.toFixed(1)}" rx="2" fill="var(--cache)" opacity="0.65" pointer-events="none" />`);
          }
          if (activeH > 0) {
            parts.push(`<rect x="${barX.toFixed(1)}" y="${yTop.toFixed(1)}" width="${barW.toFixed(1)}" height="${Math.max(2, activeH).toFixed(1)}" rx="2" fill="var(--ink)" pointer-events="none" />`);
          }
        }
      }

      // Show x-axis labels every 4 hours plus the latest hour
      if (i % 4 === 0 || i === data.length - 1) {
        const cx = slotX + step / 2;
        parts.push(`<text x="${cx.toFixed(1)}" y="${H - 6}" text-anchor="middle" font-size="10" fill="var(--ink-muted)" font-family="var(--font-mono)">${esc(d.label)}</text>`);
      }
    });

    parts.push("</svg>");
    container.innerHTML = parts.join("");

    const tooltip = $("chart-tooltip");
    const wrap = container.parentElement;
    container.querySelectorAll(".chart-bar-bg").forEach((rect) => {
      rect.addEventListener("mouseenter", (e) => {
        const d = data[Number(rect.getAttribute("data-idx"))];
        const totalTok = d.input_tokens + d.cache_read_tokens + d.output_tokens;
        tooltip.innerHTML = `
          <div class="mono" style="font-weight:600;margin-bottom:2px">${esc(d.label)}</div>
          <div class="mono">请求 ${fmtNum(d.requests)}${d.errors > 0 ? ` · 异常 ${fmtNum(d.errors)}` : ""}</div>
          <div class="mono">Token ${fmtCompact(totalTok)}（缓存 ${fmtCompact(d.cache_read_tokens)} / 输出 ${fmtCompact(d.output_tokens)}）</div>
        `;
        tooltip.classList.remove("hidden");
        positionTooltip(e, wrap, tooltip);
      });
      rect.addEventListener("mousemove", (e) => positionTooltip(e, wrap, tooltip));
      rect.addEventListener("mouseleave", () => tooltip.classList.add("hidden"));
    });
  }

  function positionTooltip(e, wrap, tooltip) {
    const r = wrap.getBoundingClientRect();
    const x = e.clientX - r.left;
    const y = e.clientY - r.top;
    const tw = tooltip.offsetWidth || 180;
    const left = Math.max(8, Math.min(r.width - tw - 8, x - tw / 2));
    const top = Math.max(6, y - (tooltip.offsetHeight || 58) - 10);
    tooltip.style.left = left + "px";
    tooltip.style.top = top + "px";
  }

  /* Overview Models */
  function renderOverviewModels() {
    const el = $("overview-models");
    const list = (state.metrics && state.metrics.by_model) || [];
    if (list.length === 0) {
      el.innerHTML = '<div class="empty-state">尚无模型调用记录</div>';
      return;
    }
    const maxReq = Math.max(...list.map((m) => m.requests), 1);
    const totalReq = list.reduce((acc, m) => acc + m.requests, 0) || 1;
    el.innerHTML = list.slice(0, 6).map((m) => {
      const pct = Math.max(3, Math.round((m.requests / maxReq) * 100));
      const share = ((m.requests / totalReq) * 100).toFixed(0);
      return `
        <div class="model-bar-item">
          <div class="model-bar-head">
            <span class="model-bar-name" title="${esc(m.model)}">${esc(m.model)}</span>
            <span class="model-bar-stat">${fmtNum(m.requests)} 次 (${share}%) · ${fmtCompact(m.total_tokens)}</span>
          </div>
          <div class="progress-track">
            <div class="progress-fill" style="width:${pct}%"></div>
          </div>
        </div>
      `;
    }).join("");
  }

  /* Overview Accounts Snapshot */
  function renderOverviewAccounts() {
    const el = $("overview-accounts");
    const accts = (state.status && state.status.accounts) || [];
    if (accts.length === 0) {
      el.innerHTML = '<div class="empty-state">未配置账号</div>';
      return;
    }
    el.innerHTML = accts.slice(0, 6).map((a) => {
      const badge = accountStateBadge(a);
      const q = a.quota;
      const monthlyText = q ? `月 ${q.monthly_used}/${q.monthly_limit} (${q.monthly_percent}%)` : "月配额未拉取";
      const sessionText = q ? `会话 ${q.session_used}/${q.session_limit}` : "";
      const proxyText = a.proxy ? a.proxy : "直连";
      return `
        <div class="mini-item">
          <div class="mini-item-top">
            <span class="mini-id" title="${esc(a.id)}">${esc(a.id)}</span>
            <span class="status-pill ${badge.cls}" data-cd-acct="${esc(a.id)}"><span class="dot"></span>${esc(badge.text)}</span>
          </div>
          <div class="mini-meta mono">
            <span>${esc(monthlyText)}</span>
            ${sessionText ? `<span>${esc(sessionText)}</span>` : ""}
            <span>${esc(a.region || "us-east-1")}</span>
            <span title="${esc(proxyText)}">${esc(proxyText)}</span>
          </div>
        </div>
      `;
    }).join("");
  }

  /* Overview Recent Requests */
  function renderOverviewRecent() {
    const tbody = $("overview-recent");
    const list = (state.metrics && state.metrics.recent) || [];
    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state">尚无请求记录</div></td></tr>';
      return;
    }
    tbody.innerHTML = list.slice(0, 10).map((r) => {
      const ok = r.status === "ok";
      const pill = ok ? '<span class="status-pill pill-ok">200</span>' : `<span class="status-pill pill-err" title="${esc(r.status)}">${esc(r.http_status || r.status)}</span>`;
      const cacheTag = r.cache_read_tokens > 0 ? ` / <span style="color:var(--cache)">${fmtCompact(r.cache_read_tokens)}</span>` : "";
      return `
        <tr>
          <td class="mono">${esc(fmtClock(r.timestamp))}</td>
          <td class="mono">${esc(r.model)}</td>
          <td class="mono">${esc(r.account_id || "-")}</td>
          <td class="num mono">${fmtCompact(r.total_tokens)}${cacheTag}</td>
          <td class="num mono">${fmtLatency(r.latency_ms)}</td>
          <td>${pill}</td>
        </tr>
      `;
    }).join("");
  }

  /* Accounts Full Tab */
  function renderAccountsTab() {
    const grid = $("accounts-grid");
    const accts = (state.status && state.status.accounts) || [];
    grid.classList.toggle("single-card", accts.length === 1);
    if (accts.length === 0) {
      grid.innerHTML = `
        <div class="panel">
          <div class="empty-state">
            <div style="margin-bottom:10px">暂无账号，点击右上角「+ OAuth 登录」即可通过远程回调 URL 添加 Amazon Quick 账号。</div>
            <button type="button" class="btn btn-primary btn-sm" data-act="open-oauth">+ OAuth 登录</button>
          </div>
        </div>
      `;
      return;
    }
    const usageByAcct = {};
    ((state.metrics && state.metrics.by_account) || []).forEach((u) => {
      usageByAcct[u.account_id] = u;
    });

    grid.innerHTML = accts.map((a) => {
      const badge = accountStateBadge(a);
      const q = a.quota;
      const u = usageByAcct[a.id];
      const probe = state.probeResults[a.id];
      const sub = formatSubscription(q);

      const monthlyPct = q ? Math.min(100, Math.max(0, q.monthly_percent || (q.monthly_limit > 0 ? Math.round((q.monthly_used / q.monthly_limit) * 100) : 0))) : 0;
      const sessionPct = q ? Math.min(100, Math.max(0, q.session_percent || (q.session_limit > 0 ? Math.round((q.session_used / q.session_limit) * 100) : 0))) : 0;
      const monthlyHasVal = q && q.monthly_used > 0;
      const sessionHasVal = q && q.session_used > 0;

      const quotaHTML = q ? `
        <div class="quota-grid">
          <div class="quota-box">
            <div class="quota-row">
              <span class="quota-label">月度配额</span>
              <span class="quota-val">${fmtNum(q.monthly_used)}<span class="quota-limit"> / ${fmtNum(q.monthly_limit)}</span></span>
            </div>
            <div class="progress-track">
              <div class="progress-fill ${quotaFillClass(monthlyPct)}${monthlyHasVal ? " has-val" : ""}" style="width:${monthlyPct}%"></div>
            </div>
            <div class="quota-foot">
              <span class="mono">${monthlyPct}%</span>
              <span>${q.monthly_resets_at ? "重置 " + fmtDateTime(q.monthly_resets_at) : "本月已用"}</span>
            </div>
          </div>
          <div class="quota-box">
            <div class="quota-row">
              <span class="quota-label">会话配额</span>
              <span class="quota-val">${fmtNum(q.session_used)}<span class="quota-limit"> / ${fmtNum(q.session_limit)}</span></span>
            </div>
            <div class="progress-track">
              <div class="progress-fill ${quotaFillClass(sessionPct)}${sessionHasVal ? " has-val" : ""}" style="width:${sessionPct}%"></div>
            </div>
            <div class="quota-foot">
              <span class="mono">${sessionPct}%</span>
              <span>${q.session_resume_in_minutes ? `${q.session_resume_in_minutes}m 后恢复` : (q.session_resets_at ? "重置 " + fmtClock(q.session_resets_at) : "当前窗口")}</span>
            </div>
          </div>
        </div>
      ` : `
        <div class="quota-empty">
          <span>尚未拉取配额快照</span>
          <button type="button" class="link-btn" data-act="fetch-usage">立即拉取 →</button>
        </div>
      `;

      const tokenExpired = !(a.access_expires_in_sec > 0);
      const tokenTTL = tokenExpired ? "待自动刷新" : fmtDuration(a.access_expires_in_sec);
      const refreshHint = a.has_refresh_token ? "含 Refresh Token" : "无 Refresh Token";
      const reqMain = u ? `${fmtNum(u.requests)} 次` : "0 次";
      const reqSub = u
        ? (u.total_tokens > 0 ? `${fmtCompact(u.total_tokens)} tok` : (u.errors > 0 ? `异常 ${u.errors}` : "本轮无 Token"))
        : "服务启动至今";
      const proxyDisplay = a.proxy || "直连（未配置代理）";

      const probeBadge = probe
        ? `<span class="acct-probe-pill ${probe.ok ? "ok" : "err"}" title="${esc(probe.ok ? `出口 IP ${probe.ip}` : probe.error)}">${probe.ok ? `${esc(probe.ip)} · ${probe.latency}ms` : "探测失败"}</span>`
        : "";

      return `
        <article class="acct-card${a.disabled ? " is-disabled" : ""}">
          <div class="acct-head">
            <div class="acct-head-main">
              <div class="acct-title-row">
                <span class="acct-title">${esc(a.id)}</span>
                ${sub.label ? `<span class="acct-sub-badge" title="${esc(sub.raw)}">${esc(sub.label)}</span>` : ""}
              </div>
              <div class="acct-sub mono" title="${esc(a.tenant_host || "")}">${esc(a.tenant_host || "-")}</div>
            </div>
            <span class="status-pill ${badge.cls}" data-cd-acct="${esc(a.id)}"><span class="dot"></span>${esc(badge.text)}</span>
          </div>
          <div class="acct-body">
            ${quotaHTML}
            <div class="acct-proxy-bar">
              <div class="acct-proxy-main">
                <span class="acct-proxy-label">出口代理</span>
                <span class="acct-proxy-val" title="${esc(proxyDisplay)}">${esc(proxyDisplay)}</span>
              </div>
              ${probeBadge}
            </div>
            <div class="acct-stats-row">
              <div class="acct-stat">
                <span class="acct-stat-k">区域</span>
                <span class="acct-stat-v">${esc(a.region || "us-east-1")}</span>
                <span class="acct-stat-sub">${q && q.updated_at ? `配额同步 ${esc(fmtClock(q.updated_at))}` : "未拉取配额"}</span>
              </div>
              <div class="acct-stat">
                <span class="acct-stat-k">Access Token</span>
                <span class="acct-stat-v${tokenExpired ? " is-warn" : ""}">${esc(tokenTTL)}</span>
                <span class="acct-stat-sub">${esc(refreshHint)}</span>
              </div>
              <div class="acct-stat">
                <span class="acct-stat-k">本轮请求</span>
                <span class="acct-stat-v">${esc(reqMain)}</span>
                <span class="acct-stat-sub">${esc(reqSub)}</span>
              </div>
            </div>
            ${a.last_error ? `<div class="acct-error">${esc(a.last_error)}</div>` : ""}
          </div>
          <div class="acct-foot">
            <div class="acct-foot-group">
              <button type="button" class="btn btn-secondary btn-sm" data-act="proxy" data-id="${esc(a.id)}">设置代理</button>
              <button type="button" class="btn btn-secondary btn-sm" data-act="probe" data-id="${esc(a.id)}">探测出口</button>
              <button type="button" class="btn btn-ghost btn-sm" data-act="reset-cd" data-id="${esc(a.id)}" ${badge.cd > 0 || a.last_error ? "" : "disabled"}>清除冷却</button>
            </div>
            <div class="acct-foot-group">
              <button type="button" class="btn btn-ghost btn-sm" data-act="toggle" data-id="${esc(a.id)}" data-disabled="${a.disabled ? "1" : "0"}">${a.disabled ? "启用" : "禁用"}</button>
              <button type="button" class="btn btn-danger-ghost btn-sm" data-act="delete" data-id="${esc(a.id)}">删除</button>
            </div>
          </div>
        </article>
      `;
    }).join("");
  }

  /* Models Tab */
  function renderModelsTab() {
    const mt = state.metrics;
    if (!mt) return;
    $("metrics-uptime-desc").textContent = `自 ${fmtDateTime(mt.started_at)} 启动以来的内存实时统计（运行时长 ${fmtDuration(mt.uptime_sec)}）`;

    const models = mt.by_model || [];
    $("model-count-meta").textContent = `${models.length} 个模型`;
    const mBody = $("models-table-body");
    if (models.length === 0) {
      mBody.innerHTML = '<tr><td colspan="11"><div class="empty-state">暂无模型使用数据</div></td></tr>';
    } else {
      mBody.innerHTML = models.map((m) => {
        const succ = m.requests > 0 ? ((m.success / m.requests) * 100).toFixed(1) + "%" : "--";
        return `
          <tr>
            <td class="mono strong-text">${esc(m.model)}</td>
            <td class="num mono">${fmtNum(m.requests)}</td>
            <td class="num mono">${succ}</td>
            <td class="num mono">${fmtCompact(m.input_tokens)}</td>
            <td class="num mono" style="color:var(--cache)">${fmtCompact(m.cache_read_tokens)}</td>
            <td class="num mono">${m.cache_hit_rate_percent.toFixed(1)}%</td>
            <td class="num mono">${fmtCompact(m.output_tokens)}</td>
            <td class="num mono">${fmtNum(m.tool_call_requests)}</td>
            <td class="num mono">${fmtLatency(m.avg_latency_ms)}</td>
            <td class="num mono">${m.cost_usd > 0 ? "$" + m.cost_usd.toFixed(4) : "--"}</td>
            <td class="num mono">${esc(fmtClock(m.last_used_at))}</td>
          </tr>
        `;
      }).join("");
    }

    const acctList = mt.by_account || [];
    $("acct-usage-meta").textContent = `${acctList.length} 个活跃账号`;
    const aBody = $("acct-usage-body");
    if (acctList.length === 0) {
      aBody.innerHTML = '<tr><td colspan="7"><div class="empty-state">暂无账号流量统计</div></td></tr>';
    } else {
      aBody.innerHTML = acctList.map((a) => `
        <tr>
          <td class="mono strong-text">${esc(a.account_id)}</td>
          <td class="num mono">${fmtNum(a.requests)}</td>
          <td class="num mono">${fmtNum(a.success)} / ${fmtNum(a.errors)}</td>
          <td class="num mono">${a.rate_limited > 0 ? `<span style="color:var(--warn)">${fmtNum(a.rate_limited)}</span>` : "0"}</td>
          <td class="num mono">${fmtCompact(a.total_tokens)}</td>
          <td class="num mono">${fmtLatency(a.avg_latency_ms)}</td>
          <td class="num mono">${esc(fmtClock(a.last_used_at))}</td>
        </tr>
      `).join("");
    }

    // Update model filter options preserving selection
    const sel = $("recent-model-filter");
    const prev = sel.value;
    const modelNames = Array.from(new Set((mt.recent || []).map((r) => r.model))).sort();
    sel.innerHTML = '<option value="">全部模型</option>' + modelNames.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join("");
    if (modelNames.includes(prev)) sel.value = prev;

    renderRecentFullTable();
  }

  function renderRecentFullTable() {
    const list = (state.metrics && state.metrics.recent) || [];
    const wantModel = $("recent-model-filter").value;
    const wantStatus = $("recent-status-filter").value;
    const filtered = list.filter((r) => {
      if (wantModel && r.model !== wantModel) return false;
      if (wantStatus === "ok" && r.status !== "ok") return false;
      if (wantStatus === "err" && r.status === "ok") return false;
      return true;
    });
    const body = $("recent-full-body");
    if (filtered.length === 0) {
      body.innerHTML = '<tr><td colspan="8"><div class="empty-state">无匹配的请求记录</div></td></tr>';
      return;
    }
    body.innerHTML = filtered.map((r) => {
      const ok = r.status === "ok";
      const pill = ok ? '<span class="status-pill pill-ok">OK</span>' : `<span class="status-pill pill-err">${esc(r.status)}</span>`;
      const chips = [];
      if (r.stream) chips.push('<span class="tag-chip">SSE</span>');
      if (r.tool_calls > 0) chips.push(`<span class="tag-chip">tools:${r.tool_calls}</span>`);
      const shortID = (r.id || "").replace(/^chatcmpl-/, "").slice(0, 10) || "-";
      return `
        <tr>
          <td class="mono">${esc(fmtClock(r.timestamp))}</td>
          <td class="mono" style="color:var(--ink-muted)" title="${esc(r.id || "")}">${esc(shortID)}</td>
          <td class="mono">${esc(r.model)}</td>
          <td class="mono">${esc(r.account_id || "-")}</td>
          <td>${chips.join(" ") || "-"}</td>
          <td class="num mono">${fmtCompact(r.input_tokens)} / <span style="color:var(--cache)">${fmtCompact(r.cache_read_tokens)}</span> / ${fmtCompact(r.output_tokens)}</td>
          <td class="num mono">${fmtLatency(r.latency_ms)}</td>
          <td>${pill}</td>
        </tr>
      `;
    }).join("");
  }

  /* Logs Tab */
  function getFilteredLogs() {
    const q = state.logSearch.trim().toLowerCase();
    return state.logs.filter((e) => {
      if (state.logLevel !== "all" && e.level !== state.logLevel) return false;
      if (state.logTag !== "all" && e.tag !== state.logTag) return false;
      if (q && !e.message.toLowerCase().includes(q) && !e.tag.toLowerCase().includes(q)) return false;
      return true;
    });
  }

  function renderLogs() {
    const errCount = state.logs.filter((e) => e.level === "error").length;
    const errBadge = $("nav-log-err");
    if (errCount > 0) {
      errBadge.textContent = String(errCount);
      errBadge.classList.remove("hidden");
    } else {
      errBadge.classList.add("hidden");
    }

    const sel = $("log-tag-filter");
    const curTag = state.logTag;
    sel.innerHTML = '<option value="all">全部模块</option>' + state.logTags.map((t) => `<option value="${esc(t)}">${esc(t)}</option>`).join("");
    if (state.logTags.includes(curTag)) sel.value = curTag;

    const filtered = getFilteredLogs();
    $("logs-meta").textContent = `缓冲 ${state.logTotalBuffered} 条 · 当前显示 ${filtered.length} 条 · 自动脱敏 Token 与代理凭据`;

    const viewer = $("log-viewer");
    if (filtered.length === 0) {
      viewer.innerHTML = '<div class="empty-state">暂无符合条件的运行日志</div>';
      return;
    }
    viewer.innerHTML = filtered.map((e) => `
      <div class="log-row">
        <span class="log-seq">#${e.seq}</span>
        <span class="log-time">${esc(fmtISOTime(e.time))}</span>
        <span class="log-lvl ${esc(e.level)}">${esc(e.level)}</span>
        <span class="log-tag" title="${esc(e.tag)}">[${esc(e.tag)}]</span>
        <span class="log-msg">${esc(e.message)}</span>
      </div>
    `).join("");

    if ($("log-autoscroll").checked) {
      viewer.scrollTop = viewer.scrollHeight;
    }
  }

  /* 1-second local countdown tick */
  function tickCountdowns() {
    if (!state.status || !state.status.accounts) return;
    let needsRerender = false;
    state.status.accounts.forEach((a) => {
      if ((a.cooldown_remaining_sec || 0) <= 0) return;
      const badge = accountStateBadge(a);
      document.querySelectorAll(`[data-cd-acct="${CSS.escape(a.id)}"]`).forEach((el) => {
        el.className = "status-pill " + badge.cls;
        el.innerHTML = `<span class="dot"></span>${esc(badge.text)}`;
      });
      if (badge.cd === 0) needsRerender = true;
    });
    if (needsRerender) {
      renderHealthAndKPIs();
    }
  }

  /* Actions */
  function switchTab(tab) {
    state.activeTab = tab;
    document.querySelectorAll(".nav-tab").forEach((b) => {
      const active = b.getAttribute("data-tab") === tab;
      b.classList.toggle("active", active);
      b.setAttribute("aria-selected", active ? "true" : "false");
    });
    document.querySelectorAll(".tab-view").forEach((v) => {
      v.classList.toggle("active", v.id === "view-" + tab);
    });
    if (tab === "logs" && state.logs.length === 0) {
      fetchLogs(true);
    }
  }

  function openProxyModal(acctId) {
    state.proxyModalAcctId = acctId;
    $("proxy-acct-id").textContent = acctId;
    const acct = ((state.status && state.status.accounts) || []).find((a) => a.id === acctId);
    const cur = acct && acct.proxy ? acct.proxy.replace(/\s*\(global\)$/, "") : "";
    $("proxy-url-input").value = acct && acct.proxy && acct.proxy.endsWith("(global)") ? "" : cur;
    $("proxy-error").classList.add("hidden");
    $("proxy-modal").classList.remove("hidden");
    $("proxy-url-input").focus();
  }

  function closeProxyModal() {
    $("proxy-modal").classList.add("hidden");
    state.proxyModalAcctId = "";
  }

  async function probeAccountProxy(acctId, btn) {
    if (btn) {
      btn.disabled = true;
      btn.textContent = "探测中...";
    }
    try {
      const res = await apiFetch("/admin/accounts/probe-proxy", {
        method: "POST",
        body: { id: acctId },
      });
      state.probeResults[acctId] = { ok: true, ip: res.egress_ip, latency: res.latency_ms };
      toast(`${acctId} 出口正常: ${res.egress_ip} (${res.latency_ms}ms)`);
    } catch (err) {
      if (!err.unauthorized) {
        state.probeResults[acctId] = { ok: false, error: err.message };
        toast(`出口探测失败: ${err.message}`, true);
      }
    } finally {
      renderAccountsTab();
    }
  }

  async function resetAccountCooldown(acctId) {
    try {
      const res = await apiFetch("/admin/accounts/reset-cooldown", {
        method: "POST",
        body: acctId ? { id: acctId } : {},
      });
      toast(acctId ? `已清除 ${acctId} 冷却状态` : `已清除 ${res.cleared || 0} 个账号的冷却状态`);
      await fetchCore(false);
    } catch (err) {
      if (!err.unauthorized) toast("清除冷却失败: " + err.message, true);
    }
  }

  async function toggleAccountDisabled(acctId, nextDisabled) {
    try {
      await apiFetch("/admin/accounts/toggle", {
        method: "POST",
        body: { id: acctId, disabled: nextDisabled },
      });
      toast(nextDisabled ? `已禁用账号 ${acctId}` : `已启用账号 ${acctId}`);
      await fetchCore(false);
    } catch (err) {
      if (!err.unauthorized) toast("切换账号状态失败: " + err.message, true);
    }
  }

  async function deleteAccount(acctId) {
    if (!window.confirm(`确认永久删除账号 ${acctId}？\n该操作会立即从 accounts.json 移除凭证并断开其连接。`)) return;
    try {
      await apiFetch("/admin/accounts/delete", {
        method: "POST",
        body: { id: acctId },
      });
      delete state.probeResults[acctId];
      toast(`已删除账号 ${acctId}`);
      await fetchCore(false);
    } catch (err) {
      if (!err.unauthorized) toast("删除账号失败: " + err.message, true);
    }
  }

  function switchAddAccountMode(mode) {
    state.oauthMode = mode === "import" ? "import" : "oauth";
    $("add-acct-tabs").querySelectorAll(".seg-btn").forEach((b) => {
      b.classList.toggle("active", b.getAttribute("data-add-mode") === state.oauthMode);
    });
    $("add-pane-oauth").classList.toggle("hidden", state.oauthMode !== "oauth");
    $("import-json-form").classList.toggle("hidden", state.oauthMode !== "import");
  }

  function resetOAuthFlow() {
    state.oauthSession = null;
    $("oauth-step2").classList.add("hidden");
    $("oauth-auth-url").value = "";
    $("oauth-open-link").setAttribute("href", "#");
    $("oauth-callback-input").value = "";
    $("oauth-error").classList.add("hidden");
    $("oauth-warn").classList.add("hidden");
    $("oauth-ok").classList.add("hidden");
    $("oauth-start-btn").textContent = "步骤 2：生成 OIDC 授权链接";
  }

  function parseDiscoveryCallbackInput(raw) {
    const s = (raw || "").trim();
    if (!s) return { error: "请先粘贴 quick.aws.com 跳转后的回调 URL。" };
    let parseTarget = s;
    if (!parseTarget.includes("://") && (parseTarget.includes("=") || parseTarget.startsWith("?"))) {
      parseTarget = "http://127.0.0.1/discovery?" + parseTarget.replace(/^\?/, "");
    }
    let u;
    try {
      u = new URL(parseTarget);
    } catch (_) {
      return { error: "URL 格式无效，请复制浏览器地址栏完整链接。" };
    }
    const params = new URLSearchParams(u.search);
    if (u.hash && u.hash.includes("=")) {
      const fp = new URLSearchParams(u.hash.replace(/^#\??/, ""));
      fp.forEach((v, k) => { if (!params.get(k)) params.set(k, v); });
    }
    const pick = (...keys) => {
      for (const k of keys) {
        const v = (params.get(k) || "").trim();
        if (v) return v;
      }
      return "";
    };
    const errCode = pick("error");
    if (errCode) {
      const desc = pick("error_description", "errorDescription");
      return { error: desc ? `${errCode}: ${desc}` : errCode };
    }
    let tenant = pick("tenant_url", "tenantUrl", "tenant").replace(/\/+$/, "");
    if (!tenant) {
      const wsHost = pick("ws_host", "wsHost");
      if (wsHost) tenant = "https://" + wsHost.replace(/^https?:\/\//i, "").replace(/\/+$/, "");
    }
    if (!tenant && u.protocol === "https:" && u.hostname && u.hostname !== "127.0.0.1" && u.hostname !== "localhost") {
      tenant = "https://" + u.host;
    }
    if (tenant && !tenant.includes("://")) tenant = "https://" + tenant;
    if (!tenant || !/^https:\/\/[^/\s]+/i.test(tenant)) {
      return { error: "未在链接中检测到有效的 https:// tenant_url，请确认已复制登录后跳转的完整 127.0.0.1 地址栏链接。" };
    }
    let issuer = pick("issuer_url", "issuerUrl", "issuer").replace(/\/+$/, "");
    const instId = pick("idc_instance_id", "idcInstanceId");
    if (!issuer && instId) issuer = "https://identitycenter.amazonaws.com/" + instId;
    let region = pick("idc_region", "idcRegion", "region");
    if (!region) {
      const m = tenant.match(/\.((?:us|eu|ap|ca|sa|me|af)-[a-z]+-\d+)\./i);
      if (m) region = m[1].toLowerCase();
    }
    return { tenant_url: tenant, issuer_url: issuer, region };
  }

  function applyDiscoveryCallback(raw, silentOnEmpty = false) {
    if (!raw || !raw.trim()) {
      if (!silentOnEmpty) {
        $("oauth-error").textContent = "请先粘贴 quick.aws.com 跳转后的回调 URL。";
        $("oauth-error").classList.remove("hidden");
      }
      return false;
    }
    const parsed = parseDiscoveryCallbackInput(raw);
    if (parsed.error) {
      $("oauth-error").textContent = parsed.error;
      $("oauth-error").classList.remove("hidden");
      $("oauth-disc-badge").classList.add("hidden");
      return false;
    }
    $("oauth-error").classList.add("hidden");
    $("oauth-tenant-input").value = parsed.tenant_url;
    if (parsed.issuer_url) $("oauth-issuer-input").value = parsed.issuer_url;
    if (parsed.region) $("oauth-region-input").value = parsed.region;
    $("oauth-disc-badge").classList.remove("hidden");
    toast("已自动提取该账号的 tenant_url 与区域，请点击步骤 2 生成授权链接");
    return true;
  }

  function openOAuthModal(mode = "oauth") {
    resetOAuthFlow();
    $("import-error").classList.add("hidden");
    $("import-json-input").value = "";
    $("import-proxy-input").value = "";
    $("oauth-disc-callback").value = "";
    $("oauth-disc-url").value = "";
    $("oauth-disc-url").classList.add("hidden");
    $("oauth-disc-open").classList.add("hidden");
    $("oauth-disc-copy").classList.add("hidden");
    $("oauth-disc-badge").classList.add("hidden");
    $("oauth-tenant-input").value = "";
    $("oauth-scopes-input").value = "quicksight:read_write";
    const firstWithHost = ((state.status && state.status.accounts) || []).find((a) => a.tenant_host);
    $("btn-reuse-tenant").classList.toggle("hidden", !firstWithHost);
    switchAddAccountMode(mode);
    $("oauth-modal").classList.remove("hidden");
    if (mode === "import") {
      $("import-json-input").focus();
    } else {
      $("oauth-disc-callback").focus();
    }
  }

  function closeOAuthModal() {
    $("oauth-modal").classList.add("hidden");
  }

  async function copyToClipboard(text, successMsg) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      toast(successMsg || "已复制到剪贴板");
    } catch (_) {
      toast("剪贴板不可用，请手动复制", true);
    }
  }

  /* Timers */
  function startTimers() {
    stopTimers();
    if (state.autoRefresh) {
      pollTimer = setInterval(() => {
        if (state.authenticated && !document.hidden) fetchCore(false);
      }, 5000);
    }
    logTimer = setInterval(() => {
      if (state.authenticated && !state.logPaused && !document.hidden) fetchLogs(false);
    }, 3000);
    tickTimer = setInterval(tickCountdowns, 1000);
  }

  function stopTimers() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    if (logTimer) { clearInterval(logTimer); logTimer = null; }
    if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
  }

  /* Event Bindings */
  function bindEvents() {
    // Tabs & goto links
    document.querySelectorAll(".nav-tab").forEach((b) => {
      b.addEventListener("click", () => switchTab(b.getAttribute("data-tab")));
    });
    document.querySelectorAll("[data-goto]").forEach((b) => {
      b.addEventListener("click", () => switchTab(b.getAttribute("data-goto")));
    });

    // Topbar controls
    $("btn-autorefresh").addEventListener("click", () => {
      state.autoRefresh = !state.autoRefresh;
      $("btn-autorefresh").classList.toggle("active", state.autoRefresh);
      $("autorefresh-label").textContent = state.autoRefresh ? "自动 5s" : "已暂停";
      startTimers();
    });

    $("btn-refresh").addEventListener("click", async () => {
      await fetchCore(false);
      await fetchLogs(false);
      toast("数据已刷新");
    });

    $("btn-theme").addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      localStorage.setItem(THEME_STORAGE, next);
      applyTheme(next);
    });

    $("btn-logout").addEventListener("click", async () => {
      try {
        await apiFetch("/admin/auth/logout", { method: "POST", noAuthGate: true });
      } catch (_) {}
      state.authenticated = false;
      $("auth-pass-input").value = "";
      $("btn-logout").classList.add("hidden");
      showAuthGate("");
      toast("已退出登录");
    });

    // Auth gate form
    $("auth-toggle-vis").addEventListener("click", () => {
      const inp = $("auth-pass-input");
      const show = inp.type === "password";
      inp.type = show ? "text" : "password";
      $("auth-toggle-vis").textContent = show ? "隐藏" : "显示";
    });

    $("auth-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const username = $("auth-user-input").value.trim() || "root";
      const password = $("auth-pass-input").value;
      if (!password) return;
      const btn = $("auth-submit");
      btn.disabled = true;
      btn.textContent = "登录中...";
      $("auth-error").classList.add("hidden");
      try {
        await apiFetch("/admin/auth/login", {
          method: "POST",
          body: { username, password, remember: $("auth-remember").checked },
          noAuthGate: true,
        });
        $("auth-pass-input").value = "";
        await fetchCore(false);
        await fetchLogs(true);
        startTimers();
        toast("欢迎回来，root");
      } catch (err) {
        const msg = /too many/i.test(err.message)
          ? "失败次数过多，请 5 分钟后再试。"
          : "用户名或密码错误，请重试。";
        $("auth-error").textContent = msg;
        $("auth-error").classList.remove("hidden");
        $("auth-pass-input").select();
      } finally {
        btn.disabled = false;
        btn.textContent = "登录控制台";
      }
    });
    // Chart mode toggle
    document.querySelectorAll("[data-chart-mode]").forEach((b) => {
      b.addEventListener("click", () => {
        state.chartMode = b.getAttribute("data-chart-mode");
        document.querySelectorAll("[data-chart-mode]").forEach((x) => x.classList.toggle("active", x === b));
        renderHourlyChart();
      });
    });

    // Accounts tab global actions
    $("btn-open-oauth").addEventListener("click", () => openOAuthModal("oauth"));

    $("btn-fetch-usage").addEventListener("click", async () => {
      const btn = $("btn-fetch-usage");
      btn.disabled = true;
      btn.textContent = "拉取中...";
      try {
        await fetchCore(true);
        toast("实时配额快照已更新");
      } finally {
        btn.disabled = false;
        btn.textContent = "拉取实时配额";
      }
    });

    $("btn-reload-accounts").addEventListener("click", async () => {
      const btn = $("btn-reload-accounts");
      btn.disabled = true;
      try {
        const res = await apiFetch("/admin/reload", { method: "POST" });
        const r = res.reload || {};
        toast(`热重载完成：共 ${r.total || 0} 个（可用 ${r.enabled || 0}）`);
        await fetchCore(false);
        await fetchLogs(false);
      } catch (err) {
        if (!err.unauthorized) toast("热重载失败: " + err.message, true);
      } finally {
        btn.disabled = false;
      }
    });

    $("btn-reset-all-cd").addEventListener("click", () => resetAccountCooldown(""));

    // Delegated account card buttons
    $("accounts-grid").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-act]");
      if (!btn) return;
      const act = btn.getAttribute("data-act");
      const id = btn.getAttribute("data-id");
      if (act === "proxy") openProxyModal(id);
      else if (act === "probe") probeAccountProxy(id, btn);
      else if (act === "reset-cd") resetAccountCooldown(id);
      else if (act === "toggle") toggleAccountDisabled(id, btn.getAttribute("data-disabled") !== "1");
      else if (act === "delete") deleteAccount(id);
      else if (act === "open-oauth") openOAuthModal("oauth");
      else if (act === "fetch-usage") $("btn-fetch-usage").click();
    });

    // Proxy modal
    $("proxy-modal-close").addEventListener("click", closeProxyModal);
    $("proxy-cancel").addEventListener("click", closeProxyModal);
    $("proxy-modal").addEventListener("click", (e) => {
      if (e.target === $("proxy-modal")) closeProxyModal();
    });
    document.querySelectorAll("[data-proxy-preset]").forEach((b) => {
      b.addEventListener("click", () => {
        $("proxy-url-input").value = b.getAttribute("data-proxy-preset");
        $("proxy-url-input").focus();
      });
    });
    $("proxy-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const id = state.proxyModalAcctId;
      if (!id) return;
      const proxyURL = $("proxy-url-input").value.trim();
      const btn = $("proxy-save");
      btn.disabled = true;
      $("proxy-error").classList.add("hidden");
      try {
        await apiFetch("/admin/accounts/proxy", {
          method: "POST",
          body: { id, proxy_url: proxyURL },
        });
        delete state.probeResults[id];
        closeProxyModal();
        toast(`已更新 ${id} 代理配置`);
        await fetchCore(false);
      } catch (err) {
        if (!err.unauthorized) {
          $("proxy-error").textContent = err.message;
          $("proxy-error").classList.remove("hidden");
        }
      } finally {
        btn.disabled = false;
      }
    });

    // OAuth Login & JSON Import Modal
    $("oauth-modal-close").addEventListener("click", closeOAuthModal);
    $("import-cancel").addEventListener("click", closeOAuthModal);
    $("oauth-modal").addEventListener("click", (e) => {
      if (e.target === $("oauth-modal")) closeOAuthModal();
    });
    $("add-acct-tabs").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-add-mode]");
      if (!btn) return;
      switchAddAccountMode(btn.getAttribute("data-add-mode"));
    });
    document.querySelectorAll("[data-oauth-proxy]").forEach((b) => {
      b.addEventListener("click", () => {
        $("oauth-proxy-input").value = b.getAttribute("data-oauth-proxy");
        $("oauth-proxy-input").focus();
      });
    });
    $("btn-oauth-discover").addEventListener("click", async () => {
      const btn = $("btn-oauth-discover");
      btn.disabled = true;
      btn.textContent = "生成中...";
      $("oauth-error").classList.add("hidden");
      try {
        const port = Number($("oauth-port-input").value) || 18080;
        const res = await apiFetch("/admin/oauth/discover", {
          method: "POST",
          body: { callback_port: port },
        });
        const url = res.discovery_url || "";
        $("oauth-disc-url").value = url;
        $("oauth-disc-url").classList.remove("hidden");
        $("oauth-disc-open").setAttribute("href", url);
        $("oauth-disc-open").classList.remove("hidden");
        $("oauth-disc-copy").classList.remove("hidden");
        btn.textContent = "重新生成发现链接";
        toast("官方发现链接已生成，请点击「打开发现页」完成登录并复制回调 URL");
      } catch (err) {
        if (!err.unauthorized) {
          $("oauth-error").textContent = err.message;
          $("oauth-error").classList.remove("hidden");
        }
        btn.textContent = "获取官方发现链接";
      } finally {
        btn.disabled = false;
      }
    });
    $("oauth-disc-copy").addEventListener("click", () => {
      copyToClipboard($("oauth-disc-url").value, "发现页链接已复制");
    });
    $("btn-parse-disc").addEventListener("click", () => {
      applyDiscoveryCallback($("oauth-disc-callback").value, false);
    });
    $("oauth-disc-callback").addEventListener("paste", () => {
      setTimeout(() => {
        const val = $("oauth-disc-callback").value;
        if (val && (val.includes("tenant") || val.includes("plato.ai.aws.dev"))) {
          applyDiscoveryCallback(val, true);
        }
      }, 20);
    });
    $("btn-reuse-tenant").addEventListener("click", () => {
      const firstWithHost = ((state.status && state.status.accounts) || []).find((a) => a.tenant_host);
      if (firstWithHost) {
        $("oauth-tenant-input").value = "https://" + firstWithHost.tenant_host;
        toast("已填入池内首个账号的租户地址（仅限同租户/重登原账号）");
      }
    });
    $("oauth-start-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const btn = $("oauth-start-btn");
      btn.disabled = true;
      btn.textContent = "注册 OIDC 中...";
      $("oauth-error").classList.add("hidden");
      $("oauth-warn").classList.add("hidden");
      $("oauth-ok").classList.add("hidden");
      try {
        const payload = {
          tenant_url: $("oauth-tenant-input").value.trim(),
          discovery_callback_url: $("oauth-disc-callback").value.trim(),
          id: $("oauth-id-input").value.trim(),
          proxy_url: $("oauth-proxy-input").value.trim(),
          region: $("oauth-region-input").value.trim(),
          issuer_url: $("oauth-issuer-input").value.trim(),
          scopes: $("oauth-scopes-input").value.trim(),
          callback_port: Number($("oauth-port-input").value) || 18080,
        };
        const res = await apiFetch("/admin/oauth/start", {
          method: "POST",
          body: payload,
        });
        state.oauthSession = res;
        if (res.tenant_url) $("oauth-tenant-input").value = res.tenant_url;
        if (res.region) $("oauth-region-input").value = res.region;
        if (res.issuer_url) $("oauth-issuer-input").value = res.issuer_url;
        $("oauth-auth-url").value = res.auth_url || "";
        $("oauth-open-link").setAttribute("href", res.auth_url || "#");
        $("oauth-redir-preview").textContent = res.redirect_uri || "http://127.0.0.1:18080/oauth/callback";
        const mins = Math.max(1, Math.round((res.expires_in_sec || 600) / 60));
        $("oauth-ttl-hint").textContent = `有效期 ${mins} 分钟`;
        $("oauth-step2").classList.remove("hidden");
        btn.textContent = "重新生成授权链接";
        $("oauth-callback-input").focus();
        toast("OIDC 授权链接已生成，请打开授权页后粘贴回调 URL");
      } catch (err) {
        if (!err.unauthorized) {
          $("oauth-error").textContent = err.message;
          $("oauth-error").classList.remove("hidden");
        }
        btn.textContent = "步骤 2：生成 OIDC 授权链接";
      } finally {
        btn.disabled = false;
      }
    });
    $("oauth-copy-url").addEventListener("click", () => {
      copyToClipboard($("oauth-auth-url").value, "授权链接已复制");
    });
    $("oauth-reset-flow").addEventListener("click", () => {
      resetOAuthFlow();
      $("oauth-start-btn").focus();
    });
    $("oauth-callback-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const rawCallback = $("oauth-callback-input").value.trim();
      if (!rawCallback) return;
      const btn = $("oauth-callback-submit");
      btn.disabled = true;
      btn.textContent = "换取 Token 中...";
      $("oauth-error").classList.add("hidden");
      $("oauth-warn").classList.add("hidden");
      $("oauth-ok").classList.add("hidden");
      try {
        const res = await apiFetch("/admin/oauth/callback", {
          method: "POST",
          body: {
            state: (state.oauthSession && state.oauthSession.state) || "",
            redirect_url: rawCallback,
            tenant_url: $("oauth-tenant-input").value.trim(),
          },
        });
        const acctId = (res.account && res.account.id) || (res.added && res.added[0]) || (res.updated && res.updated[0]) || "新账号";
        state.oauthSession = null;
        await fetchCore(false);
        await fetchLogs(false);
        if (res.usage_ok) {
          $("oauth-ok").textContent = `账号 ${acctId} 登录并热重载成功，已自动拉取初始配额。`;
          $("oauth-ok").classList.remove("hidden");
          toast(`OAuth 登录成功：${acctId}`);
          setTimeout(() => closeOAuthModal(), 900);
        } else {
          $("oauth-warn").textContent = `账号 ${acctId} 已保存，但初始配额探测失败（${res.usage_note || "请检查 tenant_url 是否与该账号匹配或出口代理是否可达"}）。请确认已通过步骤 1 获取该账号专属 tenant_url。`;
          $("oauth-warn").classList.remove("hidden");
          toast(`账号 ${acctId} 已保存，但初始配额探测失败`, true);
        }
      } catch (err) {
        if (!err.unauthorized) {
          $("oauth-error").textContent = err.message;
          $("oauth-error").classList.remove("hidden");
        }
      } finally {
        btn.disabled = false;
        btn.textContent = "提交回调并完成登录";
      }
    });
    $("import-json-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const rawText = $("import-json-input").value.trim();
      if (!rawText) return;
      $("import-error").classList.add("hidden");
      let parsed;
      try {
        parsed = JSON.parse(rawText);
      } catch (parseErr) {
        $("import-error").textContent = "JSON 格式无效：" + parseErr.message;
        $("import-error").classList.remove("hidden");
        return;
      }
      const btn = $("import-submit");
      btn.disabled = true;
      btn.textContent = "导入中...";
      try {
        const res = await apiFetch("/admin/accounts/import", {
          method: "POST",
          body: {
            payload: parsed,
            proxy_url: $("import-proxy-input").value.trim(),
          },
        });
        const addedN = (res.added || []).length;
        const updN = (res.updated || []).length;
        closeOAuthModal();
        toast(`导入成功：新增 ${addedN} 个，更新 ${updN} 个`);
        await fetchCore(false);
        await fetchLogs(false);
      } catch (err) {
        if (!err.unauthorized) {
          $("import-error").textContent = err.message;
          $("import-error").classList.remove("hidden");
        }
      } finally {
        btn.disabled = false;
        btn.textContent = "导入并热重载";
      }
    });

    // Models filters & reset
    $("recent-model-filter").addEventListener("change", renderRecentFullTable);
    $("recent-status-filter").addEventListener("change", renderRecentFullTable);
    $("btn-reset-metrics").addEventListener("click", async () => {
      if (!window.confirm("确认重置当前内存中的请求与模型统计？")) return;
      try {
        await apiFetch("/admin/metrics/reset", { method: "POST" });
        toast("模型统计已重置");
        await fetchCore(false);
      } catch (err) {
        if (!err.unauthorized) toast("重置失败: " + err.message, true);
      }
    });

    // Logs toolbar
    $("log-level-group").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-level]");
      if (!btn) return;
      state.logLevel = btn.getAttribute("data-level");
      $("log-level-group").querySelectorAll(".seg-btn").forEach((x) => x.classList.toggle("active", x === btn));
      renderLogs();
    });
    $("log-tag-filter").addEventListener("change", () => {
      state.logTag = $("log-tag-filter").value;
      renderLogs();
    });
    $("log-search").addEventListener("input", () => {
      state.logSearch = $("log-search").value;
      renderLogs();
    });
    $("btn-logs-pause").addEventListener("click", () => {
      state.logPaused = !state.logPaused;
      $("btn-logs-pause").textContent = state.logPaused ? "继续跟踪" : "暂停跟踪";
    });
    $("btn-logs-copy").addEventListener("click", async () => {
      const lines = getFilteredLogs().map((e) => `${e.time} [${e.level.toUpperCase()}] [${e.tag}] ${e.message}`).join("\n");
      if (!lines) {
        toast("没有可复制的日志");
        return;
      }
      try {
        await navigator.clipboard.writeText(lines);
        toast(`已复制 ${getFilteredLogs().length} 条日志`);
      } catch (_) {
        toast("剪贴板不可用", true);
      }
    });
    $("btn-logs-clear").addEventListener("click", async () => {
      try {
        await apiFetch("/admin/logs/clear", { method: "POST" });
        state.logs = [];
        state.logTotalBuffered = 0;
        renderLogs();
        toast("已清空日志缓冲");
      } catch (err) {
        if (!err.unauthorized) toast("清空失败: " + err.message, true);
      }
    });

    // Escape closes active modal
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Escape") return;
      if (!$("oauth-modal").classList.contains("hidden")) {
        closeOAuthModal();
      } else if (!$("proxy-modal").classList.contains("hidden")) {
        closeProxyModal();
      }
    });
  }

  /* Boot */
  async function boot() {
    initTheme();
    bindEvents();
    try {
      await fetchCore(false);
      await fetchLogs(true);
      startTimers();
    } catch (_) {
      // auth gate shown automatically on 401
    }
  }

  boot();
})();
