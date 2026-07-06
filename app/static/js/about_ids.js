/* =========================================
   ABOUT IDS PAGE
   - Loads live platform stats from API
   - Animates pipeline steps on scroll
   - Renders live MITRE tactic distribution
   - Populates version and DB info
========================================= */

"use strict";

document.addEventListener("DOMContentLoaded", () => {

    _loadLiveStats();
    _initScrollAnimations();
    _initPipelineHover();
});

// ─── helpers ──────────────────────────────────────────────

function _token() {
    return localStorage.getItem("soc_token") || "";
}

function _authHeaders() {
    return {
        "Content-Type":  "application/json",
        "Authorization": "Bearer " + _token()
    };
}

// ─── LIVE STATS ───────────────────────────────────────────

async function _loadLiveStats() {
    try {
        const [statsRes, chartRes] = await Promise.all([
            fetch("/api/settings/platform-stats", { headers: _authHeaders() }),
            fetch("/api/chart-data",               { headers: _authHeaders() })
        ]);

        if (statsRes.ok) {
            const s = await statsRes.json();
            _setStat("about-stat-alerts",  _fmt(s.total_alerts));
            _setStat("about-stat-rules",   _fmt(s.active_rules));
            _setStat("about-stat-reports", _fmt(s.total_reports));
            _setStat("about-stat-users",   _fmt(s.active_users));
        }

        if (chartRes.ok) {
            const c = await chartRes.json();

            // Severity breakdown
            const sev = c.severity_counts || {};
            _setStat("about-sev-critical", _fmt(sev.CRITICAL || 0));
            _setStat("about-sev-high",     _fmt(sev.HIGH     || 0));
            _setStat("about-sev-medium",   _fmt(sev.MEDIUM   || 0));
            _setStat("about-sev-low",      _fmt(sev.LOW      || 0));

            // MITRE tactic bars
            const cats = c.category_counts || {};
            _renderTacticBars(cats);
        }

    } catch (_) {
        // Non-critical — stats just stay as "—"
    }
}

function _setStat(id, val) {
    const el = document.getElementById(id);
    if (el) {
        _animateCounter(el, val);
    }
}

function _fmt(n) {
    if (n === undefined || n === null || n === "—") return "—";
    return Number(n).toLocaleString();
}

// Animate a number counting up from 0
function _animateCounter(el, target) {
    if (target === "—") { el.textContent = "—"; return; }
    const end = parseInt(String(target).replace(/,/g, ""), 10);
    if (isNaN(end)) { el.textContent = target; return; }

    const duration = 800;
    const start    = performance.now();
    const from     = 0;

    function step(now) {
        const progress = Math.min((now - start) / duration, 1);
        const ease     = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        el.textContent = Math.round(from + (end - from) * ease).toLocaleString();
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

// ─── MITRE TACTIC BARS ────────────────────────────────────

function _renderTacticBars(cats) {
    const container = document.getElementById("about-tactic-bars");
    if (!container) return;

    const entries = Object.entries(cats)
        .filter(([, v]) => v > 0)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 8);

    if (!entries.length) {
        container.innerHTML = `<p style="opacity:.5">No alert data yet — run a scan first.</p>`;
        return;
    }

    const max = entries[0][1];

    container.innerHTML = entries.map(([tactic, count]) => {
        const pct = Math.round((count / max) * 100);
        return `
        <div class="tactic-bar-row">
            <span class="tactic-bar-label">${_esc(tactic)}</span>
            <div class="tactic-bar-track">
                <div
                    class="tactic-bar-fill"
                    style="width:0%"
                    data-target="${pct}"
                ></div>
            </div>
            <span class="tactic-bar-count">${count.toLocaleString()}</span>
        </div>`;
    }).join("");

    // Animate bars in after a brief delay
    requestAnimationFrame(() => {
        container.querySelectorAll(".tactic-bar-fill").forEach(bar => {
            setTimeout(() => {
                bar.style.transition = "width 0.8s cubic-bezier(.4,0,.2,1)";
                bar.style.width      = bar.dataset.target + "%";
            }, 100);
        });
    });
}

function _esc(s) {
    return String(s ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

// ─── SCROLL ANIMATIONS ────────────────────────────────────

function _initScrollAnimations() {
    const targets = document.querySelectorAll(
        ".about-section, .overview-card, .feature-card, " +
        ".comparison-card, .pipeline-box, .attack-step"
    );

    if (!("IntersectionObserver" in window)) {
        targets.forEach(el => el.classList.add("about-visible"));
        return;
    }

    const obs = new IntersectionObserver((entries) => {
        entries.forEach(e => {
            if (e.isIntersecting) {
                e.target.classList.add("about-visible");
                obs.unobserve(e.target);
            }
        });
    }, { threshold: 0.12 });

    targets.forEach(el => {
        el.classList.add("about-hidden");
        obs.observe(el);
    });
}

// ─── PIPELINE HOVER TOOLTIP ───────────────────────────────

const PIPELINE_TIPS = {
    "System Logs":            "Raw Windows Event Logs, Sysmon, network packet captures, and firewall logs are ingested as the data source.",
    "Event Normalization":    "Logs are parsed and normalized into a unified schema — timestamp, source, event type, severity, and raw data.",
    "Detection Rule Matching":"Each normalized event is tested against all active HIDS and NIDS rules stored in the rules table.",
    "Behavioral Correlation": "Matched events within a time window are correlated by process chain, IP, user, and attack pattern.",
    "Generate Incidents":     "Correlated clusters become structured incident records with severity, MITRE tactic, and event count.",
    "Incident Grouping":      "Related incidents across HIDS and NIDS are grouped into a unified attack timeline.",
    "SOC Dashboard Update":   "All severity counts, charts, and alert queues are refreshed in the dashboard UI.",
    "Store Results":          "Final alerts and incidents are written to the SQLite database for investigation and reporting.",
    // Analyst workflow
    "Alert Detection":        "New alerts appear in the Dashboard alert queue sorted by severity.",
    "Incident Correlation":   "Analyst opens HIDS or NIDS page to review grouped incidents and expand the event chain.",
    "Attack Investigation":   "Analyst examines the attack timeline, MITRE mapping, and raw event details.",
    "Threat Containment":     "Analyst updates incident status and documents containment actions in the report.",
    "Incident Reporting":     "Analyst submits a structured report that is saved to the Reports page and case database.",
};

function _initPipelineHover() {
    const tooltip = document.createElement("div");
    tooltip.id    = "pipeline-tooltip";
    tooltip.style.cssText = `
        position:fixed; z-index:9999; max-width:260px;
        background:var(--clr-surface,#1e2430);
        color:var(--clr-text,#e0e6f0);
        border:1px solid var(--clr-border,#2a3347);
        border-radius:8px; padding:10px 14px;
        font-size:12px; line-height:1.5;
        box-shadow:0 8px 24px rgba(0,0,0,.4);
        pointer-events:none; opacity:0;
        transition:opacity .15s;
    `;
    document.body.appendChild(tooltip);

    document.querySelectorAll(".pipeline-box, .attack-step").forEach(box => {
        const label = box.textContent.trim();
        const tip   = PIPELINE_TIPS[label];
        if (!tip) return;

        box.style.cursor = "help";
        box.setAttribute("title", "");  // suppress native tooltip

        box.addEventListener("mouseenter", (e) => {
            tooltip.textContent = tip;
            tooltip.style.opacity = "1";
            _positionTooltip(tooltip, e);
        });

        box.addEventListener("mousemove", (e) => {
            _positionTooltip(tooltip, e);
        });

        box.addEventListener("mouseleave", () => {
            tooltip.style.opacity = "0";
        });
    });
}

function _positionTooltip(tip, e) {
    const x = e.clientX + 14;
    const y = e.clientY - 10;
    const w = tip.offsetWidth  || 260;
    const h = tip.offsetHeight || 80;
    tip.style.left = (x + w > window.innerWidth  ? x - w - 28 : x) + "px";
    tip.style.top  = (y + h > window.innerHeight ? y - h      : y) + "px";
}