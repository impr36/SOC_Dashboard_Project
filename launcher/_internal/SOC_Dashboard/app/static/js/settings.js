/* =========================================
   SETTINGS PAGE — complete rewrite
   - All settings load from /api/settings on page open
   - Save Configuration posts all values back
   - Reset Default calls /api/settings/reset (admin only)
   - User table loads from /api/auth/users (admin only)
   - Password change calls /api/auth/change-password
   - Theme toggle persists to DB and applies instantly
   - Logout clears localStorage and reloads to show login
========================================= */

"use strict";

// ─── state ────────────────────────────────────────────────

let _currentSettings = {};
let _isDirty         = false;

// ─── init ─────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
    _loadSettings();
    _loadPlatformStats();
    _loadUsers();
    _bindButtons();
    _bindPasswordForm();
    _markDirtyOnChange();
});

// ─── auth helpers ─────────────────────────────────────────

function _token() {
    return localStorage.getItem("soc_token") || "";
}

function _authHeaders() {
    return {
        "Content-Type":  "application/json",
        "Authorization": "Bearer " + _token()
    };
}

// ─── toast ────────────────────────────────────────────────

function _toast(msg, type = "success") {
    const existing = document.querySelector(".soc-toast");
    if (existing) existing.remove();

    const t = document.createElement("div");
    t.className = "soc-toast soc-toast-" + type;
    t.textContent = msg;
    document.body.appendChild(t);

    requestAnimationFrame(() => t.classList.add("soc-toast-show"));
    setTimeout(() => {
        t.classList.remove("soc-toast-show");
        setTimeout(() => t.remove(), 400);
    }, 3000);
}

// ─── LOAD settings from API ───────────────────────────────

async function _loadSettings() {
    try {
        const res = await fetch("/api/settings", { headers: _authHeaders() });
        if (!res.ok) throw new Error(await res.text());
        _currentSettings = await res.json();
        _applySettingsToUI(_currentSettings);
        _isDirty = false;
    } catch (err) {
        _toast("Failed to load settings: " + err.message, "error");
    }
}

function _applySettingsToUI(s) {
    _setToggle("toggle-realtime",      s["detection.realtime"]);
    _setToggle("toggle-behavioral",    s["detection.behavioral"]);
    _setToggle("toggle-escalation",    s["detection.auto_escalation"]);
    _setRange ("range-sensitivity",    s["detection.sensitivity"]);
    _setLabel ("label-sensitivity",    s["detection.sensitivity"] + "%");

    _setSelect("select-theme",         s["dashboard.theme"]);
    _setSelect("select-refresh",       String(s["dashboard.refresh_interval"]));
    _setToggle("toggle-compact",       s["dashboard.compact_mode"]);
    _applyTheme(s["dashboard.theme"]);

    _setToggle("toggle-process",       s["hids.process_monitoring"]);
    _setToggle("toggle-registry",      s["hids.registry_monitoring"]);
    _setToggle("toggle-powershell",    s["hids.powershell_detection"]);

    _setToggle("toggle-packet",        s["nids.packet_inspection"]);
    _setToggle("toggle-dns",           s["nids.dns_tunneling"]);
    _setToggle("toggle-exfil",         s["nids.exfiltration"]);

    _setInput ("input-signature",      s["reporting.analyst_signature"]);
    _setSelect("select-report-retain", String(s["reporting.retention_days"]));
    _setToggle("toggle-pdf",           s["reporting.pdf_export"]);

    _setSelect("select-alert-retain",  String(s["storage.alert_retention"]));
    _setToggle("toggle-cleanup",       s["storage.auto_cleanup"]);
}

// ─── UI set helpers ───────────────────────────────────────

function _setToggle(id, val) {
    const el = document.getElementById(id);
    if (el) el.checked = !!val;
}

function _setSelect(id, val) {
    const el = document.getElementById(id);
    if (!el) return;
    for (const opt of el.options) {
        if (opt.value === String(val)) { el.value = String(val); return; }
    }
}

function _setRange(id, val) {
    const el = document.getElementById(id);
    if (el) el.value = val;
}

function _setLabel(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

function _setInput(id, val) {
    const el = document.getElementById(id);
    if (el) el.value = val || "";
}

// ─── READ UI state ────────────────────────────────────────

function _readSettingsFromUI() {
    const g = (id) => document.getElementById(id);
    return {
        "detection.realtime":          g("toggle-realtime")   ?.checked ?? true,
        "detection.behavioral":        g("toggle-behavioral") ?.checked ?? true,
        "detection.auto_escalation":   g("toggle-escalation") ?.checked ?? false,
        "detection.sensitivity":       Number(g("range-sensitivity")?.value ?? 78),
        "dashboard.theme":             g("select-theme")?.value ?? "dark",
        "dashboard.refresh_interval":  Number(g("select-refresh")?.value ?? 15),
        "dashboard.compact_mode":      g("toggle-compact")?.checked ?? false,
        "hids.process_monitoring":     g("toggle-process")   ?.checked ?? true,
        "hids.registry_monitoring":    g("toggle-registry")  ?.checked ?? true,
        "hids.powershell_detection":   g("toggle-powershell")?.checked ?? true,
        "nids.packet_inspection":      g("toggle-packet")?.checked ?? true,
        "nids.dns_tunneling":          g("toggle-dns")  ?.checked ?? true,
        "nids.exfiltration":           g("toggle-exfil")?.checked ?? true,
        "reporting.analyst_signature": g("input-signature")?.value?.trim() ?? "",
        "reporting.retention_days":    Number(g("select-report-retain")?.value ?? 30),
        "reporting.pdf_export":        g("toggle-pdf")?.checked ?? true,
        "storage.alert_retention":     Number(g("select-alert-retain")?.value ?? 30),
        "storage.auto_cleanup":        g("toggle-cleanup")?.checked ?? false,
    };
}

// ─── SAVE settings ────────────────────────────────────────

async function saveSettings() {
    const btn = document.getElementById("btn-save");
    if (btn) { btn.disabled = true; btn.textContent = "Saving..."; }
    try {
        const settings = _readSettingsFromUI();
        const res = await fetch("/api/settings", {
            method:  "POST",
            headers: _authHeaders(),
            body:    JSON.stringify({ settings })
        });
        if (!res.ok) throw new Error(await res.text());
        _currentSettings = settings;
        _isDirty = false;
        _applyTheme(settings["dashboard.theme"]);
        // Notify dashboard of new refresh interval
        localStorage.setItem(
            "soc_refresh_interval",
            String(settings["dashboard.refresh_interval"])
        );
        _toast("Settings saved successfully");
    } catch (err) {
        _toast("Save failed: " + err.message, "error");
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = "Save Configuration"; }
    }
}

// ─── RESET to defaults ────────────────────────────────────

async function resetSettings() {
    if (!confirm("Reset ALL settings to factory defaults?\n\nThis cannot be undone.")) return;
    const btn = document.getElementById("btn-reset");
    if (btn) { btn.disabled = true; btn.textContent = "Resetting..."; }
    try {
        const res = await fetch("/api/settings/reset", {
            method: "POST", headers: _authHeaders()
        });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || "Reset failed");
        }
        await _loadSettings();
        _toast("Settings reset to defaults");
    } catch (err) {
        _toast(err.message, "error");
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = "Reset Default"; }
    }
}

// ─── THEME ────────────────────────────────────────────────

function _applyTheme(theme) {
    if (theme === "light") {
        document.body.classList.add("light-mode");
    } else {
        document.body.classList.remove("light-mode");
    }
    // Swap icon paths used in sidebar/header
    document.querySelectorAll(".theme-icon").forEach(icon => {
        if (theme === "light") {
            icon.src = icon.src.replace("icons-W", "icons-B");
        } else {
            icon.src = icon.src.replace("icons-B", "icons-W");
        }
    });
    localStorage.setItem("soc_theme", theme);
}

// ─── PLATFORM STATS ───────────────────────────────────────

async function _loadPlatformStats() {
    try {
        const res = await fetch("/api/settings/platform-stats", {
            headers: _authHeaders()
        });
        if (!res.ok) return;
        const d = await res.json();
        _setStat("stat-alerts",  d.total_alerts);
        _setStat("stat-rules",   d.active_rules);
        _setStat("stat-users",   d.active_users);
        _setStat("stat-reports", d.total_reports);
    } catch (_) { /* non-critical */ }
}

function _setStat(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = (val ?? "—").toLocaleString?.() ?? val;
}

// ─── USER TABLE  (uses existing /api/auth/users) ──────────

async function _loadUsers() {
    const role    = localStorage.getItem("soc_role");
    const section = document.getElementById("admin-management-section");
    const tbody   = document.getElementById("admin-table-body");
    if (!tbody) return;

    // Hide entire section for non-admins
    if (role !== "admin") {
        if (section) section.style.display = "none";
        return;
    }

    try {
        const res = await fetch("/api/auth/users", { headers: _authHeaders() });
        if (!res.ok) throw new Error(await res.text());
        const users = await res.json();   // array of user objects
        _renderUserTable(users);
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" style="color:var(--danger)">
            Failed to load users: ${err.message}</td></tr>`;
    }
}

function _renderUserTable(users) {
    const tbody = document.getElementById("admin-table-body");
    if (!tbody) return;

    if (!users.length) {
        tbody.innerHTML = `<tr><td colspan="5" style="opacity:.5">No users found</td></tr>`;
        return;
    }

    const roleLabel = { admin: "Super Admin", analyst: "SOC Analyst", viewer: "Viewer" };
    const me = localStorage.getItem("soc_username") || "";

    tbody.innerHTML = users.map(u => {
        const isActive     = !!u.is_active;
        const statusClass  = isActive ? "badge-active" : "badge-inactive";
        const statusLabel  = isActive ? "Active" : "Inactive";
        const toggleLabel  = isActive ? "Deactivate" : "Activate";
        const isMe         = u.username === me;

        // Format last_login ISO string → readable
        let lastLogin = u.last_login || "Never";
        if (lastLogin && lastLogin !== "Never") {
            try {
                const dt = new Date(lastLogin);
                lastLogin = dt.toLocaleString();
            } catch (_) {}
        }

        return `
        <tr>
            <td>
                ${_esc(u.display_name || u.username)}
                <br><small style="opacity:.6">${_esc(u.username)}</small>
            </td>
            <td>${_esc(roleLabel[u.role] || u.role)}</td>
            <td>${_esc(lastLogin)}</td>
            <td><span class="user-status-badge ${statusClass}">${statusLabel}</span></td>
            <td>
                ${isMe
                    ? '<span style="opacity:.4">—</span>'
                    : `<button class="user-toggle-btn"
                           onclick="toggleUserActive('${_esc(u.username)}', ${!isActive})">
                           ${toggleLabel}
                       </button>`
                }
            </td>
        </tr>`;
    }).join("");
}

function _esc(s) {
    return String(s ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

async function toggleUserActive(username, active) {
    try {
        const res = await fetch("/api/settings/users/toggle", {
            method:  "POST",
            headers: _authHeaders(),
            body:    JSON.stringify({ username, active })
        });
        if (!res.ok) throw new Error((await res.json()).detail);
        await _loadUsers();
        _toast(`User "${username}" ${active ? "activated" : "deactivated"}`);
    } catch (err) {
        _toast(err.message, "error");
    }
}

// ─── PASSWORD CHANGE  (calls existing /api/auth/change-password) ──

function _bindPasswordForm() {
    const btn = document.getElementById("btn-change-password");
    if (!btn) return;

    btn.addEventListener("click", async () => {
        const currentPw = document.getElementById("input-current-pw")?.value ?? "";
        const newPw     = document.getElementById("input-new-pw")?.value ?? "";
        const confirmPw = document.getElementById("input-confirm-pw")?.value ?? "";

        if (!currentPw || !newPw || !confirmPw) {
            _toast("All password fields are required", "error"); return;
        }
        if (newPw !== confirmPw) {
            _toast("New passwords do not match", "error"); return;
        }
        if (newPw.length < 8) {
            _toast("Password must be at least 8 characters", "error"); return;
        }

        btn.disabled = true; btn.textContent = "Updating...";
        try {
            const res = await fetch("/api/auth/change-password", {
                method:  "POST",
                headers: _authHeaders(),
                body:    JSON.stringify({
                    current_password: currentPw,
                    new_password:     newPw
                })
            });
            if (!res.ok) throw new Error((await res.json()).detail);
            document.getElementById("input-current-pw").value = "";
            document.getElementById("input-new-pw").value     = "";
            document.getElementById("input-confirm-pw").value = "";
            _toast("Password updated successfully");
        } catch (err) {
            _toast(err.message, "error");
        } finally {
            btn.disabled = false; btn.textContent = "Update Password";
        }
    });
}

// ─── DIRTY FLAG ───────────────────────────────────────────

function _markDirtyOnChange() {
    const ids = [
        "toggle-realtime","toggle-behavioral","toggle-escalation",
        "range-sensitivity","select-theme","select-refresh",
        "toggle-compact","toggle-process","toggle-registry",
        "toggle-powershell","toggle-packet","toggle-dns","toggle-exfil",
        "input-signature","select-report-retain","toggle-pdf",
        "select-alert-retain","toggle-cleanup"
    ];
    ids.forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        el.addEventListener("change", () => {
            _isDirty = true;
            if (id === "select-theme") _applyTheme(el.value);
            if (id === "range-sensitivity") _setLabel("label-sensitivity", el.value + "%");
        });
        if (el.type === "range") {
            el.addEventListener("input", () =>
                _setLabel("label-sensitivity", el.value + "%")
            );
        }
    });

    window.addEventListener("beforeunload", (e) => {
        if (_isDirty) { e.preventDefault(); e.returnValue = ""; }
    });
}

// ─── BUTTON BINDINGS ─────────────────────────────────────

function _bindButtons() {
    document.getElementById("btn-save")  ?.addEventListener("click", saveSettings);
    document.getElementById("btn-reset") ?.addEventListener("click", resetSettings);
    document.getElementById("btn-logout")?.addEventListener("click", logoutUser);
}

// ─── LOGOUT ───────────────────────────────────────────────

function logoutUser() {
    localStorage.removeItem("soc_token");
    localStorage.removeItem("soc_role");
    localStorage.removeItem("soc_username");
    localStorage.removeItem("soc_displayname");
    localStorage.removeItem("soc_theme");
    localStorage.removeItem("soc_refresh_interval");

    // Try to close the tab; browser may block it if not script-opened
    window.close();
    // Fallback — reload triggers login.js which shows login overlay
    setTimeout(() => { window.location.reload(); }, 150);
}