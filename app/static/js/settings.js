/* =========================================
   SETTINGS PAGE 
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
    // Token system removed. Auth handled by Tkinter launcher.
    return "";
}

function _authHeaders() {
    // Authorization removed — all API endpoints are open on localhost.
    return {
        "Content-Type": "application/json"
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
        _setStat("stat-total-alerts",  d.total_alerts);
        _setStat("stat-active-rules",   d.active_rules);
        _setStat("stat-active-users",   d.active_users);
        _setStat("stat-total-reports",  d.total_reports);
    } catch (_) { /* non-critical */ }
}

function _setStat(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = (val ?? "—").toLocaleString?.() ?? val;
}

// ─── USER TABLE  (uses existing /api/auth/users) ──────────

async function _loadUsers() {
    // Default to admin since auth is handled by the Tkinter launcher.
    // Web-based role restriction would need JWT — not applicable here.
    const role    = localStorage.getItem("soc_role") || "admin";
    const section = document.getElementById("admin-management-section");
    const tbody   = document.getElementById("admin-table-body");
    if (!tbody) return;

    // Always show section (Tkinter-launched = admin by default)
    if (section) section.style.display = "block";

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

async function logoutUser() {
    if(!confirm("Log out of the SOC Dashboard?\nThe login window will reappear.")) return

    // Clear local session
    ["soc_token","soc_role","soc_username","soc_display_name",
     "soc_displayname","soc_refresh_interval"].forEach(k => localStorage.removeItem(k))

    // Notify the server — this signals the Tkinter launcher
    // to stop the server and show the login window again
    try {
        await fetch("/api/auth/logout", { method: "POST" })
    } catch(_) {}

    // Show a message then close the browser tab
    document.body.innerHTML = `
        <div style="display:flex;flex-direction:column;align-items:center;
            justify-content:center;height:100vh;background:#031b29;color:#fff;
            font-family:'Segoe UI',sans-serif;gap:20px">
            <div style="font-size:48px">🔒</div>
            <div style="font-size:22px;font-weight:700">Logged Out Successfully</div>
            <div style="font-size:14px;color:#5a8a9f">
                The login window will reappear shortly.<br>
                You can close this browser tab.
            </div>
        </div>`

    // Close tab after 2 seconds
    setTimeout(() => { window.close() }, 2000)
}

// =========================================
// THEME TOGGLE — Settings Page
// Uses existing _applyTheme() from this file
// =========================================

function settingsToggleTheme(){
    const isLight = document.body.classList.contains("light-mode")
    const newTheme = isLight ? "dark" : "light"
    _applyTheme(newTheme)
    localStorage.setItem("soc_theme", newTheme)
    _syncThemeUI()
    if(typeof updateChartsTheme === "function") updateChartsTheme()
}

function _syncThemeUI(){
    const isLight = document.body.classList.contains("light-mode")

    // Checkbox toggle
    const chk = document.getElementById("themeToggleCheck")
    if(chk) chk.checked = isLight

    // Label
    const lbl = document.getElementById("themeLabel")
    if(lbl) lbl.textContent = isLight ? "☀️ Light Mode" : "🌙 Dark Mode"

    // Preview card borders
    const dark  = document.getElementById("themePreviewDark")
    const light = document.getElementById("themePreviewLight")
    if(dark)  dark.style.borderColor  = isLight ? "#1e4d6b" : "#2f6bff"
    if(light) light.style.borderColor = isLight ? "#2f6bff" : "#dde3ea"
}

// =========================================
// ADD NEW USER
// =========================================

async function createNewUser(){
    const username    = document.getElementById("new-username")?.value?.trim()
    const displayName = document.getElementById("new-display-name")?.value?.trim()
    const password    = document.getElementById("new-password")?.value
    const role        = document.getElementById("new-role")?.value
    const msgEl       = document.getElementById("add-user-msg")

    if(!username){
        _showAddUserMsg("❌ Username is required", "error"); return
    }
    if(!password || password.length < 8){
        _showAddUserMsg("❌ Password must be at least 8 characters", "error"); return
    }
    if(!/^[a-zA-Z0-9_.-]+$/.test(username)){
        _showAddUserMsg("❌ Username: only letters, numbers, _ . - allowed", "error"); return
    }

    try{
        const resp = await fetch("/api/auth/users", {
            method:  "POST",
            headers: {"Content-Type":"application/json", ..._authHeaders()},
            body:    JSON.stringify({
                username,
                password,
                role,
                display_name: displayName || username
            })
        })
        const data = await resp.json()
        if(resp.ok){
            _showAddUserMsg(`✅ User "@${username}" created as ${role.toUpperCase()}`, "success")
            document.getElementById("new-username").value      = ""
            document.getElementById("new-display-name").value = ""
            document.getElementById("new-password").value     = ""
            document.getElementById("new-role").value         = "analyst"
            await _loadUsers()
        } else {
            _showAddUserMsg(`❌ ${data.detail || "Failed to create user"}`, "error")
        }
    }catch(e){
        _showAddUserMsg("❌ Network error: " + e.message, "error")
    }
}

function _showAddUserMsg(msg, type){
    const el = document.getElementById("add-user-msg")
    if(!el) return
    el.textContent = msg
    el.style.display = "block"
    el.style.color = type === "error" ? "#ff3b30" : "#55d800"
    el.style.background = type === "error" ? "rgba(255,59,48,0.1)" : "rgba(85,216,0,0.1)"
    clearTimeout(el._t)
    el._t = setTimeout(() => { el.style.display = "none" }, 5000)
}

// Load user table alias (called from HTML onclick)
function loadUserTable(){ _loadUsers() }

// Sync theme on settings page open
setTimeout(() => {
    _syncThemeUI()
    _loadUsers()
    if(typeof _loadPlatformStats === "function") _loadPlatformStats()
}, 300)