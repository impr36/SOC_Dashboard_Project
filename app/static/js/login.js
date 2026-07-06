/* =========================================
   SOC DASHBOARD AUTH — login.js
   - Shows login overlay on page load
   - Validates JWT token with server
   - Handles login, logout, session expiry
   - Sets soc_token, soc_role, soc_username in localStorage
   - Updates header with logged-in user info
   - Logout: clears session + closes browser tab
   ========================================= */

// =========================================
// SESSION HELPERS
// =========================================

function _getToken(){    return localStorage.getItem("soc_token")    || "" }
function _getRole(){     return localStorage.getItem("soc_role")     || "" }
function _getUsername(){ return localStorage.getItem("soc_username") || "" }

function _saveSession(token, role, username, displayName){
    localStorage.setItem("soc_token",       token)
    localStorage.setItem("soc_role",        role)
    localStorage.setItem("soc_username",    username)
    localStorage.setItem("soc_displayname", displayName || username)
}

function _clearSession(){
    localStorage.removeItem("soc_token")
    localStorage.removeItem("soc_role")
    localStorage.removeItem("soc_username")
    localStorage.removeItem("soc_displayname")
}

// =========================================
// AUTH HEADER for API calls
// =========================================

function _authHeader(){
    const token = _getToken()
    return token ? { "Authorization": `Bearer ${token}` } : {}
}

// =========================================
// VALIDATE TOKEN WITH SERVER
// =========================================

async function _validateSession(){
    const token = _getToken()
    if(!token) return false

    try{
        const resp = await fetch("/api/auth/validate", {
            headers: { "Authorization": `Bearer ${token}` }
        })
        const data = await resp.json()
        if(data.valid){
            // Refresh display name from server in case role changed
            localStorage.setItem("soc_role",     data.role)
            localStorage.setItem("soc_username",  data.username)
            return true
        }
        return false
    }catch(e){
        // Network error — allow offline use if token exists
        return !!token
    }
}

// =========================================
// LOGIN OVERLAY
// =========================================

function _showLoginOverlay(){
    // Hide all dashboard content
    const content = document.querySelector(".content-area")
    const header  = document.querySelector(".header")
    const sidebar = document.getElementById("sidebar")
    if(content) content.style.display = "none"
    if(header)  header.style.display  = "none"
    if(sidebar) sidebar.style.display = "none"

    let overlay = document.getElementById("loginOverlay")
    if(!overlay){
        overlay = document.createElement("div")
        overlay.id = "loginOverlay"
        overlay.style.cssText = `
            position:fixed;inset:0;background:#060f1a;z-index:99999;
            display:flex;align-items:stretch;justify-content:center`
        document.body.appendChild(overlay)
    }

    overlay.innerHTML = `
        <!-- LEFT PANEL: branding -->
        <div style="flex:1;background:linear-gradient(160deg,#0a1e2e 0%,#0d2a42 100%);
            display:flex;flex-direction:column;align-items:center;justify-content:center;
            padding:60px 48px;min-width:320px;max-width:480px;
            border-right:1px solid #1e4d6b">

            <div style="display:flex;align-items:center;gap:16px;margin-bottom:48px">
                <div style="background:#2f6bff22;border:2px solid #2f6bff;border-radius:12px;
                    padding:10px 14px;font-size:28px">🛡️</div>
                <div>
                    <div style="font-size:26px;font-weight:900;color:#fff">SOC Simulator</div>
                    <div style="font-size:12px;color:#5a8a9f;margin-top:2px">
                        Host + Network IDS Platform
                    </div>
                </div>
            </div>

            <div style="width:100%;max-width:320px">
                ${["Real-Time Threat Detection","HIDS + NIDS Monitoring",
                   "MITRE ATT&CK Mapping","Threat Hunting Engine",
                   "Digital Forensics Support"].map(f=>`
                    <div style="display:flex;align-items:center;gap:12px;
                        margin-bottom:18px;color:#a0c8e8;font-size:14px">
                        <span style="color:#2f6bff;font-size:18px">✓</span> ${f}
                    </div>`).join("")}
            </div>

        </div>

        <!-- RIGHT PANEL: login form -->
        <div style="flex:1;display:flex;align-items:center;justify-content:center;
            padding:60px 48px;max-width:480px">
            <div style="width:100%;max-width:380px">

                <div style="font-size:24px;font-weight:800;color:#fff;margin-bottom:6px">
                    Admin Login
                </div>
                <div style="font-size:13px;color:#5a8a9f;margin-bottom:32px">
                    Sign in to access the SOC Dashboard
                </div>

                <div id="loginError" style="display:none;background:#2a0a0a;
                    border:1px solid #ff3b30;border-radius:8px;padding:10px 14px;
                    color:#ff6b6b;font-size:13px;margin-bottom:16px"></div>

                <div style="margin-bottom:18px">
                    <label style="font-size:12px;color:#5a8a9f;display:block;margin-bottom:6px">
                        Username
                    </label>
                    <input id="loginUsername" type="text"
                        placeholder="Enter username"
                        autocomplete="username"
                        style="${_loginInputStyle()}"
                        onkeydown="if(event.key==='Enter') _attemptLogin()">
                </div>

                <div style="margin-bottom:26px">
                    <label style="font-size:12px;color:#5a8a9f;display:block;margin-bottom:6px">
                        Password
                    </label>
                    <input id="loginPassword" type="password"
                        placeholder="Enter password"
                        autocomplete="current-password"
                        style="${_loginInputStyle()}"
                        onkeydown="if(event.key==='Enter') _attemptLogin()">
                </div>

                <button onclick="_attemptLogin()"
                    id="loginBtn"
                    style="width:100%;background:#2f6bff;color:#fff;border:none;
                    border-radius:10px;padding:14px;font-size:15px;font-weight:700;
                    cursor:pointer;transition:background 0.2s"
                    onmouseover="this.style.background='#1a56e8'"
                    onmouseout="this.style.background='#2f6bff'">
                    LOGIN
                </button>

                <div style="text-align:center;margin-top:20px;font-size:12px;color:#3a6a8f">
                    Contact your administrator for credentials
                </div>

            </div>
        </div>
    `
    overlay.style.display = "flex"

    // Focus username input
    setTimeout(()=>{
        document.getElementById("loginUsername")?.focus()
    }, 100)
}

function _loginInputStyle(){
    return `width:100%;background:#0a1520;border:1.5px solid #1e4d6b;border-radius:10px;
        padding:12px 16px;color:#fff;font-size:14px;box-sizing:border-box;outline:none;
        transition:border-color 0.2s`
}

function _hideLoginOverlay(){
    const overlay = document.getElementById("loginOverlay")
    if(overlay) overlay.style.display = "none"

    // Show dashboard content
    const content = document.querySelector(".content-area")
    const header  = document.querySelector(".header")
    const sidebar = document.getElementById("sidebar")
    if(content) content.style.display = ""
    if(header)  header.style.display  = ""
    if(sidebar) sidebar.style.display = ""
}

// =========================================
// ATTEMPT LOGIN
// =========================================

async function _attemptLogin(){
    const username = document.getElementById("loginUsername")?.value?.trim()
    const password = document.getElementById("loginPassword")?.value

    if(!username || !password){
        _showLoginError("Please enter both username and password")
        return
    }

    const btn = document.getElementById("loginBtn")
    if(btn){ btn.disabled=true; btn.textContent="Signing in..." }

    try{
        const resp = await fetch("/api/auth/login", {
            method:  "POST",
            headers: {"Content-Type": "application/json"},
            body:    JSON.stringify({username, password})
        })
        const data = await resp.json()

        if(!resp.ok){
            _showLoginError(data.detail || "Login failed")
            return
        }

        // Save session
        _saveSession(data.token, data.role, data.username, data.display_name)

        // Hide login, show dashboard
        _hideLoginOverlay()
        _updateHeaderUser(data.display_name || data.username, data.role)

        // Apply role-based visibility across the dashboard
        _applyRoleVisibility(data.role)

        // Trigger dashboard data load
        if(typeof loadDashboardData === "function") await loadDashboardData()
        if(typeof loadSystemInfo    === "function") loadSystemInfo()

        console.log(`[SOC] Logged in as ${data.username} (${data.role})`)

    }catch(e){
        _showLoginError("Unable to connect to server. Is the backend running?")
        console.error("Login error:", e)
    }finally{
        if(btn){ btn.disabled=false; btn.textContent="LOGIN" }
    }
}

function _showLoginError(msg){
    const el = document.getElementById("loginError")
    if(el){ el.textContent=msg; el.style.display="block" }
}

// =========================================
// LOGOUT
// =========================================

function logout(){
    _clearSession()
    // Close the browser tab as required
    window.close()
    // Fallback: if window.close() is blocked (some browsers), redirect to login
    setTimeout(()=>{
        window.location.href = "/dashboard"
    }, 300)
}

// =========================================
// UPDATE HEADER WITH LOGGED-IN USER
// =========================================

function _updateHeaderUser(displayName, role){
    // Update the signature/username display in the header
    const sigEl = document.getElementById("userSignature")
    if(sigEl) sigEl.textContent = displayName

    // Update role badge if it exists
    const roleEl = document.getElementById("userRoleBadge")
    if(roleEl){
        const colours = {admin:"#ff3b30", analyst:"#2f6bff", viewer:"#55d800"}
        roleEl.textContent  = role.toUpperCase()
        roleEl.style.color  = colours[role] || "#888"
    }

    // Update the header tooltip
    const headerUser = document.getElementById("headerUsername")
    if(headerUser) headerUser.textContent = displayName
}

// =========================================
// ROLE-BASED VISIBILITY
// =========================================

function _applyRoleVisibility(role){
    const isAdmin   = role === "admin"
    const isViewer  = role === "viewer"

    // .admin-only elements: Add Rule, Delete Rule, Edit buttons
    document.querySelectorAll(".admin-only").forEach(el=>{
        el.style.display = isAdmin ? "" : "none"
    })

    // .analyst-plus elements: status dropdowns, upload report button
    document.querySelectorAll(".analyst-plus").forEach(el=>{
        el.style.display = (isAdmin || role === "analyst") ? "" : "none"
    })

    // .viewer-hide elements: hidden for viewers
    document.querySelectorAll(".viewer-hide").forEach(el=>{
        el.style.display = isViewer ? "none" : ""
    })
}

// =========================================
// SESSION EXPIRY CHECK (periodic)
// =========================================

async function _checkSessionValidity(){
    const token = _getToken()
    if(!token) return

    try{
        const resp = await fetch("/api/auth/validate", {
            headers: { "Authorization": `Bearer ${token}` }
        })
        const data = await resp.json()
        if(!data.valid){
            _clearSession()
            _showLoginOverlay()
            alert("Your session has expired. Please log in again.")
        }
    }catch(e){
        // Network issue — don't force logout
    }
}

// =========================================
// PAGE LOAD INIT
// =========================================

document.addEventListener("DOMContentLoaded", async()=>{
    const isValid = await _validateSession()

    if(!isValid){
        _showLoginOverlay()
    }else{
        _hideLoginOverlay()
        const username    = _getUsername()
        const displayName = localStorage.getItem("soc_displayname") || username
        const role        = _getRole()
        _updateHeaderUser(displayName, role)
        _applyRoleVisibility(role)
    }

    // Check session every 5 minutes
    setInterval(_checkSessionValidity, 5 * 60 * 1000)
})