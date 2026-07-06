/* =========================================
   DETECTION RULES — rules.js
   Phase 4: Full functional rewrite
   - Load HIDS / NIDS rules from DB
   - Real-time search across all fields
   - Sort by Event ID / Name / Severity (asc/desc)
   - Admin check: Add/Delete/Edit shown only to admin
   - Add Rule modal with full form + validation
   - Edit Rule modal (pre-filled with existing data)
   - Delete Rule with confirmation dialog
   - All mutations send X-User-Role header for server-side guard
   - Rule count badge per tab
   - Empty state when no rules
   ========================================= */

let _currentRuleType = "HIDS"
let _allRules = []          // master copy for client-side search/sort
let _isAdmin = false        // set from localStorage after login

// =========================================
// ADMIN CHECK
// Read role from localStorage (set on login in Phase 5).
// Falls back to false if not logged in yet.
// =========================================

function _checkAdminRole(){
    const role = localStorage.getItem("soc_role") || ""
    _isAdmin = role.toLowerCase() === "admin"
    _applyAdminVisibility()
}

function _applyAdminVisibility(){
    document.querySelectorAll(".admin-only").forEach(el=>{
        el.style.display = _isAdmin ? "" : "none"
    })
}

// =========================================
// LOAD RULES
// =========================================

async function loadRules(type){
    if(type) _currentRuleType = type.toUpperCase()

    const tbody = document.getElementById("rulesTableBody")
    if(!tbody) return

    try{
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;
            padding:30px;color:#5a8a9f">Loading rules...</td></tr>`

        const resp = await fetch(`/api/rules/${_currentRuleType}`)
        if(!resp.ok) throw new Error(`HTTP ${resp.status}`)
        _allRules = await resp.json()

        // Update tab count badge
        _updateRuleCount(_currentRuleType, _allRules.length)

        _renderRules(_allRules)

    }catch(e){
        console.error("loadRules error:", e)
        const tbody = document.getElementById("rulesTableBody")
        if(tbody) tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;
            padding:30px;color:#ff6b6b">Failed to load rules. Check server.</td></tr>`
    }
}

function _updateRuleCount(type, count){
    const tabId = type === "HIDS" ? "hidsRulesTab" : "nidsRulesTab"
    const tab = document.getElementById(tabId)
    if(!tab) return
    // Remove existing badge
    tab.querySelectorAll(".rule-count-badge").forEach(b=>b.remove())
    const badge = document.createElement("span")
    badge.className = "rule-count-badge"
    badge.style.cssText = `background:#1e4d6b;color:#a0c8e8;border-radius:12px;
        padding:1px 8px;font-size:11px;margin-left:8px;font-weight:600`
    badge.textContent = count
    tab.appendChild(badge)
}

// =========================================
// RENDER RULES TABLE
// =========================================

const SEV_COLOURS = {
    CRITICAL:"#ff3b30", HIGH:"#ffd21f", MEDIUM:"#2f6bff", LOW:"#55d800"
}

function _renderRules(rules){
    const tbody = document.getElementById("rulesTableBody")
    if(!tbody) return
    tbody.innerHTML = ""

    if(!rules || rules.length === 0){
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;
            padding:50px;color:#5a8a9f;font-size:15px">
            No rules found for ${_currentRuleType}.
            ${_isAdmin ? 'Click <b style="color:#fff">+ Add Rule</b> to create one.' : ''}
        </td></tr>`
        return
    }

    rules.forEach(rule=>{
        const sev = (rule.severity||"LOW").toUpperCase()
        const sevColour = SEV_COLOURS[sev] || "#888"
        const row = document.createElement("tr")
        row.dataset.ruleId = rule.id

        row.innerHTML = `
            <td style="font-family:monospace">${rule.event_id||"-"}</td>
            <td style="font-weight:600">${rule.rule_name||"-"}</td>
            <td style="text-align:center">${rule.threshold||"-"}</td>
            <td style="text-align:center">${rule.window_sec||"-"}</td>
            <td>
                <div class="rule-severity severity-${sev.toLowerCase()}"
                    style="color:${sevColour};background:${sevColour}22;
                    border:1px solid ${sevColour};border-radius:6px;
                    padding:2px 10px;display:inline-block;font-size:12px;font-weight:700">
                    ${sev}
                </div>
            </td>
            <td style="color:#a0c8e8;font-size:13px">${rule.description||"-"}</td>
            <td class="admin-only" style="${_isAdmin?'':'display:none'}">
                <button class="rule-edit-btn"
                    onclick="openEditRule(${rule.id})"
                    style="background:#1e4d6b;color:#fff;border:none;border-radius:6px;
                    padding:5px 14px;cursor:pointer;font-size:12px">
                    Edit
                </button>
            </td>
        `
        tbody.appendChild(row)
    })
}

// =========================================
// REAL-TIME SEARCH
// =========================================

function _filterRules(){
    const q = (document.getElementById("rulesSearchInput")?.value||"").toLowerCase().trim()
    if(!q){
        _renderRules(_allRules)
        return
    }
    const filtered = _allRules.filter(r=>
        String(r.event_id||"").includes(q) ||
        (r.rule_name||"").toLowerCase().includes(q) ||
        (r.description||"").toLowerCase().includes(q) ||
        (r.severity||"").toLowerCase().includes(q)
    )
    _renderRules(filtered)
}

// =========================================
// SORT
// =========================================

function sortRulesTable(){
    const by    = document.getElementById("sortBy")?.value || "event"
    const order = document.getElementById("sortOrder")?.value || "asc"
    const sevRank = {LOW:1, MEDIUM:2, HIGH:3, CRITICAL:4}
    const dir = order === "asc" ? 1 : -1

    const sorted = [..._allRules].sort((a,b)=>{
        if(by === "event"){
            return dir * ((parseInt(a.event_id)||0) - (parseInt(b.event_id)||0))
        }
        if(by === "name"){
            return dir * (a.rule_name||"").localeCompare(b.rule_name||"")
        }
        if(by === "severity"){
            const ra = sevRank[(a.severity||"").toUpperCase()] || 0
            const rb = sevRank[(b.severity||"").toUpperCase()] || 0
            return dir * (ra - rb)
        }
        return 0
    })
    _renderRules(sorted)
}

// =========================================
// TAB SWITCHING
// =========================================

function setActiveTab(activeId){
    document.querySelectorAll(".rules-tab").forEach(t=>t.classList.remove("active"))
    document.getElementById(activeId)?.classList.add("active")
}

// =========================================
// ADD RULE MODAL
// =========================================

function openAddRule(){
    if(!_isAdmin){ _rulesAlert("Admin access required"); return }
    _openRuleModal("add", null)
}

// =========================================
// EDIT RULE MODAL
// =========================================

function openEditRule(ruleId){
    if(!_isAdmin){ _rulesAlert("Admin access required"); return }
    const rule = _allRules.find(r=> r.id === ruleId)
    if(!rule){ _rulesAlert("Rule not found"); return }
    _openRuleModal("edit", rule)
}

// =========================================
// SHARED MODAL BUILDER
// =========================================

function _openRuleModal(mode, rule){
    let modal = document.getElementById("ruleModal")
    if(!modal){
        modal = document.createElement("div")
        modal.id = "ruleModal"
        modal.style.cssText = `position:fixed;inset:0;background:rgba(0,0,0,0.75);
            z-index:10000;display:flex;align-items:center;justify-content:center`
        document.body.appendChild(modal)
    }

    const isEdit = mode === "edit"
    const title  = isEdit ? "✏️ Edit Rule" : "➕ Add Detection Rule"

    modal.innerHTML = `
        <div style="background:#0d1f2d;border:2px solid #1e4d6b;border-radius:14px;
            padding:32px;width:580px;max-width:96vw;max-height:90vh;overflow-y:auto;
            color:#fff;font-family:inherit;box-shadow:0 8px 40px rgba(0,0,0,0.7)">

            <div style="display:flex;justify-content:space-between;align-items:center;
                margin-bottom:24px">
                <div style="font-size:20px;font-weight:800">${title}</div>
                <button onclick="document.getElementById('ruleModal').style.display='none'"
                    style="background:transparent;border:none;color:#5a8a9f;
                    font-size:22px;cursor:pointer">✕</button>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">

                <div style="grid-column:1/-1">
                    <label style="font-size:12px;color:#5a8a9f">Rule Name <span style="color:#ff6b6b">*</span></label>
                    <input id="rm_name" value="${isEdit?(rule.rule_name||""):""}"
                        placeholder="e.g. Brute Force Login Attempt"
                        style="${_rStyle()}">
                </div>

                <div>
                    <label style="font-size:12px;color:#5a8a9f">Rule Type <span style="color:#ff6b6b">*</span></label>
                    <select id="rm_type" style="${_rStyle()}background:#0a1520">
                        <option value="HIDS" ${(!isEdit||rule.rule_type==="HIDS")?"selected":""}>HIDS</option>
                        <option value="NIDS" ${(isEdit&&rule.rule_type==="NIDS")?"selected":""}>NIDS</option>
                    </select>
                </div>

                <div>
                    <label style="font-size:12px;color:#5a8a9f">Severity <span style="color:#ff6b6b">*</span></label>
                    <select id="rm_severity" style="${_rStyle()}background:#0a1520">
                        ${["LOW","MEDIUM","HIGH","CRITICAL"].map(s=>
                            `<option value="${s}" ${isEdit&&rule.severity===s?"selected":""}>${s}</option>`
                        ).join("")}
                    </select>
                </div>

                <div>
                    <label style="font-size:12px;color:#5a8a9f">Event ID</label>
                    <input id="rm_event_id" type="number"
                        value="${isEdit?(rule.event_id||""):""}"
                        placeholder="e.g. 4625"
                        style="${_rStyle()}">
                </div>

                <div>
                    <label style="font-size:12px;color:#5a8a9f">Threshold <span style="color:#ff6b6b">*</span>
                        <span style="color:#3a6a8f">(min hits to trigger)</span></label>
                    <input id="rm_threshold" type="number" min="1"
                        value="${isEdit?(rule.threshold||1):1}"
                        style="${_rStyle()}">
                </div>

                <div>
                    <label style="font-size:12px;color:#5a8a9f">Window (seconds) <span style="color:#ff6b6b">*</span>
                        <span style="color:#3a6a8f">(time window)</span></label>
                    <input id="rm_window" type="number" min="1"
                        value="${isEdit?(rule.window_sec||300):300}"
                        style="${_rStyle()}">
                </div>

                <div style="grid-column:1/-1">
                    <label style="font-size:12px;color:#5a8a9f">Description</label>
                    <textarea id="rm_desc" rows="3"
                        placeholder="Describe what this rule detects..."
                        style="${_rStyle()}resize:vertical"
                    >${isEdit?(rule.description||""):""}</textarea>
                </div>

            </div>

            <div style="display:flex;gap:12px;justify-content:flex-end;margin-top:20px">
                <button onclick="document.getElementById('ruleModal').style.display='none'"
                    style="background:#1a3a5c;color:#fff;border:none;border-radius:8px;
                    padding:10px 24px;cursor:pointer;font-size:14px">Cancel</button>
                <button onclick="${isEdit ? `_submitEditRule(${rule.id})` : "_submitAddRule()"}"
                    style="background:#2f6bff;color:#fff;border:none;border-radius:8px;
                    padding:10px 28px;cursor:pointer;font-size:14px;font-weight:700">
                    ${isEdit ? "💾 Save Changes" : "➕ Add Rule"}
                </button>
            </div>
        </div>
    `
    modal.style.display = "flex"
}

function _rStyle(){
    return `width:100%;background:#0a1520;border:1.5px solid #1e4d6b;border-radius:8px;
        padding:8px 12px;color:#fff;font-size:13px;margin-top:4px;box-sizing:border-box;`
}

function _collectModalData(){
    return {
        rule_name:  document.getElementById("rm_name")?.value?.trim(),
        rule_type:  document.getElementById("rm_type")?.value,
        severity:   document.getElementById("rm_severity")?.value,
        event_id:   document.getElementById("rm_event_id")?.value || null,
        threshold:  document.getElementById("rm_threshold")?.value,
        window_sec: document.getElementById("rm_window")?.value,
        description:document.getElementById("rm_desc")?.value?.trim(),
    }
}

function _validateRuleData(data){
    if(!data.rule_name) return "Rule Name is required"
    if(!data.threshold || parseInt(data.threshold) < 1) return "Threshold must be at least 1"
    if(!data.window_sec || parseInt(data.window_sec) < 1) return "Window must be at least 1 second"
    return null  // valid
}

// =========================================
// SUBMIT ADD RULE
// =========================================

async function _submitAddRule(){
    const data = _collectModalData()
    const err = _validateRuleData(data)
    if(err){ _rulesAlert(err); return }

    try{
        const resp = await fetch("/api/rules/add", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-User-Role": localStorage.getItem("soc_role") || ""
            },
            body: JSON.stringify(data)
        })
        const result = await resp.json()
        if(!resp.ok) throw new Error(result.detail || "Failed to add rule")

        document.getElementById("ruleModal").style.display = "none"
        _rulesAlert(`✅ Rule "${data.rule_name}" added successfully`, "success")
        await loadRules(_currentRuleType)
    }catch(e){
        _rulesAlert(`❌ ${e.message}`)
    }
}

// =========================================
// SUBMIT EDIT RULE
// =========================================

async function _submitEditRule(ruleId){
    const data = _collectModalData()
    const err = _validateRuleData(data)
    if(err){ _rulesAlert(err); return }

    try{
        const resp = await fetch(`/api/rules/update/${ruleId}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "X-User-Role": localStorage.getItem("soc_role") || ""
            },
            body: JSON.stringify(data)
        })
        const result = await resp.json()
        if(!resp.ok) throw new Error(result.detail || "Failed to update rule")

        document.getElementById("ruleModal").style.display = "none"
        _rulesAlert(`✅ Rule updated successfully`, "success")
        await loadRules(_currentRuleType)
    }catch(e){
        _rulesAlert(`❌ ${e.message}`)
    }
}

// =========================================
// DELETE RULE (with confirmation)
// =========================================

function openDeleteRule(){
    if(!_isAdmin){ _rulesAlert("Admin access required"); return }

    // Get selected rows (those the user clicked)
    const selected = _getSelectedRuleIds()
    if(selected.length === 0){
        _rulesAlert("Select at least one rule row to delete")
        return
    }
    _showDeleteConfirm(selected)
}

function _getSelectedRuleIds(){
    return Array.from(
        document.querySelectorAll("#rulesTableBody tr.selected")
    ).map(r=> parseInt(r.dataset.ruleId)).filter(Boolean)
}

function _showDeleteConfirm(ids){
    let modal = document.getElementById("deleteConfirmModal")
    if(!modal){
        modal = document.createElement("div")
        modal.id = "deleteConfirmModal"
        modal.style.cssText = `position:fixed;inset:0;background:rgba(0,0,0,0.75);
            z-index:10001;display:flex;align-items:center;justify-content:center`
        document.body.appendChild(modal)
    }

    const names = ids.map(id=>{
        const r = _allRules.find(r=>r.id===id)
        return r ? r.rule_name : `Rule #${id}`
    })

    modal.innerHTML = `
        <div style="background:#0d1f2d;border:2px solid #ff3b30;border-radius:14px;
            padding:32px;width:420px;max-width:96vw;color:#fff;text-align:center;
            font-family:inherit;box-shadow:0 8px 40px rgba(0,0,0,0.7)">
            <div style="font-size:36px;margin-bottom:12px">🗑️</div>
            <div style="font-size:18px;font-weight:800;margin-bottom:8px">Delete Rule${ids.length>1?"s":""}</div>
            <div style="font-size:13px;color:#a0c8e8;margin-bottom:20px;max-height:120px;overflow-y:auto">
                ${names.map(n=>`<div style="margin:4px 0">• ${n}</div>`).join("")}
            </div>
            <div style="font-size:13px;color:#ff6b6b;margin-bottom:24px">
                This action cannot be undone.
            </div>
            <div style="display:flex;gap:12px;justify-content:center">
                <button onclick="document.getElementById('deleteConfirmModal').style.display='none'"
                    style="background:#1a3a5c;color:#fff;border:none;border-radius:8px;
                    padding:10px 24px;cursor:pointer;font-size:14px">Cancel</button>
                <button onclick="_executeDelete([${ids.join(",")}])"
                    style="background:#ff3b30;color:#fff;border:none;border-radius:8px;
                    padding:10px 28px;cursor:pointer;font-size:14px;font-weight:700">
                    Delete
                </button>
            </div>
        </div>
    `
    modal.style.display = "flex"
}

async function _executeDelete(ids){
    document.getElementById("deleteConfirmModal").style.display = "none"
    let success = 0, failed = 0

    for(const id of ids){
        try{
            const resp = await fetch(`/api/rules/delete/${id}`, {
                method: "DELETE",
                headers: {"X-User-Role": localStorage.getItem("soc_role") || ""}
            })
            const result = await resp.json()
            if(resp.ok) success++
            else failed++
        }catch(e){ failed++ }
    }

    if(success > 0) _rulesAlert(`✅ ${success} rule${success>1?"s":""} deleted`, "success")
    if(failed > 0)  _rulesAlert(`❌ ${failed} rule${failed>1?"s":""} could not be deleted`)

    // Clear selection and reload
    document.querySelectorAll("#rulesTableBody tr.selected").forEach(r=>{
        r.classList.remove("selected")
    })
    await loadRules(_currentRuleType)
}

// =========================================
// ROW SELECTION (click to select for delete)
// =========================================

function _wireRowSelection(){
    const tbody = document.getElementById("rulesTableBody")
    if(!tbody) return
    tbody.addEventListener("click", e=>{
        if(!_isAdmin) return
        const row = e.target.closest("tr")
        if(!row || !row.dataset.ruleId) return
        // Don't toggle selection when clicking Edit button
        if(e.target.closest(".rule-edit-btn")) return
        row.classList.toggle("selected")
        row.style.background = row.classList.contains("selected")
            ? "rgba(255,59,48,0.12)"
            : ""
    })
}

// =========================================
// ALERT / TOAST
// =========================================

function _rulesAlert(msg, type="error"){
    let t = document.getElementById("rulesAlert")
    if(!t){
        t = document.createElement("div")
        t.id = "rulesAlert"
        t.style.cssText = `position:fixed;bottom:28px;right:28px;border-radius:10px;
            padding:14px 22px;color:#fff;font-size:14px;z-index:9998;
            box-shadow:0 4px 20px rgba(0,0,0,0.5);transition:opacity 0.4s;max-width:360px`
        document.body.appendChild(t)
    }
    t.style.background = type === "success" ? "#0a2a0a" : "#2a0a0a"
    t.style.border = `1.5px solid ${type === "success" ? "#55d800" : "#ff3b30"}`
    t.textContent = msg
    t.style.opacity = "1"
    clearTimeout(t._timeout)
    t._timeout = setTimeout(()=>{ t.style.opacity="0" }, 4000)
}

// =========================================
// WIRE UP ON DOM READY
// =========================================

document.addEventListener("DOMContentLoaded", ()=>{
    _checkAdminRole()

    // Tab buttons
    const hidsTab = document.getElementById("hidsRulesTab")
    const nidsTab = document.getElementById("nidsRulesTab")
    if(hidsTab) hidsTab.addEventListener("click", ()=>{
        setActiveTab("hidsRulesTab")
        loadRules("HIDS")
    })
    if(nidsTab) nidsTab.addEventListener("click", ()=>{
        setActiveTab("nidsRulesTab")
        loadRules("NIDS")
    })

    // Add / Delete buttons
    const addBtn = document.getElementById("addRuleBtn")
    const delBtn = document.getElementById("deleteRuleBtn")
    if(addBtn) addBtn.addEventListener("click", openAddRule)
    if(delBtn) delBtn.addEventListener("click", openDeleteRule)

    // Search
    const search = document.getElementById("rulesSearchInput")
    if(search){
        search.addEventListener("input",  _filterRules)
        search.addEventListener("keyup",  _filterRules)
    }

    // Row selection (for delete)
    _wireRowSelection()

    // Initial load
    loadRules("HIDS")
})