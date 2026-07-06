// =========================================
// DETECTION RULES PAGE
// =========================================

let _rulesData     = { HIDS: [], NIDS: [] }
let _rulesFiltered = []
let _currentTab    = "HIDS"
let _editingRuleId = null
let _selectedRuleId= null
let _userRole      = localStorage.getItem("soc_role") || "admin"

// =========================================
// LOAD RULES
// =========================================

async function loadRules(){
    try{
        const [hidsResp, nidsResp] = await Promise.all([
            fetch("/api/rules/HIDS"),
            fetch("/api/rules/NIDS")
        ])
        _rulesData.HIDS = await hidsResp.json()
        _rulesData.NIDS = await nidsResp.json()

        const hidsCount = document.getElementById("hidsCount")
        const nidsCount = document.getElementById("nidsCount")
        if(hidsCount) hidsCount.textContent = _rulesData.HIDS.length
        if(nidsCount) nidsCount.textContent  = _rulesData.NIDS.length

        _applyRoleVisibility()
        renderRulesTable()
    }catch(e){
        console.error("loadRules error:", e)
        const tbody = document.getElementById("rulesTableBody")
        if(tbody) tbody.innerHTML = `<tr><td colspan="8" style="color:#ff3b30;padding:20px">
            Error loading rules: ${e.message}</td></tr>`
    }
}

function _applyRoleVisibility(){
    // Only admin can add/edit/delete rules
    const adminActions = document.getElementById("rulesAdminActions")
    const editColHeader = document.getElementById("rulesEditColHeader")
    const isAdmin = _userRole === "admin"
    if(adminActions)   adminActions.style.display   = isAdmin ? "flex" : "none"
    if(editColHeader)  editColHeader.style.display   = isAdmin ? "" : "none"
}

// =========================================
// RENDER TABLE
// =========================================

function renderRulesTable(){
    const tbody = document.getElementById("rulesTableBody")
    if(!tbody) return

    let rules = [...(_rulesData[_currentTab] || [])]

    // Apply search filter
    const q = (document.getElementById("rulesSearchInput")?.value || "").toLowerCase().trim()
    if(q){
        rules = rules.filter(r =>
            String(r.rule_name   || "").toLowerCase().includes(q) ||
            String(r.event_id    || "").toLowerCase().includes(q) ||
            String(r.severity    || "").toLowerCase().includes(q) ||
            String(r.description || "").toLowerCase().includes(q)
        )
    }

    _rulesFiltered = rules

    const countEl = document.getElementById("rulesResultCount")
    if(countEl) countEl.textContent = `Showing ${rules.length} of ${_rulesData[_currentTab].length} rules`

    if(!rules.length){
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:40px;opacity:.5">
            No rules found</td></tr>`
        return
    }

    const isAdmin = _userRole === "admin"
    const sevColors = {CRITICAL:"#ff3b30",HIGH:"#ffd21f",MEDIUM:"#2f6bff",LOW:"#55d800"}

    tbody.innerHTML = rules.map(r => {
        const sev   = (r.severity || "LOW").toUpperCase()
        const color = sevColors[sev] || "#888"
        const isSelected = r.id === _selectedRuleId

        return `<tr class="rules-row ${isSelected ? "rules-row-selected" : ""}"
            onclick="selectRule(${r.id})"
            style="cursor:pointer">
            <td onclick="event.stopPropagation()">
                <input type="checkbox" class="rule-checkbox"
                    data-id="${r.id}"
                    ${isSelected ? "checked" : ""}
                    onchange="onRuleCheckbox(${r.id}, this.checked)">
            </td>
            <td style="font-weight:700;color:#5a8a9f">${r.event_id || "-"}</td>
            <td style="font-weight:700">${r.rule_name || "-"}</td>
            <td style="text-align:center">${r.threshold || "-"}</td>
            <td style="text-align:center">${r.window_sec || "-"}</td>
            <td>
                <span style="background:${color}22;color:${color};
                    padding:3px 12px;border-radius:10px;
                    font-size:11px;font-weight:800;letter-spacing:0.5px">
                    ${sev}
                </span>
            </td>
            <td style="font-size:12px;color:#5a8a9f;max-width:300px;
                word-break:break-word;white-space:normal">
                ${r.description || "-"}
            </td>
            ${isAdmin ? `
            <td onclick="event.stopPropagation()">
                <button class="rules-edit-btn" onclick="openEditRuleModal(${r.id})">
                    Edit
                </button>
            </td>` : "<td></td>"}
        </tr>`
    }).join("")
}

// =========================================
// SELECTION
// =========================================

function selectRule(ruleId){
    _selectedRuleId = (_selectedRuleId === ruleId) ? null : ruleId
    const deleteBtn = document.getElementById("rulesDeleteBtn")
    if(deleteBtn) deleteBtn.disabled = !_selectedRuleId
    renderRulesTable()
}

function onRuleCheckbox(ruleId, checked){
    _selectedRuleId = checked ? ruleId : null
    const deleteBtn = document.getElementById("rulesDeleteBtn")
    if(deleteBtn) deleteBtn.disabled = !_selectedRuleId
    // Uncheck all others
    document.querySelectorAll(".rule-checkbox").forEach(cb => {
        if(parseInt(cb.dataset.id) !== ruleId) cb.checked = false
    })
}

function toggleSelectAllRules(checked){
    _selectedRuleId = null
    document.querySelectorAll(".rule-checkbox").forEach(cb => cb.checked = false)
    const deleteBtn = document.getElementById("rulesDeleteBtn")
    if(deleteBtn) deleteBtn.disabled = true
}

// =========================================
// TABS
// =========================================

function switchRuleTab(tab){
    _currentTab     = tab
    _selectedRuleId = null
    const deleteBtn = document.getElementById("rulesDeleteBtn")
    if(deleteBtn) deleteBtn.disabled = true

    document.getElementById("tabHIDS")?.classList.toggle("active", tab === "HIDS")
    document.getElementById("tabNIDS")?.classList.toggle("active", tab === "NIDS")

    renderRulesTable()
}

// =========================================
// SEARCH + SORT
// =========================================

function filterRules(){ renderRulesTable() }

function sortRules(){
    const field = document.getElementById("rulesSortField")?.value || "event_id"
    const order = document.getElementById("rulesSortOrder")?.value || "asc"

    const rules = _rulesData[_currentTab]
    rules.sort((a, b) => {
        let av = a[field], bv = b[field]
        if(field === "event_id" || field === "threshold"){
            av = parseInt(av) || 0
            bv = parseInt(bv) || 0
        } else {
            av = String(av || "").toLowerCase()
            bv = String(bv || "").toLowerCase()
        }
        if(av < bv) return order === "asc" ? -1 : 1
        if(av > bv) return order === "asc" ?  1 : -1
        return 0
    })
    renderRulesTable()
}

// =========================================
// ADD RULE MODAL
// =========================================

function openAddRuleModal(){
    _editingRuleId = null
    document.getElementById("addRuleModalTitle").textContent = "+ Add New Rule"
    document.getElementById("ruleFormSaveBtn").textContent   = "Save Rule"

    // Clear form
    ;["ruleFormName","ruleFormEventId","ruleFormThreshold",
      "ruleFormWindow","ruleFormDesc"].forEach(id => {
        const el = document.getElementById(id)
        if(el) el.value = ""
    })
    document.getElementById("ruleFormType").value     = _currentTab
    document.getElementById("ruleFormSeverity").value = "HIGH"
    document.getElementById("ruleFormMitreTactic").value = ""

    const msg = document.getElementById("ruleFormMsg")
    if(msg) msg.style.display = "none"

    document.getElementById("addRuleModal").style.display = "flex"
}

function openEditRuleModal(ruleId){
    const rule = _rulesData[_currentTab].find(r => r.id === ruleId)
    if(!rule) return

    _editingRuleId = ruleId
    document.getElementById("addRuleModalTitle").textContent = "✏️ Edit Rule"
    document.getElementById("ruleFormSaveBtn").textContent   = "Update Rule"

    document.getElementById("ruleFormName").value        = rule.rule_name    || ""
    document.getElementById("ruleFormType").value        = rule.rule_type    || _currentTab
    document.getElementById("ruleFormEventId").value     = rule.event_id     || ""
    document.getElementById("ruleFormThreshold").value   = rule.threshold    || ""
    document.getElementById("ruleFormWindow").value      = rule.window_sec   || ""
    document.getElementById("ruleFormSeverity").value    = rule.severity     || "HIGH"
    document.getElementById("ruleFormDesc").value        = rule.description  || ""
    document.getElementById("ruleFormMitreTactic").value = rule.mitre_tactic || ""

    const msg = document.getElementById("ruleFormMsg")
    if(msg) msg.style.display = "none"

    document.getElementById("addRuleModal").style.display = "flex"
}

function closeAddRuleModal(){
    document.getElementById("addRuleModal").style.display = "none"
    _editingRuleId = null
}

async function saveRule(){
    const btn  = document.getElementById("ruleFormSaveBtn")
    if(btn) btn.disabled = true

    const name      = document.getElementById("ruleFormName")?.value?.trim()
    const ruleType  = document.getElementById("ruleFormType")?.value
    const eventId   = parseInt(document.getElementById("ruleFormEventId")?.value)
    const threshold = parseInt(document.getElementById("ruleFormThreshold")?.value)
    const windowSec = parseInt(document.getElementById("ruleFormWindow")?.value)
    const severity  = document.getElementById("ruleFormSeverity")?.value
    const desc      = document.getElementById("ruleFormDesc")?.value?.trim()
    const mitreTactic = document.getElementById("ruleFormMitreTactic")?.value || ""

    if(!name || !eventId || !threshold || !windowSec || !severity || !desc){
        _ruleFormMsg("❌ All required fields must be filled", "error")
        if(btn) btn.disabled = false
        return
    }

    const payload = {
        rule_type:    ruleType,
        event_id:     eventId,
        rule_name:    name,
        threshold:    threshold,
        window_sec:   windowSec,
        severity:     severity,
        description:  desc,
        mitre_tactic: mitreTactic,
    }

    try{
        let resp
        if(_editingRuleId){
            resp = await fetch(`/api/rules/update/${_editingRuleId}`, {
                method:  "PUT",
                headers: {"Content-Type":"application/json"},
                body:    JSON.stringify(payload)
            })
        } else {
            resp = await fetch("/api/rules/add", {
                method:  "POST",
                headers: {"Content-Type":"application/json"},
                body:    JSON.stringify(payload)
            })
        }

        if(resp.ok){
            _ruleFormMsg("✅ Rule saved successfully", "success")
            setTimeout(() => {
                closeAddRuleModal()
                loadRules()
            }, 800)
        } else {
            const data = await resp.json()
            _ruleFormMsg(`❌ ${data.detail || "Failed to save rule"}`, "error")
        }
    }catch(e){
        _ruleFormMsg("❌ Network error: " + e.message, "error")
    }finally{
        if(btn) btn.disabled = false
    }
}

async function deleteSelectedRule(){
    if(!_selectedRuleId) return

    const rule = _rulesData[_currentTab].find(r => r.id === _selectedRuleId)
    const name = rule?.rule_name || `ID ${_selectedRuleId}`

    if(!confirm(`Delete rule "${name}"?\n\nThis cannot be undone.`)) return

    try{
        const resp = await fetch(`/api/rules/delete/${_selectedRuleId}`, {
            method: "DELETE"
        })
        if(resp.ok){
            _selectedRuleId = null
            const deleteBtn = document.getElementById("rulesDeleteBtn")
            if(deleteBtn) deleteBtn.disabled = true
            await loadRules()
        } else {
            alert("Failed to delete rule")
        }
    }catch(e){
        alert("Error: " + e.message)
    }
}

function _ruleFormMsg(msg, type){
    const el = document.getElementById("ruleFormMsg")
    if(!el) return
    el.textContent  = msg
    el.style.color  = type === "error" ? "#ff3b30" : "#55d800"
    el.style.background = type === "error" ? "rgba(255,59,48,0.08)" : "rgba(85,216,0,0.08)"
    el.style.display = "block"
}

// Load on init
loadRules()