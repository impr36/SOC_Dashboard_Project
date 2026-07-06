/* =========================================
   HIDS INVESTIGATION CONSOLE — hids.js
   Phase 2: Full functional rewrite
   - Load & display grouped incidents
   - Search / severity / time / status filters
   - Expand/collapse event chain rows
   - Status dropdown → saves to DB immediately
   - Upload button → report modal with template
   - Report submission → saves to DB + shown in Reports page
   - Severity badge colours
   - Empty state handling
   ========================================= */

const STATUS_OPTIONS = ["New","Investigating","Escalated","True Positive","False Positive"]

let _hidsAllIncidents = []   // master copy for client-side filtering

// =========================================
// SEVERITY BADGE
// =========================================

function _hidsBadge(sev){
    const s = (sev||"").toUpperCase()
    const c = {CRITICAL:"#ff3b30",HIGH:"#ffd21f",MEDIUM:"#2f6bff",LOW:"#55d800"}[s]||"#888"
    return `<span class="severity-badge ${s.toLowerCase()}" style="color:${c};font-weight:700;
        background:${c}22;padding:2px 10px;border-radius:6px;font-size:12px">${s}</span>`
}

// =========================================
// LOAD HIDS INCIDENTS
// =========================================

async function loadHIDSIncidents(){
    try{
        const resp = await fetch("/api/hids-incidents")
        _hidsAllIncidents = await resp.json()
        _renderHIDSTable(_hidsAllIncidents)
    }catch(e){
        console.error("loadHIDSIncidents error:", e)
    }
}

// =========================================
// RENDER TABLE
// =========================================

function _renderHIDSTable(incidents){
    const tbody = document.getElementById("hidsTableBody")
    if(!tbody) return
    tbody.innerHTML = ""

    if(!incidents || incidents.length === 0){
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:40px;
            color:#5a8a9f;font-size:15px">No HIDS incidents found for this filter.</td></tr>`
        return
    }

    incidents.forEach((incident, index)=>{
        const sev = (incident.severity||"LOW").toLowerCase()
        const alertIds = JSON.stringify(incident.alert_ids || [])

        // Build status dropdown
        let statusOpts = STATUS_OPTIONS.map(s =>
            `<option value="${s}" ${s===incident.status?"selected":""}>${s}</option>`
        ).join("")

        // ── Group row ──────────────────────────────────────────
        const groupRow = document.createElement("tr")
        groupRow.className = `group-row ${sev}`
        groupRow.dataset.index = index
        groupRow.innerHTML = `
            <td class="expand-toggle" style="cursor:pointer;text-align:center;font-size:16px;
                user-select:none" title="Expand details">▼</td>
            <td style="font-weight:700">${incident.group_id||"-"}</td>
            <td>${_hidsBadge(incident.severity)}</td>
            <td style="font-weight:600">${incident.attack_chain||"-"}</td>
            <td style="text-align:center">${incident.events||0}</td>
            <td>${incident.window||"-"}</td>
            <td style="color:#2f6bff;font-weight:600">${incident.confidence||"-"}</td>
            <td class="status-cell">
                <select class="status-dropdown"
                    data-group-id="${incident.group_id}"
                    data-alert-ids='${alertIds}'
                    onchange="updateHIDSStatus(this)">
                    ${statusOpts}
                </select>
                <div class="status-divider"></div>
                <button class="report-btn"
                    title="Generate Incident Report"
                    onclick="event.stopPropagation();openHIDSReport(${index})">
                    <img src="/static/icons-W/upload.png" class="report-icon theme-icon">
                </button>
            </td>
        `

        // ── Event chain row ────────────────────────────────────
        const eventRow = document.createElement("tr")
        eventRow.className = "event-chain-row"
        eventRow.id = `hids-incident-${index}`
        eventRow.style.display = "none"

        let eventRows = (incident.event_chain||[]).map(ev=>`
            <tr>
                <td>${String(ev.timestamp||"-").replace("T"," ").slice(0,19)}</td>
                <td style="font-family:monospace">${ev.process||"-"}</td>
                <td style="font-family:monospace;color:#a0c8e8">${ev.parent||"-"}</td>
                <td>${ev.user||"-"}</td>
                <td style="color:#2f6bff;font-weight:600">${ev.mitre||"-"}</td>
                <td class="desc-cell">${ev.description||"-"}</td>
            </tr>
        `).join("")

        eventRow.innerHTML = `
            <td colspan="8">
                <div class="event-chain-container">
                    <table class="event-chain-table">
                        <thead>
                            <tr>
                                <th>Timestamp</th><th>Process</th><th>Parent</th>
                                <th>User</th><th>MITRE</th><th>Description</th>
                            </tr>
                        </thead>
                        <tbody>${eventRows||'<tr><td colspan="6" style="color:#5a8a9f;text-align:center">No event data</td></tr>'}</tbody>
                    </table>
                </div>
            </td>
        `

        // ── Expand toggle ──────────────────────────────────────
        const expandBtn = groupRow.querySelector(".expand-toggle")
        expandBtn.addEventListener("click", e=>{
            e.stopPropagation()
            const expanded = eventRow.style.display === "table-row"
            eventRow.style.display = expanded ? "none" : "table-row"
            expandBtn.textContent = expanded ? "▼" : "▲"
        })

        // Prevent dropdown clicks bubbling to row
        const dd = groupRow.querySelector(".status-dropdown")
        ;["click","mousedown","mouseup","change"].forEach(t=>{
            dd.addEventListener(t, e=> e.stopPropagation())
        })

        tbody.appendChild(groupRow)
        tbody.appendChild(eventRow)
    })
}

// =========================================
// STATUS UPDATE → DB
// =========================================

async function updateHIDSStatus(selectEl){
    const groupId  = selectEl.dataset.groupId
    const alertIds = JSON.parse(selectEl.dataset.alertIds || "[]")
    const newStatus = selectEl.value

    try{
        await fetch("/api/alerts/update-group-status", {
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body: JSON.stringify({alert_ids: alertIds, status: newStatus})
        })
        _showHIDSToast(`✅ Status updated to "${newStatus}" for ${groupId}`)
        // Update master copy so filter still works after status change
        const idx = _hidsAllIncidents.findIndex(i=>i.group_id===groupId)
        if(idx>=0) _hidsAllIncidents[idx].status = newStatus
    }catch(e){
        console.error("Status update failed:", e)
        _showHIDSToast("❌ Failed to update status")
    }
}

// =========================================
// OPEN INCIDENT REPORT MODAL
// =========================================

function openHIDSReport(incidentIndex){
    const incident = _hidsAllIncidents[incidentIndex]
    if(!incident){ _showHIDSToast("Incident not found"); return }

    let modal = document.getElementById("hidsReportModal")
    if(!modal){
        modal = document.createElement("div")
        modal.id = "hidsReportModal"
        modal.style.cssText = `
            position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:10000;
            display:flex;align-items:center;justify-content:center`
        document.body.appendChild(modal)
    }

    const now = new Date().toLocaleString()
    modal.innerHTML = `
        <div style="background:#0d1f2d;border:2px solid #1e4d6b;border-radius:14px;
            padding:32px;width:660px;max-width:96vw;max-height:90vh;overflow-y:auto;
            color:#fff;font-family:inherit;box-shadow:0 8px 40px rgba(0,0,0,0.7)">

            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
                <div>
                    <div style="font-size:20px;font-weight:800">📋 Incident Report</div>
                    <div style="font-size:13px;color:#5a8a9f;margin-top:4px">
                        ${incident.group_id} · Generated ${now}
                    </div>
                </div>
                <button onclick="document.getElementById('hidsReportModal').style.display='none'"
                    style="background:transparent;border:none;color:#5a8a9f;font-size:22px;
                    cursor:pointer;line-height:1">✕</button>
            </div>

            <!-- Pre-filled fields -->
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px">
                <div>
                    <label style="font-size:12px;color:#5a8a9f">Ticket ID</label>
                    <input id="rpt_ticket" value="CASE-HIDS-${incident.group_id.replace('GRP-','')}"
                        style="${_rptInputStyle()}" readonly>
                </div>
                <div>
                    <label style="font-size:12px;color:#5a8a9f">Severity</label>
                    <input id="rpt_severity" value="${incident.severity}"
                        style="${_rptInputStyle()}" readonly>
                </div>
                <div>
                    <label style="font-size:12px;color:#5a8a9f">Attack Chain</label>
                    <input id="rpt_chain" value="${incident.attack_chain}"
                        style="${_rptInputStyle()}" readonly>
                </div>
                <div>
                    <label style="font-size:12px;color:#5a8a9f">MITRE Tactic</label>
                    <input id="rpt_mitre" value="${incident.mitre_tactic||'-'}"
                        style="${_rptInputStyle()}" readonly>
                </div>
                <div>
                    <label style="font-size:12px;color:#5a8a9f">Events Detected</label>
                    <input id="rpt_events" value="${incident.events} events in ${incident.window}"
                        style="${_rptInputStyle()}" readonly>
                </div>
                <div>
                    <label style="font-size:12px;color:#5a8a9f">Confidence</label>
                    <input id="rpt_conf" value="${incident.confidence}"
                        style="${_rptInputStyle()}" readonly>
                </div>
            </div>

            <!-- Status -->
            <div style="margin-bottom:14px">
                <label style="font-size:12px;color:#5a8a9f">Classification</label>
                <select id="rpt_status"
                    style="${_rptInputStyle()}background:#0a1520">
                    ${STATUS_OPTIONS.map(s=>`<option value="${s}" ${s===incident.status?"selected":""}>${s}</option>`).join("")}
                </select>
            </div>

            <!-- Analyst notes -->
            <div style="margin-bottom:14px">
                <label style="font-size:12px;color:#5a8a9f">
                    Analyst Notes
                    <span style="color:#ff6b6b"> *</span>
                    <span style="color:#3a6a8f"> (describe why True Positive / False Positive or investigation notes)</span>
                </label>
                <textarea id="rpt_notes" rows="5"
                    placeholder="Describe the incident findings, evidence, impact assessment, and your reasoning..."
                    style="${_rptInputStyle()}resize:vertical;min-height:100px"></textarea>
            </div>

            <!-- Timeline summary (auto-filled) -->
            <div style="margin-bottom:14px">
                <label style="font-size:12px;color:#5a8a9f">Timeline Summary</label>
                <textarea id="rpt_timeline" rows="3"
                    style="${_rptInputStyle()}resize:vertical"
                >${_buildHIDSTimeline(incident)}</textarea>
            </div>

            <!-- Actions row -->
            <div style="display:flex;gap:12px;justify-content:flex-end;margin-top:8px">
                <button onclick="document.getElementById('hidsReportModal').style.display='none'"
                    style="background:#1a3a5c;color:#fff;border:none;border-radius:8px;
                    padding:10px 24px;cursor:pointer;font-size:14px">Cancel</button>
                <button onclick="_submitHIDSReport(${incidentIndex})"
                    style="background:#2f6bff;color:#fff;border:none;border-radius:8px;
                    padding:10px 28px;cursor:pointer;font-size:14px;font-weight:700">
                    📤 Submit Report
                </button>
            </div>

        </div>
    `
    modal.style.display = "flex"
}

function _rptInputStyle(){
    return `width:100%;background:#0a1520;border:1.5px solid #1e4d6b;border-radius:8px;
        padding:8px 12px;color:#fff;font-size:13px;margin-top:4px;box-sizing:border-box;`
}

function _buildHIDSTimeline(incident){
    const chain = (incident.event_chain||[]).slice(0,4).map(ev=>
        `${String(ev.timestamp||"").slice(0,19)} — ${ev.process||"?"} (${ev.mitre||"-"})`
    ).join("\n")
    return chain || "No event chain data available."
}

// =========================================
// SUBMIT REPORT
// =========================================

async function _submitHIDSReport(incidentIndex){
    const incident = _hidsAllIncidents[incidentIndex]
    const notes = document.getElementById("rpt_notes")?.value?.trim()
    if(!notes){
        _showHIDSToast("⚠️ Please fill in the Analyst Notes before submitting")
        return
    }

    const payload = {
        group_id:      incident.group_id,
        source_type:   "HIDS",
        severity:      incident.severity,
        attack_chain:  incident.attack_chain,
        status:        document.getElementById("rpt_status")?.value || incident.status,
        analyst_notes: notes,
        alert_ids:     incident.alert_ids || [],
        mitre_tactic:  incident.mitre_tactic || "-",
        mitre_technique: incident.mitre_technique || "-"
    }

    try{
        const resp = await fetch("/api/reports/incident", {
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body: JSON.stringify(payload)
        })
        const result = await resp.json()
        document.getElementById("hidsReportModal").style.display = "none"
        _showHIDSToast(`✅ Report ${result.ticket_id} saved successfully`)
        // Reload to reflect status change
        await loadHIDSIncidents()
    }catch(e){
        console.error("Report submit failed:", e)
        _showHIDSToast("❌ Failed to submit report")
    }
}

// =========================================
// CLIENT-SIDE FILTERS
// =========================================

function filterHIDSIncidents(){
    const search = (document.getElementById("hidsSearchInput")?.value||"").toLowerCase()
    const sev    = (document.getElementById("severityFilter")?.value||"ALL").toUpperCase()
    const status = (document.getElementById("statusFilter")?.value||"ALL").toUpperCase()

    let filtered = _hidsAllIncidents

    if(sev !== "ALL")
        filtered = filtered.filter(i=>(i.severity||"").toUpperCase()===sev)

    if(status !== "ALL")
        filtered = filtered.filter(i=>(i.status||"").toUpperCase()===status)

    if(search)
        filtered = filtered.filter(i=>
            JSON.stringify(i).toLowerCase().includes(search)
        )

    _renderHIDSTable(filtered)
}

// =========================================
// TOAST
// =========================================

function _showHIDSToast(msg, duration=4000){
    let t = document.getElementById("hidsToast")
    if(!t){
        t = document.createElement("div")
        t.id = "hidsToast"
        t.style.cssText = `position:fixed;bottom:28px;right:28px;background:#0d1f2d;
            border:1.5px solid #1e4d6b;border-radius:10px;padding:14px 22px;color:#fff;
            font-size:14px;z-index:9998;box-shadow:0 4px 20px rgba(0,0,0,0.5);
            transition:opacity 0.4s;max-width:360px`
        document.body.appendChild(t)
    }
    t.textContent = msg
    t.style.opacity = "1"
    clearTimeout(t._timeout)
    t._timeout = setTimeout(()=>{ t.style.opacity="0" }, duration)
}

// =========================================
// WIRE UP FILTERS ON DOM READY
// =========================================

document.addEventListener("DOMContentLoaded", ()=>{
    const search = document.getElementById("hidsSearchInput")
    const sevF   = document.getElementById("severityFilter")
    const statF  = document.getElementById("statusFilter")
    const timeF  = document.getElementById("timeFilter")

    if(search) search.addEventListener("input",  filterHIDSIncidents)
    if(sevF)   sevF.addEventListener("change",   filterHIDSIncidents)
    if(statF)  statF.addEventListener("change",  filterHIDSIncidents)
    if(timeF)  timeF.addEventListener("change",  loadHIDSIncidents)

    loadHIDSIncidents()
})