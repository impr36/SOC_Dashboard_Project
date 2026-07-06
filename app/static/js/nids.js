/* =========================================
   NIDS INVESTIGATION CONSOLE — nids.js
   Phase 2: Full functional rewrite
   - Load & display grouped network incidents
   - Search / severity / time / status filters
   - Expand/collapse event chain rows
   - Status dropdown → saves to DB immediately
   - Upload button → report modal with template
   - Report submission → saves to DB + shown in Reports page
   - Severity badge colours
   - Empty state handling
   ========================================= */

const NIDS_STATUS_OPTIONS = ["New","Investigating","Escalated","True Positive","False Positive"]

let _nidsAllIncidents = []

// =========================================
// SEVERITY BADGE
// =========================================

function _nidsBadge(sev){
    const s = (sev||"").toUpperCase()
    const c = {CRITICAL:"#ff3b30",HIGH:"#ffd21f",MEDIUM:"#2f6bff",LOW:"#55d800"}[s]||"#888"
    return `<span class="severity-badge ${s.toLowerCase()}" style="color:${c};font-weight:700;
        background:${c}22;padding:2px 10px;border-radius:6px;font-size:12px">${s}</span>`
}

// =========================================
// LOAD NIDS INCIDENTS
// =========================================

async function loadNIDSIncidents(){
    try{
        const resp = await fetch("/api/nids-incidents")
        _nidsAllIncidents = await resp.json()
        _renderNIDSTable(_nidsAllIncidents)
    }catch(e){
        console.error("loadNIDSIncidents error:", e)
    }
}

// =========================================
// RENDER TABLE
// =========================================

function _renderNIDSTable(incidents){
    const tbody = document.getElementById("nidsTableBody")
    if(!tbody) return
    tbody.innerHTML = ""

    if(!incidents || incidents.length === 0){
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:40px;
            color:#5a8a9f;font-size:15px">No NIDS incidents found for this filter.</td></tr>`
        return
    }

    incidents.forEach((incident, index)=>{
        const sev = (incident.severity||"LOW").toLowerCase()
        const alertIds = JSON.stringify(incident.alert_ids || [])

        let statusOpts = NIDS_STATUS_OPTIONS.map(s =>
            `<option value="${s}" ${s===incident.status?"selected":""}>${s}</option>`
        ).join("")

        // ── Group row ──────────────────────────────────────────
        const groupRow = document.createElement("tr")
        groupRow.className = `group-row ${sev}`
        groupRow.dataset.index = index
        groupRow.innerHTML = `
            <td class="expand-icon" style="cursor:pointer;text-align:center;font-size:16px;
                user-select:none" title="Expand details">▼</td>
            <td style="font-weight:700">${incident.group_id||"-"}</td>
            <td>${_nidsBadge(incident.severity)}</td>
            <td style="font-weight:600">${incident.attack_flow||"-"}</td>
            <td style="text-align:center">${incident.packets||incident.events||0}</td>
            <td>${incident.window||"-"}</td>
            <td style="color:#2f6bff;font-weight:600">${incident.confidence||"-"}</td>
            <td class="status-cell">
                <select class="status-dropdown"
                    data-group-id="${incident.group_id}"
                    data-alert-ids='${alertIds}'
                    onchange="updateNIDSStatus(this)">
                    ${statusOpts}
                </select>
                <div class="status-divider"></div>
                <button class="report-btn"
                    title="Generate Incident Report"
                    onclick="event.stopPropagation();openNIDSReport(${index})">
                    <img src="/static/icons-W/upload.png" class="report-icon theme-icon">
                </button>
            </td>
        `

        // ── Event chain row ────────────────────────────────────
        const eventRow = document.createElement("tr")
        eventRow.className = "event-chain-row"
        eventRow.id = `nids-incident-${index}`
        eventRow.style.display = "none"

        let eventRows = (incident.event_chain||[]).map(ev=>`
            <tr>
                <td>${String(ev.timestamp||"-").replace("T"," ").slice(0,19)}</td>
                <td style="font-family:monospace;color:#5fd4d4">${ev.src_ip||"-"}</td>
                <td style="font-family:monospace;color:#f2aa66">${ev.dst_ip||"-"}</td>
                <td style="font-weight:600">${ev.protocol||"-"}</td>
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
                                <th>Timestamp</th><th>Source IP</th><th>Destination IP</th>
                                <th>Protocol</th><th>MITRE</th><th>Description</th>
                            </tr>
                        </thead>
                        <tbody>${eventRows||'<tr><td colspan="6" style="color:#5a8a9f;text-align:center">No event data</td></tr>'}</tbody>
                    </table>
                </div>
            </td>
        `

        // ── Expand toggle ──────────────────────────────────────
        const expandBtn = groupRow.querySelector(".expand-icon")
        expandBtn.addEventListener("click", e=>{
            e.stopPropagation()
            const expanded = eventRow.style.display === "table-row"
            eventRow.style.display = expanded ? "none" : "table-row"
            expandBtn.textContent = expanded ? "▼" : "▲"
        })

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

async function updateNIDSStatus(selectEl){
    const groupId  = selectEl.dataset.groupId
    const alertIds = JSON.parse(selectEl.dataset.alertIds || "[]")
    const newStatus = selectEl.value

    try{
        await fetch("/api/alerts/update-group-status", {
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body: JSON.stringify({alert_ids: alertIds, status: newStatus})
        })
        _showNIDSToast(`✅ Status updated to "${newStatus}" for ${groupId}`)
        const idx = _nidsAllIncidents.findIndex(i=>i.group_id===groupId)
        if(idx>=0) _nidsAllIncidents[idx].status = newStatus
    }catch(e){
        _showNIDSToast("❌ Failed to update status")
    }
}

// =========================================
// OPEN INCIDENT REPORT MODAL
// =========================================

function openNIDSReport(incidentIndex){
    const incident = _nidsAllIncidents[incidentIndex]
    if(!incident){ _showNIDSToast("Incident not found"); return }

    let modal = document.getElementById("nidsReportModal")
    if(!modal){
        modal = document.createElement("div")
        modal.id = "nidsReportModal"
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
                    <div style="font-size:20px;font-weight:800">📋 Network Incident Report</div>
                    <div style="font-size:13px;color:#5a8a9f;margin-top:4px">
                        ${incident.group_id} · Generated ${now}
                    </div>
                </div>
                <button onclick="document.getElementById('nidsReportModal').style.display='none'"
                    style="background:transparent;border:none;color:#5a8a9f;font-size:22px;
                    cursor:pointer;line-height:1">✕</button>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px">
                <div>
                    <label style="font-size:12px;color:#5a8a9f">Ticket ID</label>
                    <input id="nrpt_ticket" value="CASE-NIDS-${incident.group_id.replace('NET-','')}"
                        style="${_nRptInputStyle()}" readonly>
                </div>
                <div>
                    <label style="font-size:12px;color:#5a8a9f">Severity</label>
                    <input id="nrpt_severity" value="${incident.severity}"
                        style="${_nRptInputStyle()}" readonly>
                </div>
                <div>
                    <label style="font-size:12px;color:#5a8a9f">Attack Flow</label>
                    <input id="nrpt_flow" value="${incident.attack_flow}"
                        style="${_nRptInputStyle()}" readonly>
                </div>
                <div>
                    <label style="font-size:12px;color:#5a8a9f">MITRE Tactic</label>
                    <input id="nrpt_mitre" value="${incident.mitre_tactic||'-'}"
                        style="${_nRptInputStyle()}" readonly>
                </div>
                <div>
                    <label style="font-size:12px;color:#5a8a9f">Packets / Events</label>
                    <input id="nrpt_pkts" value="${incident.packets||incident.events||0} in ${incident.window||'?'}"
                        style="${_nRptInputStyle()}" readonly>
                </div>
                <div>
                    <label style="font-size:12px;color:#5a8a9f">Confidence</label>
                    <input id="nrpt_conf" value="${incident.confidence}"
                        style="${_nRptInputStyle()}" readonly>
                </div>
            </div>

            <div style="margin-bottom:14px">
                <label style="font-size:12px;color:#5a8a9f">Classification</label>
                <select id="nrpt_status" style="${_nRptInputStyle()}background:#0a1520">
                    ${NIDS_STATUS_OPTIONS.map(s=>`<option value="${s}" ${s===incident.status?"selected":""}>${s}</option>`).join("")}
                </select>
            </div>

            <div style="margin-bottom:14px">
                <label style="font-size:12px;color:#5a8a9f">
                    Analyst Notes <span style="color:#ff6b6b"> *</span>
                    <span style="color:#3a6a8f"> (describe findings and reasoning)</span>
                </label>
                <textarea id="nrpt_notes" rows="5"
                    placeholder="Describe source IPs, attack pattern, evidence, impact assessment..."
                    style="${_nRptInputStyle()}resize:vertical;min-height:100px"></textarea>
            </div>

            <div style="margin-bottom:14px">
                <label style="font-size:12px;color:#5a8a9f">Network Flow Summary</label>
                <textarea id="nrpt_timeline" rows="3"
                    style="${_nRptInputStyle()}resize:vertical"
                >${_buildNIDSTimeline(incident)}</textarea>
            </div>

            <div style="display:flex;gap:12px;justify-content:flex-end;margin-top:8px">
                <button onclick="document.getElementById('nidsReportModal').style.display='none'"
                    style="background:#1a3a5c;color:#fff;border:none;border-radius:8px;
                    padding:10px 24px;cursor:pointer;font-size:14px">Cancel</button>
                <button onclick="_submitNIDSReport(${incidentIndex})"
                    style="background:#2f6bff;color:#fff;border:none;border-radius:8px;
                    padding:10px 28px;cursor:pointer;font-size:14px;font-weight:700">
                    📤 Submit Report
                </button>
            </div>
        </div>
    `
    modal.style.display = "flex"
}

function _nRptInputStyle(){
    return `width:100%;background:#0a1520;border:1.5px solid #1e4d6b;border-radius:8px;
        padding:8px 12px;color:#fff;font-size:13px;margin-top:4px;box-sizing:border-box;`
}

function _buildNIDSTimeline(incident){
    return (incident.event_chain||[]).slice(0,4).map(ev=>
        `${String(ev.timestamp||"").slice(0,19)} — ${ev.src_ip||"?"} → ${ev.dst_ip||"?"} (${ev.protocol||"?"}) [${ev.mitre||"-"}]`
    ).join("\n") || "No network flow data available."
}

async function _submitNIDSReport(incidentIndex){
    const incident = _nidsAllIncidents[incidentIndex]
    const notes = document.getElementById("nrpt_notes")?.value?.trim()
    if(!notes){
        _showNIDSToast("⚠️ Please fill in the Analyst Notes before submitting")
        return
    }

    const payload = {
        group_id:       incident.group_id,
        source_type:    "NIDS",
        severity:       incident.severity,
        attack_chain:   incident.attack_flow,
        status:         document.getElementById("nrpt_status")?.value || incident.status,
        analyst_notes:  notes,
        alert_ids:      incident.alert_ids || [],
        mitre_tactic:   incident.mitre_tactic || "-",
        mitre_technique: incident.mitre_technique || "-"
    }

    try{
        const resp = await fetch("/api/reports/incident", {
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body: JSON.stringify(payload)
        })
        const result = await resp.json()
        document.getElementById("nidsReportModal").style.display = "none"
        _showNIDSToast(`✅ Report ${result.ticket_id} saved successfully`)
        await loadNIDSIncidents()
    }catch(e){
        _showNIDSToast("❌ Failed to submit report")
    }
}

// =========================================
// CLIENT-SIDE FILTERS
// =========================================

function filterNIDSIncidents(){
    const search = (document.getElementById("nidsSearchInput")?.value||"").toLowerCase()
    const sev    = (document.getElementById("nidsSeverityFilter")?.value||"ALL").toUpperCase()
    const status = (document.getElementById("nidsStatusFilter")?.value||"ALL").toUpperCase()

    let filtered = _nidsAllIncidents
    if(sev !== "ALL")    filtered = filtered.filter(i=>(i.severity||"").toUpperCase()===sev)
    if(status !== "ALL") filtered = filtered.filter(i=>(i.status||"").toUpperCase()===status)
    if(search)           filtered = filtered.filter(i=>JSON.stringify(i).toLowerCase().includes(search))
    _renderNIDSTable(filtered)
}

// =========================================
// TOAST
// =========================================

function _showNIDSToast(msg, duration=4000){
    let t = document.getElementById("nidsToast")
    if(!t){
        t = document.createElement("div")
        t.id = "nidsToast"
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
// WIRE UP ON DOM READY
// =========================================

document.addEventListener("DOMContentLoaded", ()=>{
    const search = document.getElementById("nidsSearchInput")
    const sevF   = document.getElementById("nidsSeverityFilter")
    const statF  = document.getElementById("nidsStatusFilter")
    const timeF  = document.getElementById("nidsTimeFilter")

    if(search) search.addEventListener("input",  filterNIDSIncidents)
    if(sevF)   sevF.addEventListener("change",   filterNIDSIncidents)
    if(statF)  statF.addEventListener("change",  filterNIDSIncidents)
    if(timeF)  timeF.addEventListener("change",  loadNIDSIncidents)

    loadNIDSIncidents()
})