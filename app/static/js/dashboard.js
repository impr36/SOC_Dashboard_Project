/* =========================================
   SOC DASHBOARD — dashboard.js
   Phase 1: Full functional rewrite
   - Run Full Scan (background poll + live counter)
   - Refresh button
   - Save to Forensics
   - Time filter (Apply + select)
   - Alert queue: search, sort, severity badge colours
   - Charts: auto-scale, correct bar alignment
   - Scan popup window with live timer + phase log
   - Time filter enforced before scan (default = "select")
   ========================================= */

let donutChart
let barChart
let _scanHasRun = false

// =========================================
// CHART HELPERS
// =========================================

const BAR_LABELS = [
    "Authentication","Privilege Escalation","Persistence",
    "Credential Access","Lateral Movement","Defense Evasion",
    "Execution","Reconnaissance","Command & Control",
    "Data Exfiltration","Ransomware","Network Scanning",
    "System Tampering","Others"
]

// Map DB category names → bar label names
// The DB may store "Command and Control" but chart shows "Command & Control"
const CATEGORY_ALIAS = {
    "Command and Control":   "Command & Control",
    "Command And Control":   "Command & Control",
    "C2":                    "Command & Control",
    "Lateral Movement":      "Lateral Movement",
    "Data Exfiltration":     "Data Exfiltration",
    "Exfiltration":          "Data Exfiltration",
    "Network":               "Network Scanning",
    "Network Scan":          "Network Scanning",
    "Scanning":              "Network Scanning",
    "Tamper":                "System Tampering",
    "System Tamper":         "System Tampering",
    "Discovery":             "Reconnaissance",
    "Recon":                 "Reconnaissance",
    "Initial Access":        "Authentication",
    "Collection":            "Credential Access",
    "Impact":                "Ransomware",
}

function _normaliseCategory(cat) {
    if(!cat) return "Others"
    const c = String(cat).trim()
    return CATEGORY_ALIAS[c] || c
}

function _severityBadge(sev){
    const s = (sev||"").toUpperCase()
    const colours = {CRITICAL:"#ff3b30",HIGH:"#ffd21f",MEDIUM:"#2f6bff",LOW:"#55d800"}
    const c = colours[s] || "#888"
    return `<span style="color:${c};font-weight:700">${s||"-"}</span>`
}

// =========================================
// LOAD FULL DASHBOARD DATA
// =========================================

async function loadDashboardData(){
    try{
        const filter = document.getElementById("timeFilter")?.value || "7d"
        const response = await fetch(`/api/chart-data?range=${filter}&_=${Date.now()}`)
        const data = await response.json()
        _applyDashboardData(data)
    }catch(error){
        console.error("loadDashboardData error:", error)
    }
}

// =========================================
// APPLY DATA TO ALL WIDGETS
// =========================================

function _applyDashboardData(data){

    // --- Counters ---
    const set = (id, val) => { const el=document.getElementById(id); if(el) el.innerText=val }
    set("totalAlerts",  data.total_alerts ?? 0)
    set("lowCount",     data.severity?.LOW      || 0)
    set("mediumCount",  data.severity?.MEDIUM   || 0)
    set("highCount",    data.severity?.HIGH     || 0)
    set("criticalCount",data.severity?.CRITICAL || 0)

    // --- Last Scan ---
    const lastScanEl = document.getElementById("lastScan")
    if(lastScanEl){
        const ls = data.last_scan || null
        lastScanEl.innerHTML = ls
            ? `${data.scan_type||"FULL SCAN"}<br>${ls.replace("T"," ").slice(0,19)}`
            : `${data.scan_type||"NONE"}<br>N/A`
    }

    // --- Donut chart ---
    const donutValues = [
        data.severity?.LOW      || 0,
        data.severity?.MEDIUM   || 0,
        data.severity?.HIGH     || 0,
        data.severity?.CRITICAL || 0
    ]
    const total = donutValues.reduce((a,b)=>a+b,0)

    if(total === 0){
        // No data yet — show equal grey segments as placeholder
        donutChart.data.labels   = ["LOW","MEDIUM","HIGH","CRITICAL"]
        donutChart.data.datasets[0].data            = [1,1,1,1]
        donutChart.data.datasets[0].backgroundColor = ["#2a3f52","#2a3f52","#2a3f52","#2a3f52"]
        donutChart.data.datasets[0].borderColor     = ["#1a2f40","#1a2f40","#1a2f40","#1a2f40"]
        donutChart.data.datasets[0].borderWidth     = 1
    } else {
        donutChart.data.labels   = ["LOW","MEDIUM","HIGH","CRITICAL"]
        donutChart.data.datasets[0].data            = donutValues
        donutChart.data.datasets[0].backgroundColor = ["#55d800","#2f6bff","#ffd21f","#ff3b30"]
        donutChart.data.datasets[0].borderColor     = ["#55d800","#2f6bff","#ffd21f","#ff3b30"]
        donutChart.data.datasets[0].borderWidth     = 1
    }
    donutChart.update()
    const dw = document.querySelector(".donut-wrapper")
    if(dw) dw.classList.toggle("has-data", total>0)

    // Re-apply theme after data update so chart colours
    // stay correct in light mode after a scan completes
    updateChartsTheme()

    // --- Bar chart ---
    // Normalise category names from DB before mapping to bar labels
    const rawCats = data.categories || {}
    const cats = {}
    Object.entries(rawCats).forEach(([k, v]) => {
        const norm = _normaliseCategory(k)
        cats[norm] = (cats[norm] || 0) + v
    })
    barChart.data.labels = BAR_LABELS
    const knownLabels = BAR_LABELS.slice(0,-1)
    const othersTotal = Object.entries(cats).filter(([k])=>!knownLabels.includes(k)).reduce((s,[,v])=>s+v,0)
    const catsWithOthers = {...cats, "Others":(cats["Others"]||0)+othersTotal}
    barChart.data.datasets[0].data = BAR_LABELS.map(l => catsWithOthers[l] || 0)
    const maxVal = Math.max(...barChart.data.datasets[0].data, 5)
    const scaledMax = Math.ceil(maxVal * 1.3)
    barChart.options.scales.y.max = scaledMax
    barChart.options.scales.y.ticks.stepSize = Math.max(1, Math.ceil(scaledMax/5))
    barChart.update()

    // --- Alert table ---
    _renderAlertTable(data.alerts || [])
}

// =========================================
// RENDER ALERT TABLE
// =========================================

let _allAlerts = []   // master copy for client-side search/sort

function _renderAlertTable(alerts){
    _allAlerts = alerts
    const tbody  = document.getElementById("alertTableBody")
    const empty  = document.getElementById("emptyAlertState")
    if(!tbody) return

    tbody.innerHTML = ""

    if(!alerts || alerts.length === 0){
        if(empty) empty.style.display = "flex"
        return
    }
    if(empty) empty.style.display = "none"

    alerts.slice(0,500).forEach(a => {
        const row = document.createElement("tr")
        row.innerHTML = `
            <td style="text-align:center;white-space:nowrap;font-weight:700">${a.id||"-"}</td>
            <td style="white-space:nowrap;font-size:12px">${(a.timestamp||"-").replace("T"," ").slice(0,19)}</td>
            <td style="font-size:13px">${a.type||"-"}</td>
            <td style="text-align:center;white-space:nowrap">${_severityBadge(a.severity)}</td>
            <td style="font-size:13px">${a.category||"-"}</td>
            <td class="alert-desc-cell" style="font-size:12px;word-break:break-word;white-space:normal">${a.description||"-"}</td>
        `
        tbody.appendChild(row)
    })
}

// =========================================
// SEARCH BAR (real-time client filter)
// =========================================

function _filterTable(){
    const q = (document.getElementById("dashboardSearchInput")?.value || "").toLowerCase().trim()
    const tbody = document.getElementById("alertTableBody")
    const empty = document.getElementById("emptyAlertState")
    if(!tbody) return

    if(!q){
        _renderAlertTable(_allAlerts)
        return
    }

    const filtered = _allAlerts.filter(a =>
        Object.values(a).some(v => String(v||"").toLowerCase().includes(q))
    )
    _renderAlertTable(filtered)
}

// =========================================
// SORT ALERTS (client-side)
// =========================================

function sortAlerts(sortType){
    if(!sortType || !_allAlerts.length) return
    const sev = {CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1}
    const sorted = [..._allAlerts]

    if(sortType==="latest")   sorted.sort((a,b)=> (b.timestamp||"").localeCompare(a.timestamp||""))
    if(sortType==="oldest")   sorted.sort((a,b)=> (a.timestamp||"").localeCompare(b.timestamp||""))
    if(sortType==="severity") sorted.sort((a,b)=> (sev[(b.severity||"").toUpperCase()]||0) - (sev[(a.severity||"").toUpperCase()]||0))
    if(sortType==="name")     sorted.sort((a,b)=> (a.type||"").localeCompare(b.type||""))

    _renderAlertTable(sorted)
}

// =========================================
// SCAN POPUP
// =========================================

function _showScanPopup(){
    let popup = document.getElementById("scanPopup")
    if(!popup){
        popup = document.createElement("div")
        popup.id = "scanPopup"
        popup.style.cssText = `
            position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
            background:#0d1f2d;border:2px solid #1e4d6b;border-radius:12px;
            padding:28px 32px;width:460px;max-width:95vw;z-index:9999;
            box-shadow:0 8px 40px rgba(0,0,0,0.7);color:#fff;font-family:inherit`
        document.body.appendChild(popup)
    }
    popup.innerHTML = `
        <div style="font-size:18px;font-weight:700;margin-bottom:12px">
            🔍 Full Scan Running
        </div>
        <div style="font-size:28px;font-weight:900;color:#2f6bff;margin-bottom:14px" id="scanTimer">00:00</div>
        <div id="scanPhaseLog" style="font-size:13px;line-height:1.8;max-height:200px;overflow-y:auto;
            background:#0a1520;border-radius:8px;padding:10px 14px;color:#a0c8e8"></div>
        <div style="margin-top:14px;color:#5a8a9f;font-size:12px">Do not close this window</div>
    `
    popup.style.display = "block"
    return popup
}

function _hideScanPopup(){
    const p = document.getElementById("scanPopup")
    if(p) p.style.display = "none"
}

function _addPhaseLog(msg){
    const log = document.getElementById("scanPhaseLog")
    if(!log) return
    const line = document.createElement("div")
    line.textContent = `▶ ${msg}`
    log.appendChild(line)
    log.scrollTop = log.scrollHeight
}

// =========================================
// RUN FULL SCAN
// =========================================

async function runFullScan(){

    // Enforce time filter selection
    const filterEl = document.getElementById("timeFilter")
    const filterVal = filterEl?.value || ""
    if(!filterVal || filterVal === "select"){
        _showTimeFilterWarning()
        return
    }

    if(window.scanRunning) return
    window.scanRunning = true

    const btn = document.getElementById("fullScanBtn")
    if(btn){ btn.disabled=true; btn.innerText="Scanning..." }

    const popup = _showScanPopup()

    // Timer
    let elapsed = 0
    const timerInterval = setInterval(()=>{
        elapsed++
        const m = String(Math.floor(elapsed/60)).padStart(2,"0")
        const s = String(elapsed%60).padStart(2,"0")
        const el = document.getElementById("scanTimer")
        if(el) el.textContent = `${m}:${s}`
    }, 1000)

    _addPhaseLog("Initiating full scan...")

    try{
        const resp = await fetch("/api/run-scan", {method:"POST"})
        const start = await resp.json()
        if(start.status==="already_running"){
            _addPhaseLog("Scan already in progress, monitoring...")
        }else{
            _addPhaseLog("Scan started in background")
        }

        const maxWait = 20 * 60 * 1000
        const pollStart = Date.now()

        await new Promise((resolve)=>{
            const poll = async()=>{
                try{
                    const sr = await fetch("/api/scan-status")
                    const st = await sr.json()

                    if(btn && st.running){
                        btn.innerText = `Scanning... (${st.total_alerts} alerts)`
                        if(st.phase) _addPhaseLog(st.phase)
                    }

                    if(!st.running && st.completed_at){
                        _scanHasRun = true
                        _addPhaseLog(`✅ Scan complete — ${st.total_alerts} alerts detected`)
                        const el = document.getElementById("lastScan")
                        if(el) el.innerHTML = "FULL SCAN<br>"+st.completed_at.replace("T"," ").slice(0,19)
                        const fsBtn = document.getElementById("fullScanBtn")
                        if(fsBtn){
                            fsBtn.disabled = true
                            fsBtn.style.opacity = "0.5"
                            fsBtn.title = "Click Reset to run a new scan"
                            fsBtn.innerHTML = `Scan Done ✓ <img src="/static/icons-W/scan.png" class="theme-icon">`
                        }
                        resolve(); return
                    }

                    if(Date.now()-pollStart > maxWait){ resolve(); return }
                    setTimeout(poll, 3000)
                }catch(e){ setTimeout(poll, 3000) }
            }
            setTimeout(poll, 3000)
        })

        await loadDashboardData()

    }catch(error){
        console.error("Scan error:", error)
        _addPhaseLog("❌ Scan error — check console")
        try{ await loadDashboardData() }catch(e){}
    }finally{
        clearInterval(timerInterval)
        window.scanRunning = false
        if(!_scanHasRun && btn){
            btn.disabled = false
            btn.style.opacity = "1"
            btn.innerHTML = `Run Full Scan <img src="/static/icons-W/scan.png" class="theme-icon">`
        }
        setTimeout(_hideScanPopup, 2000)
    }
}

// =========================================
// TIME FILTER WARNING POPUP
// =========================================

function _showTimeFilterWarning(){
    let w = document.getElementById("timeFilterWarning")
    if(!w){
        w = document.createElement("div")
        w.id = "timeFilterWarning"
        w.style.cssText = `
            position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
            background:#0d1f2d;border:2px solid #ff3b30;border-radius:12px;
            padding:28px 32px;width:360px;z-index:9999;color:#fff;
            box-shadow:0 8px 40px rgba(0,0,0,0.7);text-align:center;font-family:inherit`
        document.body.appendChild(w)
    }
    w.innerHTML = `
        <div style="font-size:22px;margin-bottom:10px">⚠️</div>
        <div style="font-size:16px;font-weight:700;margin-bottom:8px">Select Time Duration First</div>
        <div style="font-size:13px;color:#a0c8e8;margin-bottom:18px">
            Please choose a time range before running the scan.
        </div>
        <button onclick="document.getElementById('timeFilterWarning').style.display='none'"
            style="background:#1e4d6b;color:#fff;border:none;border-radius:8px;
            padding:8px 24px;cursor:pointer;font-size:14px">OK</button>
    `
    w.style.display = "block"
}

// =========================================
// REFRESH BUTTON
// =========================================

async function refreshDashboard(){
    if(!_scanHasRun){
        _showToast("⚠️ Run a Full Scan first before refreshing.")
        return
    }
    const btn = document.querySelector(".action-btn[onclick='refreshDashboard()']")
    if(btn){ btn.disabled=true; btn.innerText="Refreshing..." }

    try{
        // Trigger background collection of new events
        await fetch("/api/refresh", {method:"POST"})
        _showToast("🔄 Collecting new events...")

        // Wait for collection to finish (max 30s, check every 2s)
        let waited = 0
        while(waited < 30){
            await new Promise(r => setTimeout(r, 2000))
            waited += 2
            try{
                const st = await (await fetch("/api/scan-status")).json()
                if(!st.running){
                    // Done — reload data
                    const filter = document.getElementById("timeFilter")?.value || "24h"
                    const data = await (await fetch(`/api/chart-data?range=${filter}&_=${Date.now()}`)).json()
                    _applyDashboardData(data)

                    // Update Last Scan card to show REFRESH
                    const el = document.getElementById("lastScan")
                    const now = new Date().toISOString().replace("T"," ").slice(0,19)
                    if(el) el.innerHTML = `REFRESH<br>${now}`

                    const total = data.total_alerts || 0
                    _showToast(`✅ Refresh complete — ${total} alerts in dashboard`)
                    break
                }
            }catch(_){}
        }
    }catch(e){
        console.error("Refresh failed:",e)
        _showToast("❌ Refresh failed")
        // Reload anyway
        try{ await loadDashboardData() }catch(_){}
    }finally{
        if(btn){
            btn.disabled=false
            btn.innerHTML=`Refresh <img src="/static/icons-W/refresh.png" class="theme-icon">`
        }
    }
}


// =========================================
// RESET DASHBOARD
// =========================================

async function resetDashboard(){
    if(!confirm("Reset will clear ALL alerts and re-enable Full Scan.\nAre you sure?")) return
    const btn = document.getElementById("resetBtn")
    if(btn){ btn.disabled=true; btn.innerText="Resetting..." }
    try{
        const res  = await fetch("/api/reset", {method:"POST"})
        const data = await res.json()
        if(data.status === "success"){
            _scanHasRun = false
            _allAlerts  = []
            const tbody = document.getElementById("alertTableBody")
            if(tbody) tbody.innerHTML = ""
            const empty = document.getElementById("emptyAlertState")
            if(empty) empty.style.display = "flex"
            ;["totalAlerts","lowCount","mediumCount","highCount","criticalCount"]
                .forEach(id => { const el=document.getElementById(id); if(el) el.innerText="0" })
            const ls = document.getElementById("lastScan")
            if(ls) ls.innerHTML = "NONE<br>N/A"
            if(donutChart){
                donutChart.data.labels = ["No data yet"]
                donutChart.data.datasets[0].data            = [1]
                donutChart.data.datasets[0].backgroundColor = ["#2a4a6a"]
                donutChart.data.datasets[0].borderColor     = ["#3a6a9a"]
                donutChart.data.datasets[0].borderWidth     = 3
                donutChart.update()
            }
            if(barChart){
                barChart.data.datasets[0].data = new Array(BAR_LABELS.length).fill(0)
                barChart.update()
            }
            const fsBtn = document.getElementById("fullScanBtn")
            if(fsBtn){
                fsBtn.disabled = false
                fsBtn.style.opacity = "1"
                fsBtn.title = ""
                fsBtn.innerHTML = `Run Full Scan <img src="/static/icons-W/scan.png" class="theme-icon">`
            }
            _showToast("✅ Dashboard reset — ready for fresh scan")
        }
    }catch(e){
        _showToast("❌ Reset failed")
    }finally{
        if(btn){
            btn.disabled=false
            btn.innerHTML=`Reset <img src="/static/icons-W/refresh.png" class="theme-icon">`
        }
    }
}

// =========================================
// APPLY TIME FILTER
// =========================================

async function applyTimeFilter(){
    const filterEl = document.getElementById("timeFilter")
    const val = filterEl?.value || "24h"
    if(!val || val==="select") return
    try{
        const resp = await fetch(`/api/chart-data?range=${val}&_=${Date.now()}`)
        const data = await resp.json()
        _applyDashboardData(data)
    }catch(e){ console.error("Time filter failed:",e) }
}

// =========================================
// SAVE TO FORENSICS
// =========================================

async function saveForensics(){
    const btn = document.querySelector(".action-btn[onclick='saveForensics()']")
    if(btn){ btn.disabled=true; btn.innerText="Exporting..." }
    try{
        const resp = await fetch("/api/export-forensics", {method:"POST"})
        const result = await resp.json()
        if(result.status==="success"){
            _showToast(`✅ Forensic export saved: ${result.filename||""}`)
            if(typeof loadSavedFiles==="function") loadSavedFiles()
        }else{
            _showToast("❌ Export failed. Check server logs.")
        }
    }catch(e){
        console.error("Forensics export failed:",e)
        _showToast("❌ Unable to connect to forensic export engine.")
    }finally{
        if(btn){
            btn.disabled=false
            btn.innerHTML=`Save to Forensics <img src="/static/icons-W/download.png" class="theme-icon">`
        }
    }
}

// =========================================
// TOAST NOTIFICATION
// =========================================

function _showToast(msg, duration=4000){
    let t = document.getElementById("socToast")
    if(!t){
        t = document.createElement("div")
        t.id = "socToast"
        t.style.cssText = `
            position:fixed;bottom:28px;right:28px;background:#0d1f2d;
            border:1.5px solid #1e4d6b;border-radius:10px;padding:14px 22px;
            color:#fff;font-size:14px;z-index:9998;box-shadow:0 4px 20px rgba(0,0,0,0.5);
            transition:opacity 0.4s;max-width:360px`
        document.body.appendChild(t)
    }
    t.textContent = msg
    t.style.opacity = "1"
    clearTimeout(t._timeout)
    t._timeout = setTimeout(()=>{ t.style.opacity="0" }, duration)
}

// =========================================
// THREAT HUNT (legacy compatible)
// =========================================

async function huntThreats(){
    _filterTable()
}

// =========================================
// LIVE UPDATE (websocket fallback)
// =========================================

async function liveUpdate(){
    try{ await loadDashboardData() }
    catch(e){ console.error("Live update failed:",e) }
}

// =========================================
// WEBSOCKET
// =========================================

const socket = new WebSocket(
    `${window.location.protocol==="https:"?"wss":"ws"}://${window.location.host}/ws`
)
socket.onopen  = ()=>{ console.log("[SOC] WebSocket Connected"); socket.send("connect") }
socket.onmessage = async(event)=>{
    try{
        const data = JSON.parse(event.data)
        if(data.type==="NEW_ALERTS") await loadDashboardData()
    }catch(e){}
}
socket.onclose = ()=> console.log("[SOC] WebSocket Closed")

// =========================================
// LOAD SYSTEM INFO
// =========================================

async function loadSystemInfo(){
    try{
        const resp = await fetch("/api/system-info")
        const data = await resp.json()
        const s = (id,v)=>{ const el=document.getElementById(id); if(el) el.innerText=v }
        s("systemOS",    data.os)
        s("systemIP",    data.ip)
        s("systemHost",  data.hostname)
        s("memoryPercent", data.memory_percent+"%")
        s("diskPercent",   data.disk_percent+"%")
        const mf = document.getElementById("memoryFill")
        if(mf) mf.style.width = data.memory_percent+"%"
        const dc = document.getElementById("diskCircle")
        if(dc) dc.style.background = `conic-gradient(#2f6bff ${data.disk_percent*3.6}deg, #1a2f40 0deg)`
    }catch(e){ console.error("System info error:",e) }
}

// =========================================
// PAGE NAVIGATION
// =========================================

function toggleSidebar(){
    const sb = document.getElementById("sidebar")
    const ca = document.querySelector(".content-area")
    if(sb) sb.classList.toggle("expanded")
    if(ca) ca.classList.toggle("expanded")
}

function showPage(pageId){
    document.querySelectorAll(".page-section").forEach(p=>p.style.display="none")
    const target = document.getElementById(pageId)
    if(target) target.style.display="block"
    document.querySelectorAll(".sidebar-btn").forEach(b=>b.classList.remove("active"))
    if(event?.currentTarget) event.currentTarget.classList.add("active")

    // Check Ollama status when Investigation page opens
    if(pageId === "investigationPage" && typeof checkOllamaStatus === "function"){
        checkOllamaStatus()
    }
}

// =========================================
// THEME TOGGLE
// =========================================

function toggleTheme(){
    document.body.classList.toggle("light-mode")
    const isLight = document.body.classList.contains("light-mode")
    localStorage.setItem("soc_theme", isLight?"light":"dark")
    updateChartsTheme()
}

function updateChartsTheme(){
    const isLight = document.body.classList.contains("light-mode")

    // Axis labels and legend text
    const axisColor  = isLight ? "#0d1f2d" : "#ffffff"
    // Grid lines
    const gridColor  = isLight ? "rgba(0,0,0,0.10)" : "rgba(255,255,255,0.08)"
    if(!barChart || !donutChart) return

    // ── Bar chart ────────────────────────────────────────
    barChart.options.scales.x.ticks.color         = axisColor
    barChart.options.scales.y.ticks.color         = axisColor
    barChart.options.scales.x.grid.color          = gridColor
    barChart.options.scales.y.grid.color          = gridColor
    barChart.options.plugins.legend.labels.color  = axisColor

    // In light mode give bars a dark border so they're visible
    // against the light background
    barChart.data.datasets[0].borderColor =
        isLight
        ? ["#3a5abf","#6b4fa8","#b07b2a","#c4a030","#b04040",
           "#a04ab0","#3aadad","#5a9030","#78a020","#908a10",
           "#3a6070","#c07840","#b09070","#b08878"]
        : barChart.data.datasets[0].backgroundColor
    barChart.data.datasets[0].borderWidth = isLight ? 2 : 0

    barChart.update()

    // ── Donut chart ──────────────────────────────────────
    donutChart.options.plugins.legend.labels.color = axisColor

    // Make legend colour boxes readable in light mode
    donutChart.options.plugins.legend.labels.boxWidth  = 18
    donutChart.options.plugins.legend.labels.padding   = 16
    donutChart.options.plugins.legend.labels.font      = {
        size: 13, weight: "700"
    }

    donutChart.update()

    // Panel backgrounds + headings handled by CSS only
    // (body.light-mode .donut-panel / .bar-panel in style.css)
    // Never set inline styles here — they override dark mode CSS
    // permanently and get stuck when switching themes.
}

// =========================================
// PAGE LOAD — INIT
// =========================================

window.onload = async()=>{

    // Restore theme
    if(localStorage.getItem("soc_theme")==="light")
        document.body.classList.add("light-mode")

    // Detect theme BEFORE creating charts so the very first
    // painted frame uses correct colours — not hardcoded white.
    const _initLight   = document.body.classList.contains("light-mode")
    const _initAxis    = _initLight ? "#0d1f2d" : "#ffffff"
    const _initGrid    = _initLight ? "rgba(0,0,0,0.10)" : "rgba(255,255,255,0.08)"

    // Init donut chart
    donutChart = new Chart(document.getElementById("donutChart"),{
        type:"doughnut",
        data:{
            labels:["LOW","MEDIUM","HIGH","CRITICAL"],
            datasets:[{
                data:[0,0,0,0],
                backgroundColor:["#55d800","#2f6bff","#ffd21f","#ff3b30"],
                borderWidth:2,
                borderColor:"rgba(0,0,0,0)"
            }]
        },
        options:{
            responsive:true,
            maintainAspectRatio:false,
            cutout:"62%",
            plugins:{
                legend:{
                    display:true,
                    position:"bottom",
                    labels:{
                        color:_initAxis,
                        font:{size:13,weight:"700"},
                        usePointStyle:true,
                        pointStyle:"rectRounded",
                        boxWidth:14,
                        boxHeight:14,
                        padding:16
                    }
                },
                tooltip:{
                    callbacks:{
                        label: function(ctx){
                            const total = ctx.dataset.data.reduce((a,b)=>a+b,0)
                            const pct = total>0 ? Math.round(ctx.parsed/total*100) : 0
                            return ` ${ctx.label}: ${ctx.parsed} (${pct}%)`
                        }
                    }
                }
            }
        }
    })

    // Init bar chart
    barChart = new Chart(document.getElementById("barChart"),{
        type:"bar",
        data:{
            labels:BAR_LABELS,
            datasets:[{
                data:new Array(BAR_LABELS.length).fill(0),
                borderRadius:6,
                backgroundColor:["#4d79ff","#8e6ad8","#d9a64f","#f2cf5b","#d46a6a",
                    "#cf6ad8","#5fd4d4","#78b84c","#9dbf46","#b7b22d",
                    "#4e7f90","#f2aa66","#d9b6a3","#dcb3a8"]
            }]
        },
        options:{
            responsive:true, maintainAspectRatio:false,
            layout:{padding:{top:10,left:10,right:10,bottom:-10}},
            plugins:{legend:{display:false}},
            scales:{
                x:{
                    ticks:{color:_initAxis,autoSkip:false,maxRotation:45,minRotation:45,padding:8,font:{size:12,weight:"700"}},
                    grid:{color:_initGrid},border:{display:false}
                },
                y:{
                    beginAtZero:true, suggestedMax:10,
                    ticks:{display:true,color:_initAxis,padding:8,font:{size:13,weight:"700"}},
                    grid:{color:_initGrid},border:{display:false}
                }
            }
        }
    })

    // Wire up search input
    const searchInput = document.getElementById("dashboardSearchInput")
    if(searchInput){
        searchInput.addEventListener("keyup", _filterTable)
        searchInput.addEventListener("input", _filterTable)
    }

    // timeFilter defaults to "24h" via the HTML selected attribute.
    // No JS override needed — removing it prevents stale value conflicts.

    // Load data
    await loadDashboardData()

    // Force Chart.js to re-measure containers after data load.
    // On first paint the wrapper may have been zero-height;
    // resize() triggers a fresh layout calculation.
    donutChart.resize()
    barChart.resize()
    donutChart.update()
    barChart.update()

    // Apply theme colours before final update so the first
    // visible frame is already correct — not a flash of white
    updateChartsTheme()

    await loadSystemInfo()
    setInterval(loadSystemInfo, 5000)

    // Re-measure on window resize so charts never get clipped
    window.addEventListener("resize", ()=>{
        donutChart.resize()
        barChart.resize()
    })
}


// =========================================
// FEATURE 2: ALERT QUEUE REFRESH BUTTON
// Only reloads the alert table, not the
// entire dashboard — fast and targeted
// =========================================

async function refreshAlertQueue(){
    const btn = document.querySelector(".alert-queue-refresh-btn")
    if(btn){ btn.style.opacity="0.5"; btn.textContent="↻ ..." }

    try{
        const filter = document.getElementById("timeFilter")?.value || "24h"
        const resp   = await fetch(`/api/chart-data?range=${filter}&_=${Date.now()}`)
        const data   = await resp.json()
        // Only update the alert table, not charts/counters
        _renderAlertTable(data.alerts || [])

        const count = (data.alerts || []).length
        _showToast(`✅ Alert queue refreshed — ${count} alerts`)
    }catch(e){
        console.error("refreshAlertQueue error:", e)
        _showToast("❌ Alert queue refresh failed")
    }finally{
        if(btn){ btn.style.opacity="1"; btn.textContent="↻" }
    }
}


// =========================================
// FEATURE 3: GROUPED SAVED FILES
// Handled server-side — see dashboard_api.py
// JS only renders — grouping by timestamp prefix
// =========================================
// (Implemented in the saved files page JS)


// =========================================
// FEATURE 6: FLOATING TERMINAL BUTTON
// Replaces the sidebar terminal button.
// Draggable, always on top, minimize/maximize.
// =========================================

function _createFloatingTerminalBtn(){
    // Remove any existing button
    const existing = document.getElementById("floatingTerminalBtn")
    if(existing) existing.remove()

    const btn = document.createElement("div")
    btn.id = "floatingTerminalBtn"
    btn.innerHTML = `
        <span class="ftb-dot"></span>
        <span class="ftb-label">Terminal</span>
    `
    btn.style.cssText = `
        position: fixed;
        bottom: 24px;
        right: 24px;
        z-index: 8000;
        background: rgba(13,31,45,0.95);
        border: 1.5px solid #1e4d6b;
        border-radius: 24px;
        padding: 10px 18px;
        display: flex;
        align-items: center;
        gap: 8px;
        cursor: pointer;
        font-size: 13px;
        font-weight: 700;
        color: #5fd4d4;
        box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        user-select: none;
        transition: border-color 0.2s, box-shadow 0.2s;
        backdrop-filter: blur(8px);
    `

    // Pulse dot
    const style = document.createElement("style")
    style.textContent = `
        #floatingTerminalBtn .ftb-dot {
            width: 8px; height: 8px;
            border-radius: 50%;
            background: #5fd4d4;
            animation: ftbPulse 2s infinite;
        }
        @keyframes ftbPulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.5;transform:scale(0.8)} }
        #floatingTerminalBtn:hover {
            border-color: #5fd4d4;
            box-shadow: 0 4px 20px rgba(95,212,212,0.2);
        }
        #floatingTerminalBtn.terminal-active {
            background: rgba(95,212,212,0.1);
            border-color: #5fd4d4;
        }
    `
    document.head.appendChild(style)

    // Click to toggle terminal
    btn.addEventListener("click", (e) => {
        if(!e.target.closest("#floatingTerminalBtn")) return
        SOCConsole.toggle()
        btn.classList.toggle("terminal-active")
    })

    // Drag to reposition
    let dragging = false, startX, startY, startRight, startBottom

    btn.addEventListener("mousedown", (e) => {
        dragging = true
        startX = e.clientX
        startY = e.clientY
        const rect = btn.getBoundingClientRect()
        startRight  = window.innerWidth  - rect.right
        startBottom = window.innerHeight - rect.bottom
        btn.style.transition = "none"
        e.preventDefault()
    })

    document.addEventListener("mousemove", (e) => {
        if(!dragging) return
        const dx = e.clientX - startX
        const dy = e.clientY - startY
        const newRight  = Math.max(8, startRight  - dx)
        const newBottom = Math.max(8, startBottom - dy)
        btn.style.right  = newRight  + "px"
        btn.style.bottom = newBottom + "px"
    })

    document.addEventListener("mouseup", () => {
        if(dragging){
            dragging = false
            btn.style.transition = "border-color 0.2s, box-shadow 0.2s"
        }
    })

    document.body.appendChild(btn)
}


// =========================================
// CALL INIT FUNCTIONS ON LOAD
// =========================================

// These run after window.onload is already defined
// We patch into window.onload
const _origOnload = window.onload
window.onload = async function(){
    if(_origOnload) await _origOnload()

    // Feature 1: header user
    await loadHeaderUser()

    // Feature 6: floating terminal button
    _createFloatingTerminalBtn()
}


// =========================================
// ROLE-BASED ACCESS CONTROL
// Enforces permissions based on logged-in
// user role stored in localStorage.
// Called once on page load.
// =========================================

const ROLE_PERMISSIONS = {
    admin: {
        canScan:        true,
        canRefresh:     true,
        canReset:       true,
        canExport:      true,
        canInvestigate: true,
        canEditRules:   true,
        canManageUsers: true,
        canSettings:    true,
        hiddenPages:    [],
    },
    analyst: {
        canScan:        true,
        canRefresh:     true,
        canReset:       false,
        canExport:      true,
        canInvestigate: true,
        canEditRules:   false,
        canManageUsers: false,
        canSettings:    false,
        hiddenPages:    [],       // can see all pages, just limited actions
    },
    viewer: {
        canScan:        false,
        canRefresh:     false,
        canReset:       false,
        canExport:      false,
        canInvestigate: false,
        canEditRules:   false,
        canManageUsers: false,
        canSettings:    false,
        hiddenPages:    ["investigationPage", "savedFilesPage", "settingsPage"],
    },
}

function applyRBAC(){
    const role  = (localStorage.getItem("soc_role") || "admin").toLowerCase()
    const perms = ROLE_PERMISSIONS[role] || ROLE_PERMISSIONS["admin"]

    // ── Scan button ──────────────────────────
    const scanBtn = document.getElementById("fullScanBtn")
    if(scanBtn && !perms.canScan){
        scanBtn.disabled = true
        scanBtn.title    = "Your role does not have scan permission"
        scanBtn.style.opacity = "0.4"
        scanBtn.style.cursor  = "not-allowed"
    }

    // ── Refresh button ───────────────────────
    const refreshBtn = document.querySelector(".action-btn[onclick='refreshDashboard()']")
    if(refreshBtn && !perms.canRefresh){
        refreshBtn.disabled = true
        refreshBtn.title    = "Your role does not have refresh permission"
        refreshBtn.style.opacity = "0.4"
    }

    // ── Reset button ─────────────────────────
    const resetBtn = document.getElementById("resetBtn")
    if(resetBtn && !perms.canReset){
        resetBtn.disabled = true
        resetBtn.title    = "Admin only"
        resetBtn.style.opacity = "0.4"
        resetBtn.style.cursor  = "not-allowed"
    }

    // ── Save to Forensics ────────────────────
    const exportBtn = document.querySelector(".action-btn[onclick='saveForensics()']")
    if(exportBtn && !perms.canExport){
        exportBtn.disabled = true
        exportBtn.title    = "Your role cannot export data"
        exportBtn.style.opacity = "0.4"
    }

    // ── Sidebar: hide pages viewer can't access ──
    if(perms.hiddenPages.length > 0){
        document.querySelectorAll(".sidebar-btn").forEach(btn => {
            const onclick = btn.getAttribute("onclick") || ""
            perms.hiddenPages.forEach(pageId => {
                if(onclick.includes(pageId)){
                    btn.style.display = "none"
                }
            })
        })
    }

    // ── Settings: hide admin-only section ────
    if(!perms.canManageUsers){
        const adminSection = document.getElementById("admin-management-section")
        if(adminSection) adminSection.style.display = "none"
    }

    // ── Show role banner if not admin ────────
    if(role !== "admin"){
        _showRoleBanner(role, perms)
    }

    console.log(`[RBAC] Role: ${role} | Permissions applied`)
}


function _showRoleBanner(role, perms){
    const existing = document.getElementById("rbacBanner")
    if(existing) return   // already shown

    const roleColors = { analyst: "#ffd21f", viewer: "#55d800" }
    const color = roleColors[role] || "#5a8a9f"

    const restrictions = []
    if(!perms.canScan)        restrictions.push("Run Scan")
    if(!perms.canReset)       restrictions.push("Reset")
    if(!perms.canExport)      restrictions.push("Export")
    if(!perms.canInvestigate) restrictions.push("AI Investigate")
    if(!perms.canEditRules)   restrictions.push("Edit Rules")

    const banner = document.createElement("div")
    banner.id = "rbacBanner"
    banner.style.cssText = `
        position: fixed;
        top: 92px;
        left: 0;
        right: 0;
        z-index: 900;
        background: ${color}18;
        border-bottom: 1px solid ${color}44;
        padding: 8px 24px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        font-size: 13px;
        font-weight: 600;
        color: ${color};
    `
    banner.innerHTML = `
        <span>
            🔒 Logged in as <strong>${role.toUpperCase()}</strong>
            ${restrictions.length
                ? ` — Restricted: ${restrictions.join(", ")}`
                : " — Full access"}
        </span>
        <button onclick="document.getElementById('rbacBanner').style.display='none'"
            style="background:none;border:none;color:${color};cursor:pointer;
            font-size:16px;padding:0 4px">✕</button>
    `
    document.body.appendChild(banner)

    // Push content area down
    const content = document.querySelector(".content-area")
    if(content){
        const currentTop = parseInt(getComputedStyle(content).paddingTop) || 0
        content.style.paddingTop = (currentTop + 36) + "px"
    }
}


// =========================================
// ALSO STORE USER INFO ON /api/auth/me
// Called from loadHeaderUser — stores role
// in localStorage so RBAC works next visit
// =========================================

async function loadHeaderUser(){
    try{
        let username    = localStorage.getItem("soc_username")    || "Admin"
        let displayName = localStorage.getItem("soc_display_name")|| username
        let role        = localStorage.getItem("soc_role")        || "admin"

        // Fetch from API to get current session role
        try{
            const resp = await fetch("/api/auth/me")
            if(resp.ok){
                const data = await resp.json()
                if(data.username)     { username    = data.username;     localStorage.setItem("soc_username", username) }
                if(data.role)         { role        = data.role;         localStorage.setItem("soc_role", role) }
                if(data.display_name) { displayName = data.display_name; localStorage.setItem("soc_display_name", displayName) }
            }
        }catch(_){}

        const nameEl   = document.getElementById("headerUserName")
        const roleEl   = document.getElementById("headerUserRole")
        const avatarEl = document.getElementById("headerUserAvatar")

        if(nameEl)   nameEl.textContent   = displayName
        if(roleEl)   roleEl.textContent   = role.toUpperCase()
        if(avatarEl) avatarEl.textContent = displayName[0].toUpperCase()

        const colors = {admin:"#ff3b30", analyst:"#ffd21f", viewer:"#55d800"}
        const color  = colors[role] || "#2f6bff"
        if(avatarEl){
            avatarEl.style.background = color + "33"
            avatarEl.style.color      = color
            avatarEl.style.border     = `2px solid ${color}55`
        }
        if(roleEl) roleEl.style.color = color

        // Apply RBAC after user info is loaded
        applyRBAC()

    }catch(e){ console.error("loadHeaderUser error:", e) }
}