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
    // Always use real severity colours — no fake placeholder data
    donutChart.data.datasets[0].data = donutValues
    donutChart.data.datasets[0].backgroundColor = ["#55d800","#2f6bff","#ffd21f","#ff3b30"]
    donutChart.update()
    const dw = document.querySelector(".donut-wrapper")
    if(dw) dw.classList.toggle("has-data", total>0)

    // --- Bar chart ---
    const cats = data.categories || {}
    barChart.data.labels = BAR_LABELS
    const othersTotal = Object.entries(cats).filter(([k])=>!BAR_LABELS.slice(0,-1).includes(k)).reduce((s,[,v])=>s+v,0)
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
            <td>${a.id||"-"}</td>
            <td>${(a.timestamp||"-").replace("T"," ").slice(0,19)}</td>
            <td>${a.type||"-"}</td>
            <td>${_severityBadge(a.severity)}</td>
            <td>${a.category||"-"}</td>
            <td class="alert-desc-cell">${a.description||"-"}</td>
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
                        _addPhaseLog(`✅ Scan complete — ${st.total_alerts} alerts detected`)
                        const el = document.getElementById("lastScan")
                        if(el) el.innerHTML = "FULL SCAN<br>"+st.completed_at.replace("T"," ").slice(0,19)
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
        if(btn){
            btn.disabled=false
            btn.innerHTML=`Run Full Scan <img src="/static/icons-W/scan.png" class="theme-icon">`
        }
        // Keep popup visible for 2s so user can read result
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
    const btn = document.querySelector(".action-btn[onclick='refreshDashboard()']")
    if(btn){ btn.disabled=true; btn.innerText="Refreshing..." }
    try{
        await loadDashboardData()
    }catch(e){ console.error("Refresh failed:",e) }
    finally{
        if(btn){
            btn.disabled=false
            btn.innerHTML=`Refresh <img src="/static/icons-W/refresh.png" class="theme-icon">`
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
    const axisColor = isLight?"#081b30":"#ffffff"
    const gridColor = isLight?"rgba(0,0,0,0.08)":"rgba(255,255,255,0.08)"
    if(!barChart || !donutChart) return
    barChart.options.scales.x.ticks.color  = axisColor
    barChart.options.scales.y.ticks.color  = axisColor
    barChart.options.scales.x.grid.color   = gridColor
    barChart.options.scales.y.grid.color   = gridColor
    barChart.options.plugins.legend.labels.color = axisColor
    barChart.update()
    donutChart.options.plugins.legend.labels.color = axisColor
    donutChart.update()
}

// =========================================
// PAGE LOAD — INIT
// =========================================

window.onload = async()=>{

    // Restore theme
    if(localStorage.getItem("soc_theme")==="light")
        document.body.classList.add("light-mode")

    // Init donut chart — colours tied to severity labels, legend derived automatically by Chart.js
    donutChart = new Chart(document.getElementById("donutChart"),{
        type:"doughnut",
        data:{
            labels:["LOW","MEDIUM","HIGH","CRITICAL"],
            datasets:[{data:[0,0,0,0],backgroundColor:["#55d800","#2f6bff","#ffd21f","#ff3b30"],borderWidth:1}]
        },
        options:{
            responsive:true, maintainAspectRatio:false,
            plugins:{legend:{display:true,labels:{color:"#ffffff",font:{size:14,weight:"700"}}}}
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
                    ticks:{color:"#fff",autoSkip:false,maxRotation:45,minRotation:45,padding:8,font:{size:12,weight:"700"}},
                    grid:{color:"rgba(255,255,255,0.08)"},border:{display:false}
                },
                y:{
                    beginAtZero:true, suggestedMax:10,
                    ticks:{display:true,color:"#fff",padding:8,font:{size:13,weight:"700"}},
                    grid:{color:"rgba(255,255,255,0.08)"},border:{display:false}
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

    // Set default timeFilter to 7d so existing alerts are always visible
    const tf = document.getElementById("timeFilter")
    if(tf && (!tf.value || tf.value==="select")) tf.value = "7d"

    // Load data
    await loadDashboardData()
    donutChart.update()
    barChart.update()
    await loadSystemInfo()
    setInterval(loadSystemInfo, 5000)

    updateChartsTheme()
}