// =========================================
// INVESTIGATION CENTER
// =========================================

let _currentInvestigation = null
let _currentAlertIds      = null

// Check Ollama status on load
async function checkOllamaStatus(){
    try{
        const resp = await fetch("/api/investigate/ollama-status")
        const data = await resp.json()
        const badge = document.getElementById("ollamaStatusBadge")
        if(!badge) return
        if(data.available && data.models && data.models.length > 0){
            badge.className = "ollama-badge online"
            badge.innerHTML = `<span class="badge-dot"></span>
                <span class="badge-text">Ollama ✓ (${data.models[0]})</span>`
        } else {
            badge.className = "ollama-badge offline"
            badge.innerHTML = `<span class="badge-dot"></span>
                <span class="badge-text">Ollama offline — rule-based fallback active</span>`
        }
    }catch(e){
        const badge = document.getElementById("ollamaStatusBadge")
        if(badge){
            badge.className = "ollama-badge offline"
            badge.innerHTML = `<span class="badge-dot"></span>
                <span class="badge-text">Rule-based fallback active</span>`
        }
    }
}

function _investModeChange(){
    const mode = document.getElementById("investMode")?.value
    document.getElementById("investSeverityGroup").style.display = mode==="severity" ? "flex" : "none"
    document.getElementById("investCategoryGroup").style.display = mode==="category" ? "flex" : "none"
    document.getElementById("investIdsGroup").style.display      = mode==="ids"      ? "flex" : "none"
}

async function runInvestigation(){
    const btn = document.getElementById("investRunBtn")
    if(btn) btn.disabled = true

    document.getElementById("investResults").style.display = "none"
    document.getElementById("investEmpty").style.display   = "none"
    document.getElementById("investLoading").style.display = "flex"

    const mode    = document.getElementById("investMode")?.value || "all"
    const context = document.getElementById("investContext")?.value || ""

    const body = { context }

    if(mode === "severity"){
        body.severity = document.getElementById("investSeverity")?.value || "CRITICAL"
    } else if(mode === "category"){
        body.category = document.getElementById("investCategory")?.value
    } else if(mode === "ids"){
        const raw = document.getElementById("investIds")?.value || ""
        const ids = raw.split(",").map(s=>parseInt(s.trim())).filter(n=>!isNaN(n))
        if(!ids.length){
            _showInvestError("Please enter at least one alert ID")
            if(btn) btn.disabled = false
            return
        }
        body.alert_ids = ids
        _currentAlertIds = ids
    } else {
        body.limit = 50
    }

    try{
        const loadingText = document.getElementById("investLoadingText")
        if(loadingText) loadingText.textContent = "Analysing alerts... (Ollama may take 30-60s)"

        const resp = await fetch("/api/investigate", {
            method: "POST",
            headers: {"Content-Type":"application/json"},
            body: JSON.stringify(body)
        })
        const data = await resp.json()

        if(data.error){
            _showInvestError(data.error)
            return
        }

        _currentInvestigation = data
        _renderInvestigation(data)

    }catch(e){
        console.error("Investigation error:", e)
        _showInvestError("Investigation failed: " + e.message)
    }finally{
        document.getElementById("investLoading").style.display = "none"
        if(btn) btn.disabled = false
    }
}

function _renderInvestigation(data){
    // Risk score
    const score = data.risk_score || 0
    const level = data.threat_level ||
        (score>=80?"CRITICAL":score>=60?"HIGH":score>=40?"MEDIUM":"LOW")
    const scoreEl = document.getElementById("riskScoreNum")
    if(scoreEl) scoreEl.textContent = score

    const circle = document.getElementById("riskScoreCircle")
    const colors = {CRITICAL:"#ff3b30",HIGH:"#ffd21f",MEDIUM:"#2f6bff",LOW:"#55d800"}
    if(circle) circle.style.borderColor = colors[level] || "#888"

    const levelBadge = document.getElementById("riskLevel")
    if(levelBadge){
        levelBadge.textContent = level
        levelBadge.style.background = colors[level] + "33"
        levelBadge.style.color      = colors[level]
    }

    const phaseEl = document.getElementById("attackPhase")
    if(phaseEl) phaseEl.textContent = `Phase: ${data.attack_phase || "Unknown"}`

    const byEl = document.getElementById("generatedBy")
    if(byEl){
        const isLLM = (data.generated_by||"").includes("ollama")
        byEl.textContent = isLLM
            ? `🤖 AI Analysis (${data.generated_by})`
            : "📋 Rule-based Analysis"
        byEl.style.color = isLLM ? "#55d800" : "#5fd4d4"
    }

    // Alert counts
    const summary = data.alert_summary || {}
    const countsEl = document.getElementById("riskCounts")
    if(countsEl) countsEl.innerHTML = `
        <div class="risk-count-item" style="color:#ff3b30">CRITICAL: ${summary.critical||0}</div>
        <div class="risk-count-item" style="color:#ffd21f">HIGH: ${summary.high||0}</div>
        <div class="risk-count-item" style="color:#2f6bff">MEDIUM: ${summary.medium||0}</div>
        <div class="risk-count-item" style="color:#55d800">LOW: ${summary.low||0}</div>
        <div class="risk-count-item" style="color:#aaa">TOTAL: ${summary.total||0}</div>
    `

    // Summary tab
    const execEl = document.getElementById("execSummary")
    if(execEl) execEl.textContent = data.executive_summary || "No summary available"

    const actionsEl = document.getElementById("immediateActions")
    if(actionsEl){
        const actions = data.immediate_actions || []
        actionsEl.innerHTML = actions.map(a =>
            `<li class="invest-action-item">⚡ ${a}</li>`
        ).join("")
    }

    // Technical tab
    const techEl = document.getElementById("technicalText")
    if(techEl) techEl.textContent = data.technical_assessment || "No assessment available"

    const topTypesEl = document.getElementById("topAlertTypes")
    if(topTypesEl && summary.top_types){
        const entries = Object.entries(summary.top_types).sort((a,b)=>b[1]-a[1])
        topTypesEl.innerHTML = `<h4>Top Alert Types</h4>` +
            entries.map(([type,count]) =>
                `<div class="invest-stat-row">
                    <span>${type}</span>
                    <span class="invest-count-badge">${count}</span>
                </div>`
            ).join("")
    }

    // Attack story tab
    const storyEl = document.getElementById("attackStory")
    if(storyEl) storyEl.textContent = data.attack_story || "No attack story available"

    // MITRE tab
    const mitreEl = document.getElementById("mitreCards")
    if(mitreEl){
        const techniques = data.mitre_techniques || []
        if(techniques.length){
            mitreEl.innerHTML = techniques.map(t => `
                <div class="mitre-card">
                    <div class="mitre-id">${t.id}</div>
                    <div class="mitre-name">${t.name}</div>
                    <div class="mitre-tactic">${t.tactic}</div>
                    ${t.count ? `<div class="mitre-count">${t.count} alert${t.count>1?"s":""}</div>` : ""}
                </div>
            `).join("")
        } else {
            mitreEl.innerHTML = '<div style="color:#5a8a9f;padding:20px">No MITRE techniques mapped for these alerts</div>'
        }
    }

    // Remediation tab
    const remEl = document.getElementById("remediationList")
    if(remEl){
        const steps = data.remediation_steps || []
        remEl.innerHTML = steps.length
            ? steps.map((s,i) => `
                <div class="invest-check-item">
                    <input type="checkbox" id="rem_${i}" class="invest-checkbox">
                    <label for="rem_${i}">${s}</label>
                </div>`).join("")
            : '<div style="color:#5a8a9f">No specific remediation steps available</div>'
    }

    // Beginner tab
    const beginEl = document.getElementById("beginnerText")
    if(beginEl) beginEl.textContent = data.beginner_explanation || "No explanation available"

    // Clear chat history
    const chatEl = document.getElementById("chatHistory")
    if(chatEl) chatEl.innerHTML = ""

    // Show results
    document.getElementById("investResults").style.display = "block"
    document.getElementById("investEmpty").style.display   = "none"

    // Default to summary tab
    showInvestTab("summary", document.querySelector(".invest-tab"))
}

function showInvestTab(tabId, btn){
    document.querySelectorAll(".invest-panel").forEach(p => p.classList.remove("active"))
    document.querySelectorAll(".invest-tab").forEach(b => b.classList.remove("active"))
    const panel = document.getElementById(`tab-${tabId}`)
    if(panel) panel.classList.add("active")
    if(btn) btn.classList.add("active")
}

function _showInvestError(msg){
    document.getElementById("investLoading").style.display = "none"
    document.getElementById("investEmpty").style.display   = "block"
    const emptyEl = document.getElementById("investEmpty")
    if(emptyEl) emptyEl.innerHTML = `
        <div style="font-size:36px;margin-bottom:12px">⚠️</div>
        <div style="font-size:15px;font-weight:600;color:#ff3b30">${msg}</div>
        <div style="font-size:13px;color:#5a8a9f;margin-top:8px">
            Make sure you have run a Full Scan first
        </div>`
}

async function sendChatQuestion(){
    const input = document.getElementById("chatQuestion")
    const q = input?.value?.trim()
    if(!q) return
    input.value = ""

    const chatEl = document.getElementById("chatHistory")
    if(!chatEl) return

    // Add user message
    chatEl.innerHTML += `<div class="chat-msg chat-user"><strong>You:</strong> ${q}</div>`
    chatEl.scrollTop = chatEl.scrollHeight

    try{
        const body = { question: q }
        if(_currentAlertIds) body.alert_ids = _currentAlertIds

        const resp = await fetch("/api/investigate/chat", {
            method: "POST",
            headers: {"Content-Type":"application/json"},
            body: JSON.stringify(body)
        })
        const data = await resp.json()
        const answer = data.answer || "No answer available"
        chatEl.innerHTML += `<div class="chat-msg chat-ai"><strong>🤖 AI:</strong> ${answer}</div>`
        chatEl.scrollTop = chatEl.scrollHeight
    }catch(e){
        chatEl.innerHTML += `<div class="chat-msg chat-error">Error: ${e.message}</div>`
    }
}

// Auto-check Ollama when investigation page loads
setTimeout(checkOllamaStatus, 500)