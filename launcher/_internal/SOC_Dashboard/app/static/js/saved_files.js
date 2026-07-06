/* =========================================
   SAVED INVESTIGATION FILES — saved_files.js
   Phase 3: Full functional rewrite
   - Load all files from all export folders
   - File type icons (JSON, CSV, TXT, PNG, PDF, LOG, PCAP etc.)
   - Open File → browser download
   - Open Folder → reveals folder in OS file manager
   - Search / type filter
   - Empty state with guidance
   - Auto-refresh after forensics export
   ========================================= */

let _sfAllFiles = []

// =========================================
// FILE TYPE ICON + COLOUR
// =========================================

const _FILE_TYPES = {
    JSON:  { icon:"{ }", color:"#f2cf5b", label:"JSON" },
    CSV:   { icon:"📊",  color:"#55d800", label:"CSV"  },
    TXT:   { icon:"📄",  color:"#a0c8e8", label:"TXT"  },
    PDF:   { icon:"📕",  color:"#ff3b30", label:"PDF"  },
    PNG:   { icon:"🖼",  color:"#cf6ad8", label:"PNG"  },
    JPG:   { icon:"🖼",  color:"#cf6ad8", label:"JPG"  },
    LOG:   { icon:"📋",  color:"#5fd4d4", label:"LOG"  },
    EVTX:  { icon:"🪟",  color:"#4d79ff", label:"EVTX" },
    PCAP:  { icon:"🌐",  color:"#8e6ad8", label:"PCAP" },
    DB:    { icon:"🗄",  color:"#d9a64f", label:"DB"   },
    ZIP:   { icon:"🗜",  color:"#d46a6a", label:"ZIP"  },
}

function _fileIcon(type){
    const t = _FILE_TYPES[type] || { icon:"📁", color:"#5a8a9f", label: type||"FILE" }
    return `<div class="file-icon-badge"
        style="background:${t.color}22;color:${t.color};border:1.5px solid ${t.color};
               border-radius:8px;padding:6px 10px;font-size:11px;font-weight:800;
               min-width:46px;text-align:center;letter-spacing:0.5px">
        <div style="font-size:18px;line-height:1">${t.icon}</div>
        <div style="margin-top:2px">${t.label}</div>
    </div>`
}

// =========================================
// LOAD FILES
// =========================================

async function loadSavedFiles(){
    const container = document.querySelector(".saved-files-list")
    if(!container) return

    try{
        container.innerHTML = `<div style="text-align:center;padding:40px;color:#5a8a9f">
            Loading files...</div>`

        const resp = await fetch("/api/saved-files")
        _sfAllFiles = await resp.json()
        _renderSavedFiles(_sfAllFiles)

    }catch(e){
        console.error("loadSavedFiles error:", e)
        container.innerHTML = `<div style="text-align:center;padding:40px;color:#ff6b6b">
            Failed to load files. Check server connection.</div>`
    }
}

// =========================================
// RENDER FILE CARDS
// =========================================

function _renderSavedFiles(files){
    const container = document.querySelector(".saved-files-list")
    if(!container) return

    container.innerHTML = ""

    if(!files || files.length === 0){
        container.innerHTML = `
            <div style="text-align:center;padding:60px 20px;color:#5a8a9f">
                <div style="font-size:48px;margin-bottom:16px">📂</div>
                <div style="font-size:18px;font-weight:700;margin-bottom:8px">No files saved yet</div>
                <div style="font-size:14px;color:#3a6a8f;max-width:400px;margin:0 auto">
                    Run a scan and click <b style="color:#fff">"Save to Forensics"</b> on the
                    dashboard to export alerts, CSV summaries and reports here.
                </div>
            </div>`
        return
    }

    // Group by folder
    const byFolder = {}
    files.forEach(f=>{
        const folder = f.folder || "forensics_exports"
        if(!byFolder[folder]) byFolder[folder] = []
        byFolder[folder].push(f)
    })

    const folderLabels = {
        "forensics_exports": "🛡️ Forensic Exports",
        "Forensic_Logs":     "📋 Forensic Logs",
        "reports":           "📄 Investigation Reports",
    }

    Object.entries(byFolder).forEach(([folder, folderFiles])=>{
        // Folder header
        const header = document.createElement("div")
        header.style.cssText = `display:flex;align-items:center;justify-content:space-between;
            margin:24px 0 12px;padding-bottom:8px;border-bottom:1px solid #1e4d6b`
        header.innerHTML = `
            <span style="font-size:16px;font-weight:700;color:#a0c8e8">
                ${folderLabels[folder]||folder}
                <span style="font-size:12px;color:#5a8a9f;font-weight:400;margin-left:8px">
                    ${folderFiles.length} file${folderFiles.length!==1?"s":""}
                </span>
            </span>
            <button onclick="openFolder('${folder}')"
                style="background:#0d1f2d;border:1.5px solid #1e4d6b;color:#a0c8e8;
                border-radius:8px;padding:6px 16px;cursor:pointer;font-size:12px;
                display:flex;align-items:center;gap:6px">
                📁 Open Folder
            </button>
        `
        container.appendChild(header)

        // File cards
        folderFiles.forEach(file=>{
            const card = document.createElement("div")
            card.className = "saved-file-card"
            card.style.cssText = `display:flex;align-items:center;justify-content:space-between;
                background:#0d1f2d;border:1.5px solid #1e4d6b;border-radius:12px;
                padding:16px 20px;margin-bottom:10px;gap:16px;
                transition:border-color 0.2s`

            card.onmouseenter = ()=> card.style.borderColor="#2f6bff"
            card.onmouseleave = ()=> card.style.borderColor="#1e4d6b"

            card.innerHTML = `
                <div style="display:flex;align-items:center;gap:16px;flex:1;min-width:0">
                    ${_fileIcon(file.type)}
                    <div style="min-width:0">
                        <div style="font-weight:700;font-size:14px;
                            overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
                            max-width:480px" title="${file.filename}">
                            ${file.filename}
                        </div>
                        <div style="font-size:12px;color:#5a8a9f;margin-top:4px">
                            <span style="margin-right:14px">📦 ${file.size}</span>
                            <span>🕐 ${file.saved}</span>
                        </div>
                    </div>
                </div>
                <div style="display:flex;gap:10px;flex-shrink:0">
                    <button onclick="downloadFile('${file.folder}','${file.filename}')"
                        style="background:#1e4d6b;color:#fff;border:none;border-radius:8px;
                        padding:8px 18px;cursor:pointer;font-size:13px;font-weight:600;
                        white-space:nowrap">
                        ⬇ Download
                    </button>
                    <button onclick="openFileInBrowser('${file.folder}','${file.filename}')"
                        style="background:#0a2a3c;color:#a0c8e8;border:1.5px solid #1e4d6b;
                        border-radius:8px;padding:8px 18px;cursor:pointer;font-size:13px;
                        white-space:nowrap">
                        👁 View
                    </button>
                </div>
            `
            container.appendChild(card)
        })
    })
}

// =========================================
// DOWNLOAD FILE
// =========================================

function downloadFile(folder, filename){
    const a = document.createElement("a")
    a.href = `/api/files/download/${encodeURIComponent(folder)}/${encodeURIComponent(filename)}`
    a.download = filename
    a.click()
}

// =========================================
// VIEW FILE IN BROWSER (opens in new tab for text/images)
// =========================================

function openFileInBrowser(folder, filename){
    window.open(
        `/api/files/download/${encodeURIComponent(folder)}/${encodeURIComponent(filename)}`,
        "_blank"
    )
}

// =========================================
// OPEN FOLDER IN OS FILE MANAGER
// =========================================

async function openFolder(folder){
    try{
        const resp = await fetch(`/api/files/open-folder/${encodeURIComponent(folder)}`, {
            method:"POST"
        })
        const result = await resp.json()
        if(result.status==="success"){
            _sfToast(`📂 Opened folder: ${result.path}`)
        }else{
            _sfToast(`❌ Could not open folder: ${result.message||"Unknown error"}`)
        }
    }catch(e){
        _sfToast("❌ Failed to open folder")
    }
}

// =========================================
// SEARCH / FILTER
// =========================================

function filterSavedFiles(){
    const q    = (document.getElementById("sfSearchInput")?.value||"").toLowerCase()
    const type = (document.getElementById("sfTypeFilter")?.value||"ALL").toUpperCase()

    let filtered = _sfAllFiles

    if(type !== "ALL")
        filtered = filtered.filter(f=>(f.type||"").toUpperCase()===type)

    if(q)
        filtered = filtered.filter(f=>
            (f.filename||"").toLowerCase().includes(q) ||
            (f.folder||"").toLowerCase().includes(q)
        )

    _renderSavedFiles(filtered)
}

// =========================================
// TOAST
// =========================================

function _sfToast(msg, duration=4000){
    let t = document.getElementById("sfToast")
    if(!t){
        t = document.createElement("div")
        t.id = "sfToast"
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
    const searchInput = document.getElementById("sfSearchInput")
    const typeFilter  = document.getElementById("sfTypeFilter")

    if(searchInput) searchInput.addEventListener("input", filterSavedFiles)
    if(typeFilter)  typeFilter.addEventListener("change", filterSavedFiles)

    loadSavedFiles()
})