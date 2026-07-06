// =========================================
// SAVED FILES PAGE — Grouped Bundle View
// Files grouped by save timestamp.
// Each bundle = one "Save to Forensics" click.
// =========================================

let _allBundles    = []
let _searchQuery   = ""
let _filterType    = "all"
let _expandedBundles = new Set()

// =========================================
// LOAD GROUPED FILES
// =========================================

async function loadSavedFiles(){
    const container = document.getElementById("savedFilesContainer")
    const countEl   = document.getElementById("savedFilesCount")
    if(container) container.innerHTML = `
        <div style="text-align:center;padding:40px;color:#5a8a9f">
            <div style="font-size:24px;margin-bottom:10px">⏳</div>
            Loading files...
        </div>`

    try{
        const resp = await fetch("/api/saved-files/grouped")
        _allBundles = await resp.json()

        if(countEl) countEl.textContent =
            `${_allBundles.length} bundle${_allBundles.length!==1?"s":""}`

        _renderBundles()
    }catch(e){
        if(container) container.innerHTML = `
            <div style="text-align:center;padding:40px;color:#ff3b30">
                ❌ Failed to load files: ${e.message}
            </div>`
    }
}

// =========================================
// RENDER BUNDLES
// =========================================

function _renderBundles(){
    const container = document.getElementById("savedFilesContainer")
    if(!container) return

    const q = _searchQuery.toLowerCase()

    // Filter bundles
    let bundles = _allBundles.filter(bundle => {
        if(_filterType !== "all"){
            const hasType = bundle.files.some(
                f => f.type.toLowerCase() === _filterType.toLowerCase()
            )
            if(!hasType) return false
        }
        if(q){
            const matchesTs = bundle.timestamp.toLowerCase().includes(q)
            const matchesFile = bundle.files.some(
                f => f.filename.toLowerCase().includes(q)
            )
            return matchesTs || matchesFile
        }
        return true
    })

    if(!bundles.length){
        container.innerHTML = `
            <div class="sf-empty">
                <div style="font-size:40px;margin-bottom:14px">📁</div>
                <div style="font-size:15px;font-weight:600;margin-bottom:6px">No saved files yet</div>
                <div style="font-size:13px;color:#5a8a9f">
                    Click "Save to Forensics" on the dashboard to export alert data
                </div>
            </div>`
        return
    }

    container.innerHTML = bundles.map(bundle => _renderBundle(bundle)).join("")
}

function _renderBundle(bundle){
    const isExpanded = _expandedBundles.has(bundle.bundle_id)
    const fileCount  = bundle.files.length
    const totalSize  = bundle.total_size_label || ""

    const typeIcons = { JSON:"🔷", CSV:"📊", TXT:"📄", PDF:"📕" }

    const filesHtml = bundle.files.map(f => `
        <div class="sf-file-row">
            <div class="sf-file-icon-wrap">
                <span class="sf-file-icon sf-icon-${(f.type||"FILE").toLowerCase()}">
                    ${f.type||"FILE"}
                </span>
            </div>
            <div class="sf-file-info">
                <div class="sf-file-name">${f.filename}</div>
                <div class="sf-file-meta">
                    <span>📦 ${f.size}</span>
                    <span>🕐 ${f.saved}</span>
                </div>
            </div>
            <div class="sf-file-actions">
                <a href="/api/files/download/${f.folder}/${f.filename}"
                   download="${f.filename}"
                   class="sf-btn sf-btn-download">
                    ↓ Download
                </a>
                <button class="sf-btn sf-btn-view"
                    onclick="viewFile('${f.folder}', '${f.filename}')">
                    👁 View
                </button>
            </div>
        </div>
    `).join("")

    return `
        <div class="sf-bundle" id="bundle_${bundle.bundle_id}">

            <!-- Bundle Header (click to expand/collapse) -->
            <div class="sf-bundle-header"
                onclick="toggleBundle('${bundle.bundle_id}')"
            >
                <div class="sf-bundle-chevron ${isExpanded ? "expanded" : ""}">▶</div>
                <div class="sf-bundle-icon">🗂️</div>
                <div class="sf-bundle-title-group">
                    <div class="sf-bundle-title">
                        Forensic Export — ${bundle.timestamp}
                    </div>
                    <div class="sf-bundle-meta">
                        ${fileCount} file${fileCount!==1?"s":""} · ${totalSize}
                        · ${bundle.folder}
                    </div>
                </div>
                <div class="sf-bundle-badges">
                    ${bundle.files.map(f =>
                        `<span class="sf-type-badge sf-icon-${(f.type||"file").toLowerCase()}">${f.type}</span>`
                    ).join("")}
                </div>
                <div class="sf-bundle-actions" onclick="event.stopPropagation()">
                    <a href="/api/files/download-bundle/${bundle.bundle_id}"
                       download="soc_forensics_${bundle.bundle_id}.zip"
                       class="sf-btn sf-btn-zip"
                       title="Download all as ZIP">
                        ⬇ ZIP All
                    </a>
                </div>
            </div>

            <!-- Bundle Body (files list) -->
            <div class="sf-bundle-body ${isExpanded ? "" : "sf-collapsed"}">
                ${filesHtml}
            </div>

        </div>
    `
}

// =========================================
// TOGGLE BUNDLE EXPAND/COLLAPSE
// =========================================

function toggleBundle(bundleId){
    if(_expandedBundles.has(bundleId)){
        _expandedBundles.delete(bundleId)
    } else {
        _expandedBundles.add(bundleId)
    }
    _renderBundles()
}

// =========================================
// VIEW FILE CONTENT
// =========================================

async function viewFile(folder, filename){
    try{
        const resp = await fetch(`/api/files/download/${folder}/${filename}`)
        const text = await resp.text()

        // Show in modal
        let modal = document.getElementById("sfViewModal")
        if(!modal){
            modal = document.createElement("div")
            modal.id = "sfViewModal"
            modal.style.cssText = `
                position:fixed;top:0;left:0;width:100%;height:100%;
                background:rgba(0,0,0,0.7);z-index:9999;
                display:flex;align-items:center;justify-content:center;`
            document.body.appendChild(modal)
        }
        modal.innerHTML = `
            <div style="background:#0d1f2d;border:1px solid #1e4d6b;border-radius:12px;
                width:80vw;max-width:900px;max-height:80vh;display:flex;flex-direction:column;
                overflow:hidden;">
                <div style="display:flex;justify-content:space-between;align-items:center;
                    padding:16px 20px;border-bottom:1px solid #1e4d6b;">
                    <span style="font-weight:700;color:#fff">${filename}</span>
                    <button onclick="document.getElementById('sfViewModal').style.display='none'"
                        style="background:none;border:none;color:#ff3b30;font-size:20px;cursor:pointer">✕</button>
                </div>
                <pre style="flex:1;overflow:auto;padding:20px;margin:0;
                    font-size:12px;font-family:monospace;color:#a0c8e8;
                    white-space:pre-wrap;word-break:break-word">${
                    text.replace(/</g,"&lt;").replace(/>/g,"&gt;").slice(0, 50000)
                }</pre>
            </div>`
        modal.style.display = "flex"
    }catch(e){
        alert("Could not view file: " + e.message)
    }
}

// =========================================
// SEARCH + FILTER
// =========================================

function searchSavedFiles(){
    _searchQuery = document.getElementById("sfSearchInput")?.value || ""
    _renderBundles()
}

function filterByType(type){
    _filterType = type
    _renderBundles()
}

function openExportsFolder(){
    fetch("/api/files/open-folder/forensics_exports", {method:"POST"})
        .catch(()=>{})
}

// =========================================
// AUTO-LOAD ON PAGE SHOW
// =========================================

// Called by showPage() when savedFilesPage opens
window._savedFilesLoaded = false
const _origShowPage = window.showPage
if(typeof window.showPage === "function"){
    window.showPage = function(pageId){
        _origShowPage(pageId)
        if(pageId === "savedFilesPage") loadSavedFiles()
    }
}

// Load on init too
setTimeout(() => { loadSavedFiles() }, 800)