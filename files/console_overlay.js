/**
 * console_overlay.js
 * ====================
 * Floating terminal panel that streams real-time
 * server-side output into the dashboard UI.
 *
 * HOW IT WORKS:
 *  - The SOC backend sends JSON over the existing
 *    WebSocket connection.
 *  - Messages with type === "CONSOLE" contain a
 *    `line` field (string) that gets appended here.
 *  - Messages with type === "SCAN_START" start the
 *    elapsed timer; type === "SCAN_END" stops it.
 *
 * PLACEMENT:
 *  Add this script tag to dashboard.html (after
 *  the existing dashboard.js script tag):
 *
 *    <script src="/static/js/console_overlay.js"></script>
 *
 *  Then add the toggle button anywhere in your HTML:
 *
 *    <button onclick="SOCConsole.toggle()">
 *      Terminal
 *    </button>
 */

;(function () {

    // =========================================
    // BUILD THE OVERLAY DOM
    // =========================================

    const OVERLAY_ID  = "soc-console-overlay"
    const LOG_ID      = "soc-console-log"
    const TIMER_ID    = "soc-console-timer"
    const TOGGLE_ID   = "soc-console-toggle-btn"

    function buildOverlay () {

        if (document.getElementById(OVERLAY_ID)) return

        // ---- STYLES ----
        const style = document.createElement("style")
        style.textContent = `

            #soc-console-overlay {
                position: fixed;
                bottom: 80px;
                right: 24px;
                width: 640px;
                height: 380px;
                background: rgba(4, 12, 24, 0.97);
                border: 1px solid #1e3a5f;
                border-radius: 10px;
                box-shadow: 0 8px 40px rgba(0,0,0,0.7);
                display: flex;
                flex-direction: column;
                z-index: 9999;
                font-family: "Consolas", "Courier New", monospace;
                resize: both;
                overflow: hidden;
                min-width: 360px;
                min-height: 200px;
                transition: opacity 0.15s ease;
            }

            #soc-console-overlay.hidden {
                display: none !important;
            }

            /* Title bar — draggable */
            #soc-console-titlebar {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 8px 14px;
                background: #071a30;
                border-bottom: 1px solid #1e3a5f;
                border-radius: 10px 10px 0 0;
                cursor: move;
                user-select: none;
                flex-shrink: 0;
            }

            #soc-console-titlebar .title-left {
                display: flex;
                align-items: center;
                gap: 10px;
                color: #ffffff;
                font-size: 13px;
                font-weight: 700;
                font-family: "Segoe UI", sans-serif;
            }

            #soc-console-titlebar .dot {
                width: 8px;
                height: 8px;
                border-radius: 50%;
                background: #00ff88;
                animation: pulse-dot 1.4s infinite;
            }

            @keyframes pulse-dot {
                0%,100% { opacity: 1; }
                50%      { opacity: 0.3; }
            }

            #soc-console-titlebar .title-left .dot.idle {
                background: #5e6f75;
                animation: none;
            }

            #soc-console-timer {
                font-size: 11px;
                color: #7aa2d6;
                font-family: "Segoe UI", sans-serif;
                min-width: 60px;
                text-align: center;
            }

            .console-ctrl-btn {
                background: none;
                border: none;
                color: #7aa2d6;
                font-size: 16px;
                cursor: pointer;
                padding: 0 4px;
                line-height: 1;
                transition: color 0.15s;
            }
            .console-ctrl-btn:hover { color: #ffffff; }

            /* Log area */
            #soc-console-log {
                flex: 1;
                overflow-y: auto;
                padding: 10px 14px;
                font-size: 12px;
                color: #00ff88;
                line-height: 1.6;
                word-break: break-all;
            }

            /* Scrollbar */
            #soc-console-log::-webkit-scrollbar {
                width: 6px;
            }
            #soc-console-log::-webkit-scrollbar-thumb {
                background: #1e3a5f;
                border-radius: 3px;
            }

            /* Line colours */
            .con-info    { color: #00ff88; }
            .con-warn    { color: #ffd21f; }
            .con-error   { color: #ff4444; }
            .con-critical{ color: #ff3b30; font-weight: 700; }
            .con-high    { color: #ffd21f; }
            .con-medium  { color: #f2aa66; }
            .con-match   { color: #5fd4d4; }
            .con-system  { color: #7aa2d6; }
            .con-dim     { color: #445566; }

            /* Toolbar */
            #soc-console-toolbar {
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 6px 14px;
                border-top: 1px solid #1e3a5f;
                flex-shrink: 0;
            }

            .con-tool-btn {
                background: #0d2035;
                border: 1px solid #1e3a5f;
                color: #7aa2d6;
                border-radius: 4px;
                font-size: 11px;
                padding: 3px 10px;
                cursor: pointer;
                font-family: "Segoe UI", sans-serif;
                transition: background 0.15s;
            }
            .con-tool-btn:hover {
                background: #1e3a5f;
                color: #fff;
            }

            /* Floating toggle button */
            #soc-console-toggle-btn {
                position: fixed;
                bottom: 24px;
                right: 24px;
                z-index: 9998;
                background: #0d2035;
                border: 1px solid #2563eb;
                color: #7aa2d6;
                border-radius: 8px;
                padding: 8px 18px;
                font-size: 13px;
                font-family: "Segoe UI", sans-serif;
                font-weight: 600;
                cursor: pointer;
                box-shadow: 0 4px 16px rgba(0,0,0,0.5);
                transition: background 0.15s, color 0.15s;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            #soc-console-toggle-btn:hover {
                background: #2563eb;
                color: #fff;
            }
            #soc-console-toggle-btn .notif-badge {
                background: #ff3b30;
                color: #fff;
                border-radius: 10px;
                font-size: 10px;
                padding: 1px 6px;
                display: none;
            }
            #soc-console-toggle-btn .notif-badge.show {
                display: inline;
            }
        `
        document.head.appendChild(style)

        // ---- TOGGLE BUTTON ----
        const toggleBtn = document.createElement("button")
        toggleBtn.id = TOGGLE_ID
        toggleBtn.innerHTML = `⬛ Terminal <span class="notif-badge" id="soc-notif-badge">!</span>`
        toggleBtn.addEventListener("click", SOCConsole.toggle)
        document.body.appendChild(toggleBtn)

        // ---- OVERLAY ----
        const overlay = document.createElement("div")
        overlay.id = OVERLAY_ID
        overlay.classList.add("hidden")

        overlay.innerHTML = `
            <div id="soc-console-titlebar">
                <div class="title-left">
                    <span class="dot idle" id="soc-dot"></span>
                    SOC Terminal
                </div>
                <span id="${TIMER_ID}">00:00</span>
                <div style="display:flex;gap:6px">
                    <button class="console-ctrl-btn" title="Minimise"
                        onclick="SOCConsole.toggle()">—</button>
                    <button class="console-ctrl-btn" title="Clear"
                        onclick="SOCConsole.clear()">✕</button>
                </div>
            </div>
            <div id="${LOG_ID}"></div>
            <div id="soc-console-toolbar">
                <button class="con-tool-btn"
                    onclick="SOCConsole.clear()">
                    Clear
                </button>
                <button class="con-tool-btn"
                    onclick="SOCConsole.copyAll()">
                    Copy All
                </button>
                <button class="con-tool-btn"
                    onclick="SOCConsole.scrollBottom()">
                    ↓ Bottom
                </button>
                <span style="flex:1"></span>
                <span style="font-size:11px;color:#445566"
                    id="soc-con-linecount">0 lines</span>
            </div>
        `
        document.body.appendChild(overlay)

        // Make titlebar draggable
        _makeDraggable(
            overlay,
            document.getElementById("soc-console-titlebar")
        )
    }


    // =========================================
    // LINE COLOURING
    // =========================================

    function _classifyLine (text) {
        const t = text.toUpperCase()
        if (t.includes("CRITICAL"))  return "con-critical"
        if (t.includes("HIGH"))      return "con-high"
        if (t.includes("MEDIUM"))    return "con-medium"
        if (t.includes("[MATCH]") || t.includes("[THRESHOLD]"))
                                     return "con-match"
        if (t.includes("[ERROR]") || t.includes("FAILED"))
                                     return "con-error"
        if (t.includes("[WARN")  || t.includes("WARNING"))
                                     return "con-warn"
        if (t.includes("===") || t.includes("---"))
                                     return "con-dim"
        if (t.includes("[SOC]")  || t.includes("[DATABASE]") ||
            t.includes("[+]"))       return "con-system"
        return "con-info"
    }

    // =========================================
    // APPEND A LINE
    // =========================================

    let _lineCount   = 0
    let _unread      = 0
    const MAX_LINES  = 2000

    function _appendLine (text) {
        const log = document.getElementById(LOG_ID)
        if (!log) return

        const line = document.createElement("div")
        line.className = _classifyLine(text)

        // Timestamp prefix
        const now  = new Date()
        const ts   = `${String(now.getHours()).padStart(2,"0")}:` +
                     `${String(now.getMinutes()).padStart(2,"0")}:` +
                     `${String(now.getSeconds()).padStart(2,"0")}`

        line.textContent = `[${ts}] ${text}`
        log.appendChild(line)

        _lineCount++

        // Trim old lines to avoid memory leak
        if (_lineCount > MAX_LINES) {
            log.removeChild(log.firstChild)
            _lineCount--
        }

        // Update line counter
        const counter = document.getElementById("soc-con-linecount")
        if (counter) counter.textContent = `${_lineCount} lines`

        // Auto-scroll if user is near the bottom
        const threshold = 60
        const nearBottom = (
            log.scrollHeight - log.scrollTop - log.clientHeight
        ) < threshold

        if (nearBottom) {
            log.scrollTop = log.scrollHeight
        }

        // Show badge if console is hidden
        const overlay = document.getElementById(OVERLAY_ID)
        if (overlay && overlay.classList.contains("hidden")) {
            _unread++
            const badge = document.getElementById("soc-notif-badge")
            if (badge) {
                badge.textContent = _unread > 99 ? "99+" : _unread
                badge.classList.add("show")
            }
        }
    }


    // =========================================
    // TIMER
    // =========================================

    let _timerInterval = null
    let _timerStart    = null

    function _startTimer () {
        _timerStart = Date.now()
        const dot   = document.getElementById("soc-dot")
        if (dot) {
            dot.classList.remove("idle")
        }
        _timerInterval = setInterval(() => {
            const elapsed = Math.floor(
                (Date.now() - _timerStart) / 1000
            )
            const m = String(Math.floor(elapsed / 60)).padStart(2,"0")
            const s = String(elapsed % 60).padStart(2,"0")
            const timer = document.getElementById(TIMER_ID)
            if (timer) timer.textContent = `${m}:${s}`
        }, 1000)
    }

    function _stopTimer () {
        if (_timerInterval) {
            clearInterval(_timerInterval)
            _timerInterval = null
        }
        const dot = document.getElementById("soc-dot")
        if (dot) dot.classList.add("idle")
    }


    // =========================================
    // WEBSOCKET INTEGRATION
    // Hook into the existing `socket` variable
    // that dashboard.js already creates.
    // We patch onmessage to intercept CONSOLE
    // and SCAN_* events without breaking the
    // existing dashboard WebSocket handler.
    // =========================================

    function _hookWebSocket () {
        // Wait for dashboard.js to create `socket`
        let attempts = 0
        const interval = setInterval(() => {
            attempts++
            if (typeof socket !== "undefined" && socket !== null) {
                clearInterval(interval)
                _patchSocket(socket)
            }
            if (attempts > 40) clearInterval(interval)
        }, 250)
    }

    function _patchSocket (ws) {
        const origOnMessage = ws.onmessage

        ws.onmessage = async (event) => {

            // Let the original handler run first
            if (origOnMessage) {
                origOnMessage.call(ws, event)
            }

            try {
                const data = JSON.parse(event.data)

                switch (data.type) {

                    case "CONSOLE":
                        _appendLine(data.line || "")
                        break

                    case "SCAN_START":
                        _startTimer()
                        _appendLine(
                            "════ SCAN STARTED ════"
                        )
                        break

                    case "SCAN_END":
                        _stopTimer()
                        _appendLine(
                            `════ SCAN COMPLETE — ` +
                            `${data.total_alerts ?? "?"} alerts ════`
                        )
                        break

                    default:
                        break
                }
            } catch (_) {
                // Not JSON or different format — ignore
            }
        }
    }


    // =========================================
    // DRAG SUPPORT
    // =========================================

    function _makeDraggable (panel, handle) {
        let startX, startY, startLeft, startTop

        handle.addEventListener("mousedown", (e) => {
            startX    = e.clientX
            startY    = e.clientY
            const r   = panel.getBoundingClientRect()
            startLeft = r.left
            startTop  = r.top

            panel.style.right  = "unset"
            panel.style.bottom = "unset"
            panel.style.left   = startLeft + "px"
            panel.style.top    = startTop  + "px"

            const onMove = (ev) => {
                panel.style.left =
                    (startLeft + ev.clientX - startX) + "px"
                panel.style.top  =
                    (startTop  + ev.clientY - startY) + "px"
            }
            const onUp = () => {
                document.removeEventListener("mousemove", onMove)
                document.removeEventListener("mouseup",  onUp)
            }
            document.addEventListener("mousemove", onMove)
            document.addEventListener("mouseup",  onUp)
        })
    }


    // =========================================
    // PUBLIC API
    // =========================================

    window.SOCConsole = {

        toggle () {
            const overlay = document.getElementById(OVERLAY_ID)
            if (!overlay) return
            overlay.classList.toggle("hidden")

            // Clear unread badge when opened
            if (!overlay.classList.contains("hidden")) {
                _unread = 0
                const badge =
                    document.getElementById("soc-notif-badge")
                if (badge) badge.classList.remove("show")
            }
        },

        clear () {
            const log = document.getElementById(LOG_ID)
            if (log) log.innerHTML = ""
            _lineCount = 0
            const counter =
                document.getElementById("soc-con-linecount")
            if (counter) counter.textContent = "0 lines"
        },

        copyAll () {
            const log = document.getElementById(LOG_ID)
            if (!log) return
            const text = Array.from(log.children)
                .map(el => el.textContent)
                .join("\n")
            navigator.clipboard.writeText(text).then(() => {
                alert("Console output copied to clipboard.")
            })
        },

        scrollBottom () {
            const log = document.getElementById(LOG_ID)
            if (log) log.scrollTop = log.scrollHeight
        },

        /** Manually push a line (for direct API calls) */
        log (text) {
            _appendLine(text)
        }
    }


    // =========================================
    // INIT
    // =========================================

    if (document.readyState === "loading") {
        document.addEventListener(
            "DOMContentLoaded", () => {
                buildOverlay()
                _hookWebSocket()
            }
        )
    } else {
        buildOverlay()
        _hookWebSocket()
    }

})()
