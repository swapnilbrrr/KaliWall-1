// KaliWall — Frontend Application
// Handles navigation, API calls, table rendering, and rule management.

(function () {
    "use strict";

    const API = "/api/v1";

    // ---------- Navigation ----------

    const navItems = document.querySelectorAll(".nav-item");
    const pages = document.querySelectorAll(".page");
    const pageTitle = document.getElementById("pageTitle");
    const sidebar = document.getElementById("sidebar");
    const menuToggle = document.getElementById("menuToggle");

    const pageTitles = {
        dashboard: "Dashboard",
        rules: "Firewall Rules",
        connections: "Active Connections",
        logs: "Traffic Logs",
        settings: "Settings",
    };

    navItems.forEach((item) => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const target = item.dataset.page;
            navItems.forEach((n) => n.classList.remove("active"));
            item.classList.add("active");
            pages.forEach((p) => p.classList.remove("active"));
            document.getElementById("page-" + target).classList.add("active");
            pageTitle.textContent = pageTitles[target] || "KaliWall";
            sidebar.classList.remove("open");
            // Stop log stream when leaving the logs page
            if (target !== "logs") stopLogStream();
            loadPageData(target);
        });
    });

    menuToggle.addEventListener("click", () => sidebar.classList.toggle("open"));

    // ---------- Data Loading ----------

    function loadPageData(page) {
        switch (page) {
            case "dashboard":
                loadStats();
                loadSysInfo();
                loadDashboardLogs();
                loadDashboardConnections();
                break;
            case "rules":
                loadRules();
                break;
            case "connections":
                loadConnections();
                break;
            case "logs":
                loadLogs();
                break;
            case "settings":
                loadSettings();
                break;
        }
    }

    async function apiFetch(endpoint) {
        const res = await fetch(API + endpoint);
        return res.json();
    }

    // ---------- Dashboard ----------

    async function loadStats() {
        const res = await apiFetch("/stats");
        if (!res.success) return;
        const d = res.data;

        // Firewall stat cards
        document.getElementById("statTotalRules").textContent = d.total_rules;
        document.getElementById("statActiveRules").textContent = d.active_rules;
        document.getElementById("statBlocked").textContent = d.blocked_today;
        document.getElementById("statAllowed").textContent = d.allowed_today;
        document.getElementById("statConnections").textContent = d.active_connections;
        document.querySelector("#ruleCount span").textContent = d.active_rules;

        // System info banner
        document.getElementById("sysHostname").textContent = d.hostname || "--";
        document.getElementById("sysKernel").textContent = d.kernel || "--";
        document.getElementById("sysUptime").textContent = d.uptime || "--";
        document.getElementById("sysLoad").textContent = d.load_average || "--";

        // CPU gauge
        var cpuPct = d.cpu_usage_percent || 0;
        setGauge("gaugeCPU", "gaugeCPUText", cpuPct);
        document.getElementById("gaugeCPUCores").textContent = (d.cpu_cores || 0) + " cores";

        // Memory gauge
        var memPct = d.mem_usage_percent || 0;
        setGauge("gaugeMem", "gaugeMemText", memPct);
        var memUsedMB = ((d.mem_used_bytes || 0) / 1048576).toFixed(0);
        var memTotalMB = ((d.mem_total_bytes || 0) / 1048576).toFixed(0);
        document.getElementById("gaugeMemDetail").textContent = memUsedMB + " / " + memTotalMB + " MB";

        // Network totals
        document.getElementById("netRxValue").textContent = formatBytes(d.net_rx_bytes || 0);
        document.getElementById("netTxValue").textContent = formatBytes(d.net_tx_bytes || 0);
    }

    // Set a circular SVG gauge by percentage (0-100).
    function setGauge(circleId, textId, percent) {
        var circumference = 2 * Math.PI * 52; // r=52
        var offset = circumference - (percent / 100) * circumference;
        var circle = document.getElementById(circleId);
        if (circle) circle.style.strokeDashoffset = offset;
        var text = document.getElementById(textId);
        if (text) text.textContent = percent.toFixed(1) + "%";
    }

    // Format bytes into human-readable string.
    function formatBytes(bytes) {
        if (bytes === 0) return "0 B";
        var units = ["B", "KB", "MB", "GB", "TB"];
        var i = Math.floor(Math.log(bytes) / Math.log(1024));
        if (i >= units.length) i = units.length - 1;
        return (bytes / Math.pow(1024, i)).toFixed(1) + " " + units[i];
    }

    // Load detailed system info including network interfaces.
    async function loadSysInfo() {
        const res = await apiFetch("/sysinfo");
        if (!res.success) return;
        const si = res.data;

        // Populate interfaces table
        var tbody = document.querySelector("#ifacesTable tbody");
        if (!tbody) return;
        tbody.innerHTML = "";
        if (si.interfaces && si.interfaces.length > 0) {
            si.interfaces.forEach(function (iface) {
                var tr = document.createElement("tr");
                var addrs = (iface.addresses || []).map(escapeHtml).join(", ") || "none";
                tr.innerHTML =
                    "<td><strong>" + escapeHtml(iface.name) + "</strong></td>" +
                    "<td>" + addrs + "</td>" +
                    "<td>" + formatBytes(iface.rx_bytes || 0) + "</td>" +
                    "<td>" + formatBytes(iface.tx_bytes || 0) + "</td>";
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#9ca3af">No network interfaces detected</td></tr>';
        }
    }

    async function loadDashboardLogs() {
        const res = await apiFetch("/logs?limit=8");
        if (!res.success) return;
        const tbody = document.querySelector("#dashRecentLogs tbody");
        tbody.innerHTML = "";
        res.data.forEach((entry) => {
            const tr = document.createElement("tr");
            tr.innerHTML =
                "<td>" + formatTime(entry.timestamp) + "</td>" +
                "<td>" + actionBadge(entry.action) + "</td>" +
                "<td>" + escapeHtml(entry.src_ip) + "</td>" +
                "<td>" + escapeHtml(entry.dst_ip) + "</td>" +
                "<td>" + escapeHtml(entry.protocol) + "</td>" +
                "<td>" + escapeHtml(entry.detail) + "</td>";
            tbody.appendChild(tr);
        });
    }

    async function loadDashboardConnections() {
        const res = await apiFetch("/connections");
        if (!res.success) return;
        const tbody = document.querySelector("#dashConnections tbody");
        tbody.innerHTML = "";
        res.data.slice(0, 6).forEach((c) => {
            const tr = document.createElement("tr");
            tr.innerHTML =
                "<td>" + escapeHtml(c.protocol) + "</td>" +
                "<td>" + escapeHtml(c.local_ip) + ":" + escapeHtml(c.local_port) + "</td>" +
                "<td>" + escapeHtml(c.remote_ip) + ":" + escapeHtml(c.remote_port) + "</td>" +
                "<td>" + stateBadge(c.state) + "</td>";
            tbody.appendChild(tr);
        });
    }

    // ---------- Rules ----------

    async function loadRules() {
        const res = await apiFetch("/rules");
        if (!res.success) return;
        const tbody = document.querySelector("#rulesTable tbody");
        tbody.innerHTML = "";
        res.data.forEach((rule) => {
            const tr = document.createElement("tr");
            tr.innerHTML =
                "<td>" + enabledBadge(rule.enabled) + "</td>" +
                "<td>" + chainBadge(rule.chain) + "</td>" +
                "<td>" + escapeHtml(rule.protocol) + "</td>" +
                "<td>" + escapeHtml(rule.src_ip) + (rule.src_port !== "any" ? ":" + escapeHtml(rule.src_port) : "") + "</td>" +
                "<td>" + escapeHtml(rule.dst_ip) + "</td>" +
                "<td>" + escapeHtml(rule.dst_port) + "</td>" +
                "<td>" + actionBadge(rule.action) + "</td>" +
                "<td>" + escapeHtml(rule.comment) + "</td>" +
                '<td class="action-cell">' +
                    '<button class="btn-icon" title="Toggle" onclick="KaliWall.toggleRule(\'' + rule.id + '\')"><i class="fa-solid fa-toggle-' + (rule.enabled ? "on" : "off") + '"></i></button>' +
                    '<button class="btn-icon danger" title="Delete" onclick="KaliWall.deleteRule(\'' + rule.id + '\')"><i class="fa-solid fa-trash"></i></button>' +
                "</td>";
            tbody.appendChild(tr);
        });
    }

    // ---------- Connections ----------

    async function loadConnections() {
        const res = await apiFetch("/connections");
        if (!res.success) return;
        const tbody = document.querySelector("#connectionsTable tbody");
        tbody.innerHTML = "";
        res.data.forEach((c) => {
            const tr = document.createElement("tr");
            var remoteIP = c.remote_ip || "";
            tr.innerHTML =
                "<td>" + escapeHtml(c.protocol) + "</td>" +
                "<td>" + escapeHtml(c.local_ip) + "</td>" +
                "<td>" + escapeHtml(c.local_port) + "</td>" +
                "<td>" + escapeHtml(remoteIP) + "</td>" +
                "<td>" + escapeHtml(c.remote_port) + "</td>" +
                "<td>" + stateBadge(c.state) + "</td>" +
                '<td class="threat-cell" data-ip="' + escapeHtml(remoteIP) + '"><span class="badge badge-disabled">-</span></td>';
            tbody.appendChild(tr);
        });
        // Auto-check threat for non-private remote IPs
        checkThreatForConnections();
    }

    // ---------- Logs (Real-time SSE) ----------

    var logEventSource = null;
    var logLive = true;     // live vs paused
    var maxLogRows = 500;   // cap DOM rows

    function startLogStream() {
        stopLogStream();
        logLive = true;
        updateLiveUI();

        logEventSource = new EventSource(API + "/logs/stream");

        logEventSource.addEventListener("log", function (e) {
            if (!logLive) return;
            try {
                var entry = JSON.parse(e.data);
                prependLogRow(entry, true);
            } catch (_) {}
        });

        logEventSource.onerror = function () {
            // Browser will auto-reconnect; just update indicator briefly
            var ind = document.getElementById("liveIndicator");
            if (ind) ind.classList.add("paused");
            setTimeout(function () {
                if (logLive && ind) ind.classList.remove("paused");
            }, 2000);
        };
    }

    function stopLogStream() {
        if (logEventSource) {
            logEventSource.close();
            logEventSource = null;
        }
    }

    function prependLogRow(entry, animate) {
        var tbody = document.querySelector("#logsTable tbody");
        if (!tbody) return;
        var tr = document.createElement("tr");
        if (animate) tr.className = "log-new";
        tr.innerHTML =
            "<td>" + formatTime(entry.timestamp) + "</td>" +
            "<td>" + actionBadge(entry.action) + "</td>" +
            "<td>" + escapeHtml(entry.src_ip) + "</td>" +
            "<td>" + escapeHtml(entry.dst_ip) + "</td>" +
            "<td>" + escapeHtml(entry.protocol) + "</td>" +
            "<td>" + escapeHtml(entry.detail) + "</td>";
        tbody.insertBefore(tr, tbody.firstChild);
        // Trim excess rows
        while (tbody.children.length > maxLogRows) {
            tbody.removeChild(tbody.lastChild);
        }
    }

    function updateLiveUI() {
        var ind = document.getElementById("liveIndicator");
        var icon = document.getElementById("liveToggleIcon");
        var text = document.getElementById("liveToggleText");
        if (logLive) {
            if (ind) ind.classList.remove("paused");
            if (icon) icon.className = "fa-solid fa-pause";
            if (text) text.textContent = "Pause";
        } else {
            if (ind) ind.classList.add("paused");
            if (icon) icon.className = "fa-solid fa-play";
            if (text) text.textContent = "Resume";
        }
    }

    async function loadLogs() {
        // Load historical logs first, then start SSE stream
        const res = await apiFetch("/logs?limit=200");
        if (res.success) {
            const tbody = document.querySelector("#logsTable tbody");
            tbody.innerHTML = "";
            res.data.forEach(function (entry) {
                prependLogRow(entry, false);
            });
        }
        startLogStream();
    }

    // ---------- Rule CRUD ----------

    const ruleModal = document.getElementById("ruleModal");
    const ruleForm = document.getElementById("ruleForm");

    document.getElementById("btnAddRule").addEventListener("click", () => {
        ruleForm.reset();
        document.getElementById("ruleSrcIP").value = "any";
        document.getElementById("ruleSrcPort").value = "any";
        ruleModal.classList.add("open");
    });

    document.getElementById("modalClose").addEventListener("click", () => ruleModal.classList.remove("open"));
    document.getElementById("btnCancelRule").addEventListener("click", () => ruleModal.classList.remove("open"));
    ruleModal.addEventListener("click", (e) => {
        if (e.target === ruleModal) ruleModal.classList.remove("open");
    });

    ruleForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const body = {
            chain: document.getElementById("ruleChain").value,
            protocol: document.getElementById("ruleProtocol").value,
            src_ip: document.getElementById("ruleSrcIP").value || "any",
            dst_ip: document.getElementById("ruleDstIP").value || "any",
            src_port: document.getElementById("ruleSrcPort").value || "any",
            dst_port: document.getElementById("ruleDstPort").value || "any",
            action: document.getElementById("ruleAction").value,
            comment: document.getElementById("ruleComment").value,
            enabled: document.getElementById("ruleEnabled").value === "true",
        };

        const res = await fetch(API + "/rules", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const data = await res.json();
        if (data.success) {
            toast("Rule created successfully", "success");
            ruleModal.classList.remove("open");
            loadRules();
            loadStats();
        } else {
            toast(data.message || "Failed to create rule", "error");
        }
    });

    async function toggleRule(id) {
        const res = await fetch(API + "/rules/" + encodeURIComponent(id), { method: "PATCH" });
        const data = await res.json();
        if (data.success) {
            toast("Rule toggled", "success");
            loadRules();
            loadStats();
        } else {
            toast(data.message, "error");
        }
    }

    async function deleteRule(id) {
        if (!confirm("Delete this firewall rule?")) return;
        const res = await fetch(API + "/rules/" + encodeURIComponent(id), { method: "DELETE" });
        const data = await res.json();
        if (data.success) {
            toast("Rule deleted", "success");
            loadRules();
            loadStats();
        } else {
            toast(data.message, "error");
        }
    }

    // Expose to inline onclick handlers safely
    window.KaliWall = { toggleRule, deleteRule };

    // ---------- Refresh Buttons ----------

    document.getElementById("btnRefresh").addEventListener("click", () => {
        const activePage = document.querySelector(".nav-item.active").dataset.page;
        loadPageData(activePage);
        toast("Data refreshed", "success");
    });

    document.getElementById("btnRefreshConn").addEventListener("click", () => loadConnections());
    document.getElementById("btnRefreshLogs").addEventListener("click", () => loadLogs());

    document.getElementById("btnToggleLive").addEventListener("click", function () {
        logLive = !logLive;
        updateLiveUI();
        if (logLive && !logEventSource) startLogStream();
    });

    document.getElementById("btnClearLogs").addEventListener("click", function () {
        var tbody = document.querySelector("#logsTable tbody");
        if (tbody) tbody.innerHTML = "";
    });

    // ---------- Settings & Threat Intelligence ----------

    async function loadSettings() {
        var res = await apiFetch("/threat/apikey");
        if (!res.success) return;
        var badge = document.getElementById("apiKeyBadge");
        var removeBtn = document.getElementById("btnRemoveApiKey");
        if (res.data.configured) {
            badge.className = "badge badge-enabled";
            badge.innerHTML = '<i class="fa-solid fa-check"></i> API key configured (' + res.data.cache_entries + ' cached IPs)';
            removeBtn.style.display = "";
        } else {
            badge.className = "badge badge-disabled";
            badge.textContent = "Not configured";
            removeBtn.style.display = "none";
        }
    }

    document.getElementById("btnSaveApiKey").addEventListener("click", async function () {
        var key = document.getElementById("vtApiKey").value.trim();
        if (!key) { toast("Enter an API key", "error"); return; }
        var res = await fetch(API + "/threat/apikey", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ api_key: key }),
        });
        var data = await res.json();
        if (data.success) {
            toast("API key saved", "success");
            document.getElementById("vtApiKey").value = "";
            loadSettings();
        } else {
            toast(data.message || "Failed to save key", "error");
        }
    });

    document.getElementById("btnRemoveApiKey").addEventListener("click", async function () {
        if (!confirm("Remove the VirusTotal API key?")) return;
        await fetch(API + "/threat/apikey", { method: "DELETE" });
        toast("API key removed", "success");
        loadSettings();
    });

    document.getElementById("btnClearCache").addEventListener("click", async function () {
        threatCache = {};
        toast("Local threat cache cleared", "success");
    });

    // Automatically check threat for each unique remote IP in the connections table
    var threatCache = {};

    async function checkThreatForConnections() {
        var cells = document.querySelectorAll("#connectionsTable .threat-cell");
        var checked = {};
        for (var i = 0; i < cells.length; i++) {
            var ip = cells[i].getAttribute("data-ip");
            if (!ip || ip === "0.0.0.0" || ip === "127.0.0.1" || ip === "::1" || ip === "*" || ip === "") continue;
            if (checked[ip]) {
                // Apply cached result
                if (threatCache[ip]) cells[i].innerHTML = threatBadge(threatCache[ip]);
                continue;
            }
            checked[ip] = true;
            if (threatCache[ip]) {
                cells[i].innerHTML = threatBadge(threatCache[ip]);
                continue;
            }
            // Async lookup — fire and forget to avoid blocking
            (function(cell, ipAddr) {
                fetch(API + "/threat/check/" + encodeURIComponent(ipAddr))
                    .then(function(r) { return r.json(); })
                    .then(function(res) {
                        if (res.data) {
                            threatCache[ipAddr] = res.data;
                            // Update all cells with this IP
                            document.querySelectorAll('#connectionsTable .threat-cell[data-ip="' + ipAddr + '"]').forEach(function(c) {
                                c.innerHTML = threatBadge(res.data);
                            });
                        }
                    })
                    .catch(function() {});
            })(cells[i], ip);
        }
    }

    function threatBadge(verdict) {
        if (!verdict || !verdict.threat_level) return '<span class="badge badge-disabled">-</span>';
        var level = verdict.threat_level;
        var cls = "badge-threat-" + level;
        var icon = level === "malicious" ? "fa-skull-crossbones"
                 : level === "suspicious" ? "fa-triangle-exclamation"
                 : level === "safe" ? "fa-shield-check"
                 : level === "internal" ? "fa-house-signal"
                 : "fa-question";
        var label = level.charAt(0).toUpperCase() + level.slice(1);
        var title = "";
        if (verdict.owner) title += verdict.owner;
        if (verdict.country) title += (title ? " | " : "") + verdict.country;
        if (verdict.malicious > 0) title += (title ? " | " : "") + verdict.malicious + " malicious detections";
        return '<span class="badge ' + cls + '" title="' + escapeHtml(title) + '"><i class="fa-solid ' + icon + '"></i> ' + escapeHtml(label) + '</span>';
    }

    // ---------- Helpers ----------

    function escapeHtml(str) {
        if (!str) return "";
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    function formatTime(ts) {
        if (!ts) return "-";
        const d = new Date(ts);
        return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    }

    function actionBadge(action) {
        const a = (action || "").toUpperCase();
        const cls =
            a === "ACCEPT" || a === "ALLOW"
                ? "badge-accept"
                : a === "DROP" || a === "BLOCK"
                ? "badge-drop"
                : a === "REJECT"
                ? "badge-reject"
                : "";
        return '<span class="badge ' + cls + '">' + escapeHtml(a) + "</span>";
    }

    function chainBadge(chain) {
        const c = (chain || "").toUpperCase();
        const cls =
            c === "INPUT"
                ? "badge-input"
                : c === "OUTPUT"
                ? "badge-output"
                : c === "FORWARD"
                ? "badge-forward"
                : "";
        return '<span class="badge ' + cls + '">' + escapeHtml(c) + "</span>";
    }

    function enabledBadge(enabled) {
        return enabled
            ? '<span class="badge badge-enabled"><i class="fa-solid fa-circle" style="font-size:6px"></i> ON</span>'
            : '<span class="badge badge-disabled"><i class="fa-solid fa-circle" style="font-size:6px"></i> OFF</span>';
    }

    function stateBadge(state) {
        const s = (state || "").toUpperCase();
        const cls = "badge-" + s.toLowerCase().replace(/ /g, "_");
        return '<span class="badge ' + cls + '">' + escapeHtml(s) + "</span>";
    }

    function toast(message, type) {
        const el = document.getElementById("toast");
        el.textContent = message;
        el.className = "toast show " + (type || "");
        setTimeout(() => (el.className = "toast"), 3000);
    }

    // ---------- Initial Load ----------
    loadPageData("dashboard");
})();
