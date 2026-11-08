// LogWarden dashboard. Plain JavaScript, no libraries.
// Logs contain attackers' own text (script tags, SQL), so every value goes through esc() before it reaches the page.
(function () {
  "use strict";

  var view = document.getElementById("view");
  var me = null, tz = "UTC";

  // ------------------------------------------------------------ helpers
  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function cookie(name) {
    var m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return m ? decodeURIComponent(m[1]) : "";
  }
  function api(path, opts) {
    opts = opts || {};
    var headers = { "Accept": "application/json" };
    if (opts.method && opts.method !== "GET") headers["X-XSRF-TOKEN"] = cookie("XSRF-TOKEN");
    if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(opts.json); }
    return fetch(path, { method: opts.method || "GET", headers: headers, body: opts.body, credentials: "same-origin" }).then(function (r) {
      if (r.status === 401) { location.href = "/login.html"; throw new Error("Signed out"); }
      return r.text().then(function (t) {
        var data = t ? JSON.parse(t) : null;
        if (!r.ok) throw new Error((data && data.error) || (r.status === 403 ? "You don't have permission to do that." : "Request failed (" + r.status + ")"));
        return data;
      });
    });
  }
  var toastTimer;
  function toast(msg, err) {
    var t = document.getElementById("toast");
    t.textContent = msg;
    t.className = "toast" + (err ? " err" : "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.className = "toast hidden"; }, 4200);
  }
  function fmt(iso, withDate) {
    if (!iso) return "";
    var d = new Date(iso);
    var o = { timeZone: tz, hour: "2-digit", minute: "2-digit", hour12: false };
    if (withDate !== false) { o.day = "numeric"; o.month = "short"; }
    return new Intl.DateTimeFormat("en-GB", o).format(d);
  }
  function fmtSec(iso) {
    return new Intl.DateTimeFormat("en-GB", { timeZone: tz, day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date(iso));
  }
  function ago(iso) {
    var s = (Date.now() - new Date(iso).getTime()) / 1000;
    if (s < 90) return "just now";
    if (s < 5400) return Math.round(s / 60) + " min ago";
    if (s < 172800) return Math.round(s / 3600) + " h ago";
    return Math.round(s / 86400) + " days ago";
  }
  function sev(s) { return '<span class="sev ' + esc(s) + '">' + esc(s) + "</span>"; }
  var STATUS = { NEW: "New", INVESTIGATING: "Investigating", RESOLVED: "Resolved", FALSE_POSITIVE: "False positive" };
  function st(s) { return '<span class="st ' + esc(s) + '">' + esc(STATUS[s] || s) + "</span>"; }
  function mitre(id) {
    if (!id) return "";
    var path = id.replace(".", "/");
    return '<a class="mono" href="https://attack.mitre.org/techniques/' + esc(path) + '/" target="_blank" rel="noopener">' + esc(id) + "</a>";
  }
  function isAdmin() { return me && me.roles.indexOf("ADMIN") >= 0; }
  function qs(o) {
    var p = [];
    Object.keys(o).forEach(function (k) { if (o[k] !== "" && o[k] != null) p.push(encodeURIComponent(k) + "=" + encodeURIComponent(o[k])); });
    return p.length ? "?" + p.join("&") : "";
  }
  function parseHash() {
    var h = location.hash.replace(/^#\/?/, ""), parts = h.split("?"), path = parts[0].split("/"), params = {};
    (parts[1] || "").split("&").forEach(function (kv) { if (kv) { var a = kv.split("="); params[decodeURIComponent(a[0])] = decodeURIComponent(a[1] || ""); } });
    return { tab: path[0] || "overview", id: path[1], params: params };
  }
  function go(hash) { location.hash = hash; }

  // ------------------------------------------------------------ charts (SVG, sized with attributes so the CSP allows them)
  function hourly(counts, endIso) {
    var w = 760, h = 190, pad = 26, bw = (w - pad) / 24, max = Math.max.apply(null, counts.concat([1]));
    var end = new Date(endIso).getTime(), out = '<svg class="chart" viewBox="0 0 ' + w + " " + (h + 22) + '" role="img" aria-label="Events per hour">';
    [0, .5, 1].forEach(function (f) {
      var y = h - f * (h - 10);
      out += '<line x1="' + pad + '" x2="' + w + '" y1="' + y + '" y2="' + y + '" stroke="#22304d"/><text x="0" y="' + (y + 4) + '">' + Math.round(max * f) + "</text>";
    });
    counts.forEach(function (c, i) {
      var bh = c / max * (h - 10), x = pad + i * bw + 2;
      var hourStart = new Date(end - (24 - i) * 3600000);
      out += '<rect class="bar" x="' + x.toFixed(1) + '" y="' + (h - bh).toFixed(1) + '" width="' + (bw - 4).toFixed(1) + '" height="' + Math.max(bh, c ? 1 : 0).toFixed(1) + '" rx="2"><title>' + esc(fmt(hourStart.toISOString()) + ": " + c + " events") + "</title></rect>";
      if (i % 3 === 0) out += '<text x="' + (x + 2).toFixed(1) + '" y="' + (h + 16) + '">' + esc(fmt(hourStart.toISOString(), false)) + "</text>";
    });
    return out + "</svg>";
  }
  function hbars(rows, opts) {
    opts = opts || {};
    if (!rows.length) return '<div class="empty">Nothing yet</div>';
    var max = Math.max.apply(null, rows.map(function (r) { return r.count; }).concat([1]));
    return rows.map(function (r) {
      var cls = opts.sev ? "fill-" + r.key : "bar";
      var label = opts.link ? '<a href="' + esc(opts.link(r)) + '">' + esc(r.label) + "</a>" : esc(r.label);
      return '<div class="hbar-row"><div class="t">' + label + '</div><svg viewBox="0 0 100 10" preserveAspectRatio="none"><rect class="track" width="100" height="10" rx="3"/>' +
        '<rect class="' + cls + '" width="' + (r.count / max * 100).toFixed(1) + '" height="10" rx="3"/></svg><div class="n">' + esc(r.count) + "</div></div>";
    }).join("");
  }

  // ------------------------------------------------------------ overview
  function overview() {
    view.innerHTML = '<div class="empty">Loading…</div>';
    api("/api/stats").then(function (s) {
      var pri = s.priority.length ? '<ul class="list">' + s.priority.map(function (a) {
        return '<li>' + sev(a.severity) + '<a class="t" href="#/alerts/' + a.id + '">' + esc(a.title) + '</a><span class="muted nowrap">' + esc(ago(a.lastSeen)) + "</span></li>";
      }).join("") + "</ul>" : '<div class="empty">No open alerts. Nice.</div>';
      view.innerHTML =
        '<h1>Overview</h1><p class="sub">The 24 hours to ' + esc(fmt(s.windowEnd)) + " (" + esc(tz) + ")</p>" +
        '<div class="grid g4">' +
        kpi("Open alerts", s.openAlerts, "#/alerts?status=open") +
        kpi("Critical, open", s.criticalOpen, "#/alerts?status=open&severity=CRITICAL", s.criticalOpen > 0) +
        kpi("Events in 24 h", s.events24h.toLocaleString(), "#/events") +
        kpi("Events stored", s.eventsTotal.toLocaleString(), "#/events") + "</div>" +
        '<div class="grid g2"><div class="panel"><h2>Events per hour</h2>' + hourly(s.hourly, s.windowEnd) + "</div>" +
        '<div class="panel"><h2>Open alerts by severity</h2>' + hbars(s.openBySeverity, { sev: true, link: function (r) { return "#/alerts?status=open&severity=" + r.key; } }) +
        '<h2 class="gap">Alert status</h2>' + hbars(s.byStatus, { link: function (r) { return "#/alerts?status=" + r.key; } }) + "</div></div>" +
        '<div class="grid g3"><div class="panel"><h2>Needs attention</h2>' + pri + "</div>" +
        '<div class="panel"><h2>Alerts by rule</h2>' + hbars(s.byRule.slice(0, 9), { link: function (r) { return "#/alerts?rule=" + r.key; } }) + "</div>" +
        '<div class="panel"><h2>Most blocked or failing addresses</h2>' + hbars(s.noisyIps, { link: function (r) { return "#/events?ip=" + r.key; } }) +
        '<h2 class="gap">Events by source</h2>' + hbars(s.bySource, { link: function (r) { return "#/events?source=" + r.key; } }) + "</div></div>";
      spaceRows();
    }).catch(function (e) { view.innerHTML = '<div class="empty">' + esc(e.message) + "</div>"; });
  }
  function kpi(label, value, href, alarm) {
    return '<a class="panel kpi' + (alarm ? " alarm" : "") + '" href="' + esc(href) + '"><div class="l">' + esc(label) + '</div><div class="v">' + esc(value) + "</div></a>";
  }
  function spaceRows() { /* spacing lives in app.css */ }

  // ------------------------------------------------------------ alerts
  function alerts(params) {
    var f = { status: params.status || "open", severity: params.severity || "", rule: params.rule || "", q: params.q || "", page: params.page || 0 };
    view.innerHTML = '<h1>Alerts</h1><p class="sub">Grouped detections. Repeats of the same thing within 30 minutes are added to one alert.</p>' +
      '<form class="filters" id="af">' +
      '<label>Status<select name="status">' + opt("open", "Open", f.status) + opt("NEW", "New", f.status) + opt("INVESTIGATING", "Investigating", f.status) +
      opt("RESOLVED", "Resolved", f.status) + opt("FALSE_POSITIVE", "False positive", f.status) + opt("", "All", f.status) + "</select></label>" +
      '<label>Severity<select name="severity">' + opt("", "Any", f.severity) + ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(function (s) { return opt(s, s.charAt(0) + s.slice(1).toLowerCase(), f.severity); }).join("") + "</select></label>" +
      '<label>Search<input name="q" value="' + esc(f.q) + '" placeholder="Title, IP, user…"></label>' +
      (f.rule ? '<label>Rule<input name="rule" value="' + esc(f.rule) + '"></label>' : "") +
      '<button class="btn" type="submit">Filter</button></form><div class="panel" id="alist"><div class="empty">Loading…</div></div>';
    document.getElementById("af").addEventListener("submit", function (e) {
      e.preventDefault();
      var d = new FormData(e.target), o = {};
      d.forEach(function (v, k) { o[k] = v; });
      go("#/alerts" + qs(o));
    });
    api("/api/alerts" + qs({ status: f.status, severity: f.severity, rule: f.rule, q: f.q, page: f.page, size: 50 })).then(function (p) {
      var box = document.getElementById("alist");
      if (!p.items.length) { box.innerHTML = '<div class="empty">No alerts match.</div>'; return; }
      box.innerHTML = '<table><thead><tr><th>Severity</th><th>Alert</th><th>Rule</th><th>ATT&amp;CK</th><th class="nowrap">Last seen</th><th>Hits</th><th>Status</th></tr></thead><tbody>' +
        p.items.map(function (a) {
          return '<tr class="click" data-id="' + a.id + '"><td>' + sev(a.severity) + '</td><td class="title">' + esc(a.title) + (a.assignee ? '<div class="muted">' + esc(a.assignee) + "</div>" : "") +
            "</td><td>" + esc(a.ruleName) + "</td><td>" + mitre(a.mitre) + '</td><td class="nowrap">' + esc(fmt(a.lastSeen)) + "</td><td>" + esc(a.hits) + "</td><td>" + st(a.status) + "</td></tr>";
        }).join("") + "</tbody></table>" + pager(p, function (n) { return "#/alerts" + qs({ status: f.status, severity: f.severity, rule: f.rule, q: f.q, page: n }); });
      box.querySelectorAll("tr.click").forEach(function (tr) { tr.addEventListener("click", function () { go("#/alerts/" + tr.dataset.id); }); });
    }).catch(fail);
  }
  function opt(v, label, cur) { return '<option value="' + esc(v) + '"' + (String(cur) === v ? " selected" : "") + ">" + esc(label) + "</option>"; }
  function pager(p, href) {
    if (p.pages <= 1) return '<div class="pager">' + esc(p.total) + " in total</div>";
    return '<div class="pager">' + (p.page > 0 ? '<a href="' + esc(href(p.page - 1)) + '">← Newer</a>' : "") +
      "<span>Page " + (p.page + 1) + " of " + p.pages + " · " + esc(p.total) + " in total</span>" +
      (p.page + 1 < p.pages ? '<a href="' + esc(href(p.page + 1)) + '">Older →</a>' : "") + "</div>";
  }
  function fail(e) { toast(e.message, true); }

  function alertDetail(id) {
    view.innerHTML = '<div class="empty">Loading…</div>';
    api("/api/alerts/" + encodeURIComponent(id)).then(function (d) {
      var a = d.alert;
      var ips = {};
      d.evidence.forEach(function (e) { if (e.srcIp) ips[e.srcIp] = 1; });
      var pivots = Object.keys(ips).slice(0, 6).map(function (ip) { return '<a href="#/events?ip=' + encodeURIComponent(ip) + '">All events from ' + esc(ip) + "</a>"; });
      view.innerHTML =
        '<p><a href="#/alerts">← Alerts</a></p>' +
        '<div class="panel"><div class="detail-head"><div>' + sev(a.severity) + ' <span class="muted">#' + esc(a.id) + " · " + esc(a.ruleName) + " · " + mitre(a.mitre) + "</span>" +
        "<h1>" + esc(a.title) + "</h1></div><div>" + st(a.status) + "</div></div>" +
        '<div class="facts"><div><b>First seen</b>' + esc(fmtSec(a.firstSeen)) + "</div><div><b>Last seen</b>" + esc(fmtSec(a.lastSeen)) + "</div><div><b>Times detected</b>" + esc(a.hits) +
        "</div><div><b>About</b><span class=\"mono\">" + esc(a.entity) + "</span></div><div><b>Assigned to</b>" + esc(a.assignee || "Nobody") + "</div></div>" +
        '<div class="desc">' + esc(a.description) + "</div>" + (pivots.length ? '<p class="muted">' + pivots.join(" · ") + "</p>" : "") + "</div>" +
        '<div class="grid g2"><div class="panel"><h2>Evidence (' + d.evidence.length + " events)</h2>" +
        '<table class="timeline"><tbody>' + d.evidence.map(function (e) {
          return '<tr class="click" data-raw="1"><td>' + esc(fmtSec(e.time)) + "</td><td>" + esc(e.host || "") + '</td><td>' + esc(e.message) +
            '<div class="raw hidden">' + esc(e.raw) + "</div></td></tr>";
        }).join("") + '</tbody></table><p class="muted">Click a row to see the original log line.</p></div>' +
        '<div class="panel"><h2>Work this alert</h2><form id="work" class="work"><label class="filters">Status<select name="status">' +
        ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"].map(function (s) { return opt(s, STATUS[s], a.status); }).join("") +
        '</select></label><label class="filters">Assigned to<input name="assignee" value="' + esc(a.assignee || "") + '" maxlength="100"></label>' +
        '<button class="btn" type="submit">Save</button></form>' +
        '<form id="note"><textarea name="body" maxlength="4000" placeholder="What did you check? What did you find?" required></textarea>' +
        '<p><button class="btn ghost" type="submit">Add note</button></p></form>' +
        "<h2>Investigation trail</h2><ul class=\"trail\">" + d.notes.map(function (n) {
          return '<li><span class="who2">' + esc(n.author) + '</span><span class="when">' + esc(fmtSec(n.createdAt)) + "</span><div>" + esc(n.body) + "</div></li>";
        }).join("") + "</ul></div></div>";
      spaceRows();
      view.querySelectorAll("tr[data-raw]").forEach(function (tr) {
        tr.addEventListener("click", function () { tr.querySelector(".raw").classList.toggle("hidden"); });
      });
      document.getElementById("work").addEventListener("submit", function (e) {
        e.preventDefault();
        var f = new FormData(e.target);
        api("/api/alerts/" + a.id, { method: "PATCH", json: { status: f.get("status"), assignee: f.get("assignee") } })
          .then(function () { toast("Saved."); alertDetail(id); }).catch(fail);
      });
      document.getElementById("note").addEventListener("submit", function (e) {
        e.preventDefault();
        var body = new FormData(e.target).get("body");
        api("/api/alerts/" + a.id + "/notes", { method: "POST", json: { body: body } })
          .then(function () { toast("Note added."); alertDetail(id); }).catch(fail);
      });
    }).catch(function (e) { view.innerHTML = '<div class="empty">' + esc(e.message) + "</div>"; });
  }

  // ------------------------------------------------------------ events
  var TYPES = ["LOGIN_SUCCESS", "LOGIN_FAILURE", "ACCOUNT_CREATED", "GROUP_MEMBER_ADDED", "PRIVILEGE_USE", "LOG_CLEARED", "HTTP_REQUEST", "CONNECTION_BLOCKED", "CONNECTION_ALLOWED", "OTHER"];
  function events(params) {
    var f = { q: params.q || "", type: params.type || "", source: params.source || "", ip: params.ip || "", user: params.user || "", host: params.host || "", page: params.page || 0 };
    view.innerHTML = '<h1>Events</h1><p class="sub">Every stored log event, newest first.</p>' +
      '<form class="filters" id="ef"><label>Contains<input name="q" value="' + esc(f.q) + '" placeholder="e.g. shadow, /admin"></label>' +
      '<label>Type<select name="type">' + opt("", "Any", f.type) + TYPES.map(function (t) { return opt(t, t.replace(/_/g, " ").toLowerCase(), f.type); }).join("") + "</select></label>" +
      '<label>Source<select name="source">' + opt("", "Any", f.source) + ["linux", "windows", "web", "firewall", "logwarden"].map(function (s) { return opt(s, s, f.source); }).join("") + "</select></label>" +
      '<label>IP address<input name="ip" value="' + esc(f.ip) + '" size="15"></label><label>User<input name="user" value="' + esc(f.user) + '" size="12"></label>' +
      '<label>Host<input name="host" value="' + esc(f.host) + '" size="12"></label>' +
      '<button class="btn" type="submit">Search</button> <a href="#/events">Clear</a></form><div class="panel" id="elist"><div class="empty">Loading…</div></div>';
    document.getElementById("ef").addEventListener("submit", function (e) {
      e.preventDefault();
      var d = new FormData(e.target), o = {};
      d.forEach(function (v, k) { o[k] = String(v).trim(); });
      go("#/events" + qs(o));
    });
    var query = Object.assign({}, f, { size: 50 });
    api("/api/events" + qs(query)).then(function (p) {
      var box = document.getElementById("elist");
      if (!p.items.length) { box.innerHTML = '<div class="empty">No events match.</div>'; return; }
      box.innerHTML = '<table><thead><tr><th class="nowrap">Time</th><th>Source</th><th>Host</th><th>What happened</th><th>User</th><th>From</th></tr></thead><tbody>' +
        p.items.map(function (e) {
          return '<tr class="click"><td class="nowrap">' + esc(fmtSec(e.time)) + "</td><td>" + esc(e.source) + "</td><td>" + esc(e.host || "") + "</td><td>" +
            '<span class="badge">' + esc(e.typeLabel) + "</span> " + esc(e.message) + '<div class="raw hidden">' + esc(e.raw) + "</div></td><td>" +
            (e.user ? '<a href="#/events?user=' + encodeURIComponent(e.user) + '">' + esc(e.user) + "</a>" : "") + "</td><td>" +
            (e.srcIp ? '<a href="#/events?ip=' + encodeURIComponent(e.srcIp) + '">' + esc(e.srcIp) + "</a>" : "") + "</td></tr>";
        }).join("") + "</tbody></table>" + pager(p, function (n) { return "#/events" + qs(Object.assign({}, f, { page: n })); });
      box.querySelectorAll("tr.click").forEach(function (tr) {
        tr.addEventListener("click", function (e) { if (e.target.tagName !== "A") tr.querySelector(".raw").classList.toggle("hidden"); });
      });
    }).catch(fail);
  }

  // ------------------------------------------------------------ rules
  function rules() {
    view.innerHTML = '<div class="empty">Loading…</div>';
    api("/api/rules").then(function (list) {
      view.innerHTML = '<h1>Detection rules</h1><p class="sub">' + list.length + " rules, each mapped to a MITRE ATT&amp;CK technique." +
        (isAdmin() ? "" : " Only admins can switch rules on and off.") + "</p>" +
        '<div class="panel"><table><thead><tr><th>On</th><th>Rule</th><th>Looks for</th><th>ATT&amp;CK</th><th>Severity</th><th>Alerts</th></tr></thead><tbody>' +
        list.map(function (r) {
          return '<tr><td><button class="switch' + (r.enabled ? " on" : "") + '" data-id="' + esc(r.id) + '" aria-label="' + esc(r.name) + '" aria-pressed="' + r.enabled + '"' + (isAdmin() ? "" : " disabled") + "></button></td>" +
            '<td class="title">' + esc(r.name) + '<div class="muted mono">' + esc(r.id) + "</div></td><td>" + esc(r.description) + "</td><td>" + mitre(r.mitre) + "</td><td>" + sev(r.severity) +
            '</td><td><a href="#/alerts?status=&rule=' + encodeURIComponent(r.id) + '">' + esc(r.alerts) + "</a></td></tr>";
        }).join("") + "</tbody></table></div>";
      view.querySelectorAll("button.switch").forEach(function (b) {
        b.addEventListener("click", function () {
          var on = !b.classList.contains("on");
          api("/api/rules/" + encodeURIComponent(b.dataset.id), { method: "PUT", json: { enabled: on } }).then(function () {
            b.classList.toggle("on", on);
            b.setAttribute("aria-pressed", on);
            toast((on ? "Switched on: " : "Switched off: ") + b.getAttribute("aria-label"));
          }).catch(fail);
        });
      });
    }).catch(fail);
  }

  // ------------------------------------------------------------ upload
  function upload() {
    var origin = location.origin;
    view.innerHTML = '<h1>Add logs</h1><p class="sub">Upload a log file or paste lines. LogWarden works out the format line by line, so one upload can mix formats. Upload older logs first: the rules read events in time order.</p>' +
      '<div class="grid g2"><div class="panel"><form id="up">' +
      '<div class="filters"><label>Format<select name="format" id="fmt"><option value="auto">Work it out</option></select></label>' +
      '<label>File<input type="file" name="file" id="file"></label></div>' +
      '<textarea name="text" id="text" placeholder="…or paste log lines here"></textarea>' +
      '<p><button class="btn" type="submit" id="go">Add to LogWarden</button></p></form><div id="res" class="result"></div></div>' +
      '<div class="panel"><h2>What it reads</h2><ul class="list" id="formats"></ul>' +
      '<h2 class="gap">Send logs automatically</h2><p class="muted">Set <span class="mono">LOGWARDEN_API_KEY</span> on the server, then from any machine:</p>' +
      '<code class="block">curl -X POST "' + esc(origin) + '/api/ingest?format=linux" \\\n  -H "X-API-Key: $LOGWARDEN_API_KEY" \\\n  --data-binary @/var/log/auth.log</code>' +
      '<p class="muted">' + (me.apiKeyIngest ? "API-key sending is on." : "API-key sending is off on this server.") + "</p>" +
      (isAdmin() ? '<h2 class="gap">Demo data</h2><p class="muted">Delete everything and load a fresh simulated day with attacks in it.</p><button class="btn danger" id="reset">Reset demo data</button>' : "") +
      "</div></div>";
    spaceRows();
    api("/api/formats").then(function (fs) {
      var sel = document.getElementById("fmt");
      fs.forEach(function (f) { sel.insertAdjacentHTML("beforeend", opt(f.name, f.name, "")); });
      document.getElementById("formats").innerHTML = fs.map(function (f) { return '<li><span class="badge">' + esc(f.name) + "</span><span>" + esc(f.description) + "</span></li>"; }).join("");
    });
    document.getElementById("up").addEventListener("submit", function (e) {
      e.preventDefault();
      var file = document.getElementById("file").files[0], text = document.getElementById("text").value, format = document.getElementById("fmt").value;
      if (!file && !text.trim()) { toast("Choose a file or paste some lines first.", true); return; }
      var btn = document.getElementById("go");
      btn.disabled = true;
      var req;
      if (file) {
        var fd = new FormData();
        fd.append("file", file);
        req = fetch("/api/ingest/file?format=" + encodeURIComponent(format), { method: "POST", body: fd, headers: { "X-XSRF-TOKEN": cookie("XSRF-TOKEN") }, credentials: "same-origin" })
          .then(function (r) { return r.json().then(function (d) { if (!r.ok) throw new Error(d.error || "Upload failed"); return d; }); });
      } else {
        req = fetch("/api/ingest?format=" + encodeURIComponent(format), { method: "POST", body: text, headers: { "Content-Type": "text/plain", "X-XSRF-TOKEN": cookie("XSRF-TOKEN") }, credentials: "same-origin" })
          .then(function (r) { return r.json().then(function (d) { if (!r.ok) throw new Error(d.error || "Upload failed"); return d; }); });
      }
      req.then(showResult).catch(fail).then(function () { btn.disabled = false; });
    });
    var reset = document.getElementById("reset");
    if (reset) reset.addEventListener("click", function () {
      if (!confirm("Delete all events and alerts and load a fresh demo day?")) return;
      reset.disabled = true;
      api("/api/demo/reset", { method: "POST" }).then(function (r) { toast("Loaded " + r.stored + " events; " + r.alertsRaised + " alerts raised."); go("#/overview"); })
        .catch(fail).then(function () { reset.disabled = false; });
    });
  }
  function showResult(r) {
    var by = Object.keys(r.byFormat).map(function (k) { return esc(r.byFormat[k]) + " " + esc(k); }).join(", ");
    document.getElementById("res").innerHTML = '<div class="desc">Read ' + esc(r.lines) + " lines: stored " + esc(r.stored) + (by ? " (" + by + ")" : "") +
      (r.skipped ? ", skipped " + esc(r.skipped) + (r.skipped === 1 ? " that wasn't" : " that weren't") + " a known format" : "") + ". " +
      "<b>" + esc(r.alertsRaised) + " new alert" + (r.alertsRaised === 1 ? "" : "s") + "</b>" + (r.alertsUpdated ? ", " + esc(r.alertsUpdated) + " updates to existing ones" : "") + ".</div>" +
      (r.skippedSamples.length ? '<p class="muted">Lines it couldn\'t read, for example:</p><code class="block">' + r.skippedSamples.map(esc).join("\n") + "</code>" : "") +
      (r.alertsRaised ? '<p><a href="#/alerts">See the alerts →</a></p>' : "");
  }

  // ------------------------------------------------------------ router
  function route() {
    var r = parseHash();
    document.querySelectorAll(".nav a").forEach(function (a) { a.classList.toggle("on", a.dataset.tab === r.tab); });
    window.scrollTo(0, 0);
    if (r.tab === "alerts" && r.id) return alertDetail(r.id);
    if (r.tab === "alerts") return alerts(r.params);
    if (r.tab === "events") return events(r.params);
    if (r.tab === "rules") return rules();
    if (r.tab === "upload") return upload();
    return overview();
  }

  api("/api/me").then(function (m) {
    me = m;
    tz = m.zone || "UTC";
    var role = isAdmin() ? "admin" : "analyst";
    document.getElementById("who").innerHTML = esc(m.name) + (m.name === role ? "" : ' <span class="badge">' + role + "</span>");
    document.getElementById("logout").addEventListener("submit", function () { document.getElementById("logoutCsrf").value = cookie("XSRF-TOKEN"); });
    window.addEventListener("hashchange", route);
    route();
  }).catch(function () { /* api() already sent us to the sign-in page */ });
})();
