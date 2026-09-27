// The page polls the status endpoint; everything else is a plain form POST.
(function () {
  "use strict";

  function bytes(n) {
    if (n < 1024) return n + " B";
    var units = ["kB", "MB", "GB", "TB", "PB"], v = n;
    for (var i = 0; i < units.length; i++) {
      v /= 1024;
      if (v < 1024) return v.toFixed(1) + " " + units[i];
    }
    return (v / 1024).toFixed(1) + " EB";
  }

  function num(n) {
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ".");
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function set(id, text) {
    var e = document.getElementById(id);
    if (e) e.textContent = text;
  }

  // Game streaming is talked about in Mbit/s, so that is what the graph says.
  function mbits(bytesPerSecond) {
    var v = bytesPerSecond * 8 / 1e6;
    if (v >= 100) return v.toFixed(0) + " Mbit/s";
    if (v >= 10) return v.toFixed(1) + " Mbit/s";
    return v.toFixed(2) + " Mbit/s";
  }

  function minutes(seconds) {
    if (seconds < 90) return Math.round(seconds) + " s";
    return Math.round(seconds / 60) + " min";
  }

  // One filled area per direction. The path is built in the SVG's own viewBox coordinates
  // and stretched by preserveAspectRatio="none", so no resize handling is needed.
  function area(samples, pick, max, w, h) {
    if (samples.length < 2) return "";
    var step = w / (samples.length - 1);
    var d = "M 0 " + h.toFixed(1);
    for (var i = 0; i < samples.length; i++) {
      var y = h - Math.min(1, pick(samples[i]) / max) * (h - 2);
      d += " L " + (i * step).toFixed(1) + " " + y.toFixed(1);
    }
    return d + " L " + w.toFixed(1) + " " + h.toFixed(1) + " Z";
  }

  function renderChart(m) {
    var samples = m.samples || [];
    var w = 600, h = 140;
    // A floor on the scale keeps an idle gateway from amplifying a few stray packets into
    // a dramatic mountain range.
    var floorBytes = 125000; // 1 Mbit/s
    var max = Math.max(m.peakUp || 0, m.peakDown || 0, floorBytes);
    var up = document.getElementById("chart-up");
    var down = document.getElementById("chart-down");
    if (up) up.setAttribute("d", area(samples, function (s) { return s.up; }, max, w, h));
    if (down) down.setAttribute("d", area(samples, function (s) { return s.down; }, max, w, h));

    var last = samples.length ? samples[samples.length - 1] : null;
    set("rate-up", last ? mbits(last.up) : "–");
    set("rate-down", last ? mbits(last.down) : "–");
    set("chart-scale", samples.length
      ? "Skala bis " + mbits(max) + " · Spitze runter " + mbits(m.peakDown || 0)
      : "sammelt Daten …");
    var span = document.getElementById("chart-span");
    if (span) {
      span.textContent = samples.length > 1
        ? "vor " + minutes((samples.length - 1) * (m.intervalSeconds || 5))
        : "\u00a0";
    }
  }

  function renderClients(m) {
    var body = document.getElementById("clients");
    if (!body) return;
    var clients = m.clients || [];
    if (clients.length === 0) {
      var tr = el("tr");
      var td = el("td", "muted", "noch nichts gesehen");
      td.colSpan = 7;
      tr.appendChild(td);
      body.replaceChildren(tr);
    } else {
      body.replaceChildren.apply(body, clients.map(function (c) {
        var row = el("tr");
        row.appendChild(el("td", null, c.ip));
        row.appendChild(el("td", c.active ? "live" : "muted", c.active ? "aktiv" : "beendet"));
        row.appendChild(el("td", "r", c.flows ? String(c.flows) : "–"));
        row.appendChild(el("td", "r", m.accounted ? bytes(c.bytesUp) : "–"));
        row.appendChild(el("td", "r", m.accounted ? bytes(c.bytesDown) : "–"));
        row.appendChild(el("td", "r", String(c.sessions)));
        row.appendChild(el("td", null, new Date(c.lastSeen).toLocaleString("de-DE", {
          day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit"
        })));
        return row;
      }));
    }
    set("clients-note", m.accounted
      ? "Adressen und Datenmengen kommen aus conntrack – Zustand, den der Kernel fuer die Uebersetzung ohnehin fuehrt."
      : "Datenmengen pro Client fehlen: net.netfilter.nf_conntrack_acct=0. Adressen und Flows sind trotzdem sichtbar.");
  }

  function renderChecks(checks) {
    var list = document.getElementById("checks");
    if (!list) return;
    list.replaceChildren.apply(list, (checks || []).map(function (c) {
      var li = el("li", c.level);
      li.appendChild(el("span", "dot"));
      li.appendChild(el("strong", null, c.name));
      li.appendChild(el("span", null, c.message));
      return li;
    }));
  }

  function renderCounters(counters) {
    var body = document.getElementById("counters");
    if (!body) return;
    if (!counters || counters.length === 0) {
      var tr = el("tr");
      var td = el("td", "muted", "keine Regeln geladen");
      td.colSpan = 4;
      tr.appendChild(td);
      body.replaceChildren(tr);
      return;
    }
    body.replaceChildren.apply(body, counters.map(function (c) {
      var tr = el("tr");
      tr.appendChild(el("td", null, c.label));
      tr.appendChild(el("td", null, c.chain));
      tr.appendChild(el("td", "r", num(c.packets)));
      tr.appendChild(el("td", "r", bytes(c.bytes)));
      return tr;
    }));
  }

  function renderEvents(evts) {
    var list = document.getElementById("events");
    if (!list) return;
    if (!evts || evts.length === 0) {
      list.replaceChildren(el("li", "muted", "noch nichts passiert"));
      return;
    }
    list.replaceChildren.apply(list, evts.map(function (e) {
      var li = el("li", e.level);
      var d = new Date(e.time);
      li.appendChild(el("time", null, d.toLocaleString("de-DE", {
        day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit"
      })));
      li.appendChild(el("span", null, e.message));
      return li;
    }));
  }

  function renderToggle(s) {
    var form = document.querySelector("form.toggle");
    if (!form) return;
    var enable = form.querySelector("input[name=enable]");
    var button = form.querySelector("button");
    enable.value = s.enabled ? "0" : "1";
    button.textContent = s.enabled ? "Jetzt abschalten" : "Weiterleitung einschalten";
    button.className = s.enabled ? "danger" : "primary";
    button.disabled = !s.enabled && !s.target;
  }

  function apply(s) {
    var pill = document.getElementById("pill");
    if (pill) {
      pill.textContent = s.enabled ? "Weiterleitung AN" : "Weiterleitung AUS";
      pill.className = "pill " + (s.enabled ? "on" : "off");
    }
    set("last-arrow", s.enabled ? "→" : "✗");
    set("tableloaded", s.tableLoaded ? "geladen" : "nicht geladen");
    set("flows", s.activeFlows < 0 ? "unbekannt" : String(s.activeFlows));
    set("nextoff", s.nextOff ? s.nextOff + " (in " + s.nextOffIn + ")" : "keine");
    set("since", s.enabledSince ? s.enabledSince : "–");
    set("clock", new Date(s.now).toLocaleString("de-DE"));
    if (s.metrics) {
      renderChart(s.metrics);
      renderClients(s.metrics);
    }
    renderChecks(s.checks);
    renderCounters(s.counters);
    renderEvents(s.events);
    renderToggle(s);
  }

  function poll() {
    fetch("/api/status", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(apply)
      .catch(function () { /* keep the last good picture */ });
  }

  setInterval(poll, 2000);
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) poll();
  });
})();
