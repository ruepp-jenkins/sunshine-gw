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
