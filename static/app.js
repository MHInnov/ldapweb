// Arbor — comportements côté client (aucun eval : compatible CSP stricte).
(function () {
  "use strict";

  // ---------------------------------------------------------------- thème
  function applyTheme(t) {
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
    else document.documentElement.removeAttribute("data-theme");
  }
  try { applyTheme(localStorage.getItem("arbor-theme")); } catch (e) { /* stockage indisponible */ }

  // ---------------------------------------------------------------- notifications
  function toast(msg, level) {
    var box = document.getElementById("toasts");
    if (!box) { alert(msg); return; }
    var el = document.createElement("div");
    el.className = "toast " + (level || "info");
    el.setAttribute("role", level === "error" ? "alert" : "status");
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(function () { el.remove(); }, level === "error" ? 9000 : 4500);
    el.addEventListener("click", function () { el.remove(); });
  }
  window.arborToast = toast;

  // ---------------------------------------------------------------- dialogues
  function openDialogs(root) {
    (root || document).querySelectorAll("dialog.modal:not([open])").forEach(function (d) {
      if (!d.isConnected) return;
      try { d.showModal(); } catch (e) { d.setAttribute("open", ""); }
      var f = d.querySelector("[autofocus]");
      if (f) f.focus();
      d.addEventListener("close", function () {
        var host = d.parentElement;
        d.remove();
        if (host && host.id === "modal2" && host.innerHTML.trim() === "") host.innerHTML = "";
      }, { once: true });
    });
  }
  function closeTop() {
    var ds = document.querySelectorAll("dialog.modal[open]");
    if (ds.length) ds[ds.length - 1].close();
  }

  document.addEventListener("htmx:afterSwap", function (ev) {
    var t = ev.detail.target;
    if (t && (t.id === "modal" || t.id === "modal2")) openDialogs(t);
    initSelection(t || document);
  });
  document.addEventListener("htmx:afterSettle", function (ev) { openDialogs(ev.detail.target); });
  document.addEventListener("DOMContentLoaded", function () { openDialogs(document); initSelection(document); });

  document.addEventListener("close-modal", closeTop);
  document.addEventListener("close-all-modals", function () {
    document.querySelectorAll("dialog.modal[open]").forEach(function (d) { d.close(); });
  });
  document.addEventListener("toast", function (ev) {
    var d = ev.detail || {};
    toast(d.msg || "", d.level === "ok" ? "ok" : d.level === "warn" ? "warn" : d.level === "error" ? "error" : "info");
  });

  // ---------------------------------------------------------------- jeton anti-CSRF
  document.addEventListener("htmx:configRequest", function (ev) {
    var m = document.querySelector('meta[name="csrf-token"]');
    if (m) ev.detail.headers["X-CSRF-Token"] = m.getAttribute("content");
  });

  // ---------------------------------------------------------------- erreurs htmx
  document.addEventListener("htmx:responseError", function (ev) {
    var xhr = ev.detail.xhr;
    var msg = xhr.getResponseHeader("X-Error-Message");
    if (msg) { try { msg = decodeURIComponent(msg); } catch (e) { /* tel quel */ } }
    toast(msg || ("Erreur " + xhr.status), "error");
  });
  document.addEventListener("htmx:sendError", function () { toast("Serveur injoignable", "error"); });
  document.addEventListener("htmx:timeout", function () { toast("Délai dépassé", "error"); });
  document.addEventListener("htmx:beforeRequest", function () { document.body.classList.add("busy"); });
  document.addEventListener("htmx:afterRequest", function () { document.body.classList.remove("busy"); });

  // ---------------------------------------------------------------- actions déclaratives
  function randomPassword(n) {
    var sets = ["abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!#%+-=?@_"];
    var all = sets.join("");
    var buf = new Uint32Array(n + sets.length);
    crypto.getRandomValues(buf);
    var out = sets.map(function (s, i) { return s[buf[i] % s.length]; });
    for (var i = sets.length; out.length < n; i++) out.push(all[buf[i] % all.length]);
    for (var j = out.length - 1; j > 0; j--) { var k = buf[j] % (j + 1); var t = out[j]; out[j] = out[k]; out[k] = t; }
    return out.join("");
  }

  document.addEventListener("click", function (ev) {
    document.querySelectorAll("details.menu[open]").forEach(function (d) { if (!d.contains(ev.target) || ev.target.closest(".menu-items")) d.removeAttribute("open"); });
    var el = ev.target.closest("[data-action],[data-close],[data-pick],[data-copy],[data-tab]");
    if (!el) return;
    if (el.hasAttribute("data-close")) { ev.preventDefault(); closeTop(); return; }
    if (el.hasAttribute("data-copy")) {
      ev.preventDefault();
      var src = document.querySelector(el.getAttribute("data-copy"));
      var txt = src ? (src.value !== undefined && src.tagName !== "DIV" && src.tagName !== "SPAN" ? src.value : src.textContent) : "";
      if (navigator.clipboard) navigator.clipboard.writeText(txt.trim()).then(function () { toast("Copié dans le presse-papiers", "ok"); });
      return;
    }
    if (el.hasAttribute("data-tab")) {
      el.parentElement.querySelectorAll("button").forEach(function (b) { b.classList.remove("active"); });
      el.classList.add("active");
      return;
    }
    if (el.hasAttribute("data-pick")) {
      // Sélection dans un sélecteur d'objets : renseigne le champ cible
      ev.preventDefault();
      var target = document.getElementById(el.getAttribute("data-pick-target"));
      if (target) {
        target.value = el.getAttribute("data-pick");
        target.dispatchEvent(new Event("change", { bubbles: true }));
      }
      closeTop();
      return;
    }
    var a = el.getAttribute("data-action");
    if (a === "theme") {
      var cur = document.documentElement.getAttribute("data-theme");
      var dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      var next = cur ? (cur === "dark" ? "light" : "dark") : (dark ? "light" : "dark");
      applyTheme(next);
      try { localStorage.setItem("arbor-theme", next); } catch (e) { /* ignore */ }
    } else if (a === "genpw") {
      ev.preventDefault();
      var pw = randomPassword(16);
      (el.getAttribute("data-targets") || "").split(",").forEach(function (id) {
        var i = document.getElementById(id.trim());
        if (i) { i.value = pw; i.type = "text"; }
      });
    } else if (a === "reveal") {
      ev.preventDefault();
      var t2 = document.getElementById(el.getAttribute("data-target"));
      if (t2) t2.classList.toggle("hidden");
    } else if (a === "select-all") {
      var table = el.closest("table");
      table.querySelectorAll("tbody input[type=checkbox][name=dn]").forEach(function (c) { c.checked = el.checked; });
      updateSelection(table);
    } else if (a === "clear-field") {
      ev.preventDefault();
      var f = document.getElementById(el.getAttribute("data-target"));
      if (f) f.value = "";
    }
  });

  // Double-clic sur une ligne de conteneur : ouvrir
  document.addEventListener("dblclick", function (ev) {
    var tr = ev.target.closest("tr[data-open]");
    if (tr && window.htmx) {
      htmx.ajax("GET", tr.getAttribute("data-open"), {
        target: tr.getAttribute("data-open-target") || "#modal",
        swap: tr.getAttribute("data-open-swap") || "innerHTML"
      });
    }
  });

  // ---------------------------------------------------------------- sélection multiple
  function updateSelection(table) {
    if (!table) return;
    var n = 0;
    table.querySelectorAll("tbody input[type=checkbox][name=dn]").forEach(function (c) {
      var tr = c.closest("tr");
      if (c.checked) { n++; tr.classList.add("sel"); } else tr.classList.remove("sel");
    });
    var scope = table.closest("[data-selection-scope]") || document;
    scope.querySelectorAll("[data-needs-selection]").forEach(function (b) { b.disabled = n === 0; });
    scope.querySelectorAll("[data-selection-count]").forEach(function (s) { s.textContent = n ? n + " sélectionné(s)" : ""; });
  }
  function initSelection(root) {
    if (!root || !root.querySelectorAll) return;
    root.querySelectorAll("table[data-selectable]").forEach(function (t) { updateSelection(t); });
  }
  document.addEventListener("change", function (ev) {
    if (ev.target.matches("tbody input[type=checkbox][name=dn]")) updateSelection(ev.target.closest("table"));
    var s = ev.target.closest("select[data-show-when]");
    if (s) toggleDependents(s.form || document);
  });

  // Champs dépendants (ex. type d'enregistrement DNS)
  function toggleDependents(root) {
    root.querySelectorAll("[data-when]").forEach(function (el) {
      var parts = el.getAttribute("data-when").split("=");
      var src = root.querySelector("[name='" + parts[0] + "']");
      if (!src) return;
      var vals = parts[1].split("|");
      var show = vals.indexOf(src.value) >= 0;
      el.classList.toggle("hidden", !show);
      el.querySelectorAll("input,select,textarea").forEach(function (i) { i.disabled = !show; });
    });
  }
  document.addEventListener("htmx:load", function (ev) {
    var forms = ev.detail.elt.querySelectorAll ? ev.detail.elt.querySelectorAll("form") : [];
    forms.forEach(toggleDependents);
  });

  // Filtrage instantané de tableaux / listes
  document.addEventListener("input", function (ev) {
    var sel = ev.target.getAttribute && ev.target.getAttribute("data-filter-table");
    if (!sel) return;
    var q = ev.target.value.trim().toLowerCase();
    var root = document.querySelector(sel);
    if (!root) return;
    root.querySelectorAll("tbody tr, li").forEach(function (r) {
      var key = (r.getAttribute("data-name") || r.textContent).toLowerCase();
      r.classList.toggle("hidden", q !== "" && key.indexOf(q) < 0);
    });
  });

  // Échap : fermer le dialogue au premier plan (comportement natif) ; nettoyage
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "/" && !ev.target.closest("input,textarea,select")) {
      var q = document.querySelector(".quicksearch input");
      if (q) { ev.preventDefault(); q.focus(); }
    }
  });
})();
