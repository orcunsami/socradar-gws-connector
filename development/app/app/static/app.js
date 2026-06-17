// Progressive enhancement for the connector admin UI.
// Loaded as an external file because the CSP (script-src falls back to 'self') blocks inline <script>
// AND inline on* handlers (onsubmit/onchange). So every behaviour below is wired with addEventListener.
(function () {
  "use strict";

  function wire() {
    var overlay = document.getElementById("scan-overlay");

    // 1) confirm-before-submit. Any <form data-confirm="message"> asks for confirmation first.
    //    The message is plain text from a data- attribute (Jinja HTML-escapes it on render and we read it
    //    via dataset, so there's no script-injection path the old inline confirm() had).
    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (e) {
        if (!window.confirm(form.dataset.confirm)) {
          e.preventDefault();
        }
      });
    });

    // 2) scan progress overlay. The scan is a synchronous (blocking) POST that PRG-redirects to Flagged
    //    Users. Native feedback is only the tab spinner, so <form data-scan> shows a full-screen overlay
    //    that says what's happening and to wait on this tab. Also disables the button (no double-run).
    //    Runs AFTER the confirm handler above, so a cancelled confirm won't flash the overlay.
    document.querySelectorAll("form[data-scan]").forEach(function (form) {
      form.addEventListener("submit", function (e) {
        if (e.defaultPrevented) return;            // a data-confirm on the same form said no
        var btn = form.querySelector("button[type=submit], button");
        if (btn) {
          btn.disabled = true;
          if (btn.dataset.busyText) btn.textContent = btn.dataset.busyText;
        }
        if (overlay) overlay.hidden = false;
      });
    });

    // 3) auto-submit selects. <select data-autosubmit> submits its form on change (replaces the
    //    CSP-blocked inline onchange used by the tenant switcher).
    document.querySelectorAll("select[data-autosubmit]").forEach(function (sel) {
      sel.addEventListener("change", function () {
        if (sel.form) sel.form.submit();
      });
    });

    // 4) tabbed forms. <form data-tabs> with .tab buttons (data-tab) over .tabpanel (data-panel) sections.
    //    The server renders ALL panels visible (so the form still works with JS off); we enhance it to show
    //    one section at a time. All inputs stay in the form, so Save still submits every tab.
    document.querySelectorAll("form[data-tabs]").forEach(function (form) {
      var tabs = form.querySelectorAll(".tab");
      var panels = form.querySelectorAll(".tabpanel");
      if (!tabs.length || !panels.length) return;
      function activate(name) {
        tabs.forEach(function (t) { t.classList.toggle("active", t.dataset.tab === name); });
        panels.forEach(function (p) { p.hidden = (p.dataset.panel !== name); });
      }
      tabs.forEach(function (t) {
        t.addEventListener("click", function () { activate(t.dataset.tab); });
      });
      activate(tabs[0].dataset.tab);   // show only the first tab once JS is in control
    });

    // 5) live scan progress. Flagged Users renders #scan-live while a budget-chunked scan is still running;
    //    drive the remaining chunks by POSTing /scans/{id}/tick in a SEQUENTIAL loop (next chunk only after the
    //    previous returns) and update the live counts. On done/stale, reload to show the final list. No bg thread.
    var live = document.getElementById("scan-live");
    if (live && live.dataset.scanLive) {
      var sid = live.dataset.scanLive, tok = live.dataset.csrf || "";
      var setTxt = function (id, v) { var el = document.getElementById(id); if (el != null && v != null) el.textContent = v; };
      var tick = function () {
        var body = new URLSearchParams(); body.set("csrf", tok);
        fetch("/scans/" + encodeURIComponent(sid) + "/tick", {
          method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: body.toString(), credentials: "same-origin"
        }).then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
          .then(function (p) {
            if (p.stale || p.done) { window.location.reload(); return; }
            setTxt("scan-live-found", p.found);
            setTxt("scan-live-sources", p.sources_done);
            if (p.source) setTxt("scan-live-cur", p.source);
            if (p.page) setTxt("scan-live-page", p.page);
            setTimeout(tick, 800);
          })
          .catch(function () { setTimeout(tick, 3000); });   // transient error -> back off + retry
      };
      setTimeout(tick, 600);
    }
  }

  // bfcache reset: if the page is restored from the back/forward cache, its frozen DOM may still show the
  // scan overlay over a non-running scan and leave the submit button disabled. Reset that state on restore.
  window.addEventListener("pageshow", function (e) {
    if (!e.persisted) return;
    var overlay = document.getElementById("scan-overlay");
    if (overlay) overlay.hidden = true;
    document.querySelectorAll("button[disabled]").forEach(function (b) { b.disabled = false; });
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
