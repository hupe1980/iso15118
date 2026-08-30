/* Two behaviours, no dependencies: the theme toggle and documentation search.
   Both degrade to nothing useful being lost if the script never runs — the
   theme still follows the system, and every page is reachable from the nav. */

(function () {
  "use strict";

  /* --- theme ------------------------------------------------------------ */

  var root = document.documentElement;
  var toggle = document.getElementById("theme-toggle");

  function systemPrefersDark() {
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  }

  function apply(theme) {
    root.dataset.theme = theme;
    /* The syntax sheets are picked by media query when no theme is chosen; an
       explicit choice has to override that, so their media is set outright. */
    document.querySelectorAll("link[data-syntax]").forEach(function (link) {
      link.media = link.dataset.syntax === theme ? "all" : "not all";
    });
    try { localStorage.setItem("theme", theme); } catch (e) {}
  }

  if (toggle) {
    toggle.addEventListener("click", function () {
      var current = root.dataset.theme || (systemPrefersDark() ? "dark" : "light");
      apply(current === "dark" ? "light" : "dark");
    });
  }

  /* --- search ----------------------------------------------------------- */

  var input = document.querySelector("[data-search]");
  var results = document.querySelector("[data-search-results]");
  if (!input || !results) return;

  var index = null;
  var loading = false;

  function load() {
    if (index || loading) return Promise.resolve();
    loading = true;
    return fetch(input.dataset.index)
      .then(function (r) { return r.json(); })
      .then(function (data) { index = data; })
      .catch(function () { index = []; });
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  /* A snippet around the first hit tells a reader why a page matched, which is
     most of what a small index can offer over a plain title list. */
  function snippet(body, query) {
    var at = body.toLowerCase().indexOf(query);
    if (at < 0) return body.slice(0, 110);
    var from = Math.max(0, at - 40);
    return (from > 0 ? "…" : "") + body.slice(from, from + 130).trim() + "…";
  }

  function render(query) {
    results.innerHTML = "";
    if (!query) return;

    var q = query.toLowerCase();
    var hits = (index || []).map(function (page) {
      var title = page.t.toLowerCase();
      var desc = (page.d || "").toLowerCase();
      var body = (page.b || "").toLowerCase();
      var score = 0;
      if (title.indexOf(q) === 0) score = 100;
      else if (title.indexOf(q) >= 0) score = 60;
      else if (desc.indexOf(q) >= 0) score = 30;
      else if (body.indexOf(q) >= 0) score = 10;
      return { page: page, score: score };
    }).filter(function (h) { return h.score > 0; });

    hits.sort(function (a, b) { return b.score - a.score; });

    if (!hits.length) {
      results.innerHTML = '<li class="search-empty">No matches.</li>';
      return;
    }

    results.innerHTML = hits.slice(0, 8).map(function (h) {
      var p = h.page;
      var why = h.score >= 30 ? (p.d || "") : snippet(p.b || "", q);
      return '<li><a href="' + p.u + '"><strong>' + escapeHtml(p.t) +
             "</strong><span>" + escapeHtml(why) + "</span></a></li>";
    }).join("");
  }

  input.addEventListener("focus", load, { once: true });
  input.addEventListener("input", function () {
    var q = input.value.trim();
    if (!q) { render(""); return; }
    load().then(function () { render(q); });
  });
  input.addEventListener("keydown", function (e) {
    if (e.key === "Escape") { input.value = ""; render(""); input.blur(); }
    if (e.key === "ArrowDown") {
      var first = results.querySelector("a");
      if (first) { e.preventDefault(); first.focus(); }
    }
  });
})();
