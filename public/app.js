// Theme toggle and small UI behaviours. Theme follows the OS unless the viewer picks light or dark; the choice is remembered in this browser only.
(function () {
  var root = document.documentElement;
  try { var saved = localStorage.getItem("sas-theme"); if (saved) root.setAttribute("data-theme", saved); } catch (e) {}
  function current() {
    var t = root.getAttribute("data-theme");
    if (t) return t;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  function label() {
    var el = document.getElementById("theme-label");
    if (el) el.textContent = current() === "dark" ? "Light mode" : "Dark mode";
  }
  // Evidence drawer: close button and Escape key empty it, which hides it.
  document.addEventListener("click", function (e) {
    if (e.target.closest("[data-close-drawer]")) { var d = document.getElementById("drawer"); if (d) d.innerHTML = ""; }
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") { var d = document.getElementById("drawer"); if (d) d.innerHTML = ""; }
  });
  document.addEventListener("DOMContentLoaded", function () {
    label();
    var btn = document.getElementById("theme-toggle");
    if (!btn) return;
    btn.addEventListener("click", function () {
      var next = current() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("sas-theme", next); } catch (e) {}
      label();
    });
  });
})();
