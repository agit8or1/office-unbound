/* Office Unbound for OpenCloud Web (loaded through web.config.scripts, same origin, allowed by script-src 'self'):
   1. the top bar's lockup "Office Unbound | Files" (docs/design/app-shell.md): "Office Unbound" is the link back to the portal (the
      Dashboard), "Files" names the app. The top bar is rendered by Vue and may be re-rendered: re-add the lockup whenever it is missing.
   2. the list view as the first default (the concept's file list): OpenCloud Web 8.2.2 hard-codes the tile view as its default
      (resource-tiles) and keeps the user's choice in localStorage "oc-options_view-mode". The list is written there once per browser;
      a user who then picks the tiles keeps them (OpenCloud removes the key when the choice equals its default, the marker stays). */
(function () {
  "use strict";
  var HOME = "@PORTAL_URL@";
  var APP = "Files";
  try {
    if (!localStorage.getItem("ou-view-mode-default")) {
      if (!localStorage.getItem("oc-options_view-mode")) { localStorage.setItem("oc-options_view-mode", "resource-table"); }
      localStorage.setItem("ou-view-mode-default", "resource-table");
    }
  } catch (e) { /* storage blocked: OpenCloud's own default applies */ }
  function add() {
    if (document.getElementById("ou-home")) { return; }
    var slot = document.querySelector("#oc-topbar .oc-logo-wrapper");
    if (!slot) { return; }
    var brand = document.createElement(HOME ? "a" : "span");
    brand.id = "ou-home";
    brand.className = "ou-home";
    if (HOME) {
      brand.href = HOME;
      brand.title = "Back to your Office Unbound dashboard";
    }
    brand.textContent = "Office Unbound";
    var app = document.createElement("span");
    app.className = "ou-app-name";
    app.textContent = APP;
    slot.appendChild(brand);
    slot.appendChild(app);
  }
  new MutationObserver(add).observe(document.documentElement, { childList: true, subtree: true });
  add();
})();
