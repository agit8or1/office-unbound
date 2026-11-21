/* Office Unbound: the "Dashboard" link back to the portal in OpenCloud Web's top bar (loaded through web.config.scripts, same origin,
   allowed by script-src 'self'). The top bar is rendered by Vue and may be re-rendered: re-add the link whenever it is missing. */
(function () {
  "use strict";
  var HOME = "@PORTAL_URL@";
  function add() {
    if (document.getElementById("ou-home")) { return; }
    var slot = document.querySelector("#oc-topbar .oc-logo-wrapper");
    if (!slot) { return; }
    var a = document.createElement("a");
    a.id = "ou-home";
    a.className = "ou-home";
    a.href = HOME;
    a.title = "Back to your dashboard";
    a.textContent = "Dashboard";
    slot.appendChild(a);
  }
  new MutationObserver(add).observe(document.documentElement, { childList: true, subtree: true });
  add();
})();
