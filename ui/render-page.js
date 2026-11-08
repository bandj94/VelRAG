/* /render/{turn_id}: render one delivered answer with the shared renderer. */
(function () {
  "use strict";
  function run() {
    var el = document.getElementById("answer");
    if (!el || !window.VelRenderer) { return; }
    window.VelRenderer.renderInto(el, el.getAttribute("data-answer") || "");
    document.body.setAttribute("data-rendered", "1");
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", run);
  } else {
    run();
  }
})();
