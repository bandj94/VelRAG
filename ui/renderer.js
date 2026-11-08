/*
 * Shared renderer module (spec §6.7). Used by the chat UI and by /render/{turn_id}.
 *
 * The answer is converted from markdown to HTML in the browser with the vendored
 * `marked` library, passing images and raw HTML through, and inserted with
 * innerHTML. This is VULNERABLE BY DEFAULT on purpose:
 *   - <script> elements inserted through innerHTML never run;
 *   - event-handler attributes (onerror, onload, ...) DO run;
 *   - automatic loads (images, iframes) DO happen.
 * D2's Content-Security-Policy blocks the last two when D2 is on.
 */
(function () {
  "use strict";

  function toHtml(markdownText) {
    var lib = window.marked;
    if (lib && typeof lib.parse === "function") {
      return lib.parse(String(markdownText || ""), { gfm: true, breaks: false, async: false });
    }
    // The vendored library failed to load: fall back to plain text.
    var div = document.createElement("div");
    div.textContent = String(markdownText || "");
    return div.innerHTML;
  }

  function renderInto(element, markdownText) {
    element.innerHTML = toHtml(markdownText);
  }

  window.VelRenderer = { toHtml: toHtml, renderInto: renderInto };
})();
