/* Chat UI. No inline scripts or styles, so it works under D2's CSP. */
(function () {
  "use strict";

  var DEFAULT_USERS = {
    employee: "employee.user01@velmora.example",
    hr: "hr.user01@velmora.example",
    it_admin: "itadmin.user01@velmora.example"
  };

  var roleEl, emailEl, logEl, formEl, msgEl, sendEl, statusEl;

  function $(id) { return document.getElementById(id); }

  function setDefaultEmail() { emailEl.value = DEFAULT_USERS[roleEl.value] || ""; }

  function addUser(text) {
    var node = $("tpl-user").content.firstElementChild.cloneNode(true);
    node.querySelector(".who").textContent = emailEl.value + " (" + roleEl.value + ")";
    node.querySelector(".text").textContent = text;
    logEl.appendChild(node);
    node.scrollIntoView({ block: "end" });
  }

  function addBot(data, status) {
    var node = $("tpl-bot").content.firstElementChild.cloneNode(true);
    var answerEl = node.querySelector(".answer");
    if (status === 200) {
      window.VelRenderer.renderInto(answerEl, data.answer || "");
    } else {
      answerEl.textContent = "[" + status + "] " + (data.detail || "request failed");
      node.classList.add("error");
    }
    var cites = data.citations || [];
    node.querySelector(".citations").textContent = cites.length ? "Sources: " + cites.join(", ") : "";
    renderPending(node.querySelector(".pending"), data.turn_id, data.pending_actions || []);
    node.querySelector(".events pre").textContent = JSON.stringify(data.events || [], null, 2);
    logEl.appendChild(node);
    node.scrollIntoView({ block: "end" });
  }

  function renderPending(container, turnId, actions) {
    actions.forEach(function (a) {
      var box = document.createElement("div");
      box.className = "pending-action";
      var desc = document.createElement("div");
      desc.textContent = "Pending email to " + a.to + " — subject: " + a.subject;
      var body = document.createElement("pre");
      body.textContent = a.body;
      var ok = document.createElement("button");
      ok.textContent = "Send";
      var no = document.createElement("button");
      no.textContent = "Cancel";
      no.className = "secondary";
      function decide(approve) {
        ok.disabled = no.disabled = true;
        postJson("/api/confirm", { turn_id: turnId, action_id: a.action_id, approve: approve })
          .then(function (r) { desc.textContent += " → " + (r.data.status || r.status); });
      }
      ok.addEventListener("click", function () { decide(true); });
      no.addEventListener("click", function () { decide(false); });
      box.appendChild(desc); box.appendChild(body); box.appendChild(ok); box.appendChild(no);
      container.appendChild(box);
    });
  }

  function postJson(url, payload) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }).then(function (resp) {
      return resp.json().catch(function () { return {}; }).then(function (data) {
        return { status: resp.status, data: data };
      });
    });
  }

  function onSubmit(ev) {
    ev.preventDefault();
    var text = msgEl.value.trim();
    if (!text) { return; }
    addUser(text);
    msgEl.value = "";
    sendEl.disabled = true;
    postJson("/api/chat", { role: roleEl.value, user_email: emailEl.value, message: text })
      .then(function (r) { addBot(r.data, r.status); })
      .catch(function (e) { addBot({ detail: String(e) }, 0); })
      .then(function () { sendEl.disabled = false; msgEl.focus(); });
  }

  function init() {
    roleEl = $("role"); emailEl = $("email"); logEl = $("log"); formEl = $("form");
    msgEl = $("message"); sendEl = $("send"); statusEl = $("status");
    var params = new URLSearchParams(window.location.search);
    if (params.get("role") && DEFAULT_USERS[params.get("role")]) { roleEl.value = params.get("role"); }
    setDefaultEmail();
    if (params.get("user")) { emailEl.value = params.get("user"); }
    if (params.get("q")) { msgEl.value = params.get("q"); }
    roleEl.addEventListener("change", setDefaultEmail);
    formEl.addEventListener("submit", onSubmit);
    msgEl.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { formEl.requestSubmit(); }
    });
    fetch("/health").then(function (r) { return r.json(); }).then(function (h) {
      statusEl.textContent = "mode " + h.mode + " · preset " + h.preset + " · model " + h.model;
    }).catch(function () { statusEl.textContent = "server unreachable"; });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
