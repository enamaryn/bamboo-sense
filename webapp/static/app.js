"use strict";

const $ = (id) => document.getElementById(id);

function toast(msg, kind = "") {
  const t = $("toast");
  t.textContent = msg;
  t.className = "show " + kind;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.className = kind), 3200);
}

async function api(path, opts = {}) {
  const r = await fetch(path, opts);
  let data = {};
  try { data = await r.json(); } catch (_) {}
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}
const post = (path, body) =>
  api(path, { method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify(body || {}) });

function kv(el, obj) {
  el.style.display = "block";
  el.innerHTML = Object.entries(obj)
    .map(([k, v]) => `<div><span class="k">${k}</span><span class="v">${
      v === null || v === undefined ? "—" : String(v)
    }</span></div>`).join("");
}

// ---------------------------------------------------------------- state
let STATE = null;

function render() {
  const s = STATE;
  $("mqttState").textContent = s.have_mqtt ? "mqtt ready" : "mqtt: install paho";
  $("mqttState").className = "mqtt" + (s.have_mqtt ? " on" : "");

  // identity
  const id = s.identity;
  mark("s1", !!id);
  if (id) {
    $("idState").textContent = "identity ready";
    $("idState").className = "pill ok";
    kv($("idOut"), {
      CN: id.cn, cert_id: id.cert_id, serial_hex: id.serial_hex, created: id.created,
    });
    if (!$("genSerial").value) $("genSerial").value = id.serial;
    if (!$("pSerial").value) $("pSerial").value = id.serial;
  } else {
    $("idState").textContent = "no identity yet";
    $("idState").className = "pill no";
    $("idOut").style.display = "none";
  }

  // printer
  const p = s.printer;
  if (p.ip && !$("pIp").value) $("pIp").value = p.ip;
  if (p.serial && !$("pSerial").value) $("pSerial").value = p.serial;
  if (p.user_id && !$("pUid").value) $("pUid").value = p.user_id;
  const configured = p.ip && p.serial && p.has_access_code;
  mark("s2", !!configured);
  $("prState").textContent = configured ? "configured" : "not configured";
  $("prState").className = "pill " + (configured ? "ok" : "no");

  // install
  mark("s4", !!p.cert_installed);
  $("instState").textContent = p.cert_installed ? "installed" : "not installed";
  $("instState").className = "pill " + (p.cert_installed ? "ok" : "no");
}

function mark(stepId, done) {
  $(stepId).classList.toggle("done", done);
  $(stepId).textContent = done ? "✓" : stepId.slice(1);
}

async function refreshState() {
  STATE = await api("/api/state");
  render();
}

// ---------------------------------------------------------------- identity
$("btnGen").onclick = async () => {
  const serial = $("genSerial").value.trim();
  if (!serial) return toast("Enter the printer serial first", "bad");
  try {
    const { identity } = await post("/api/generate", {
      serial, prefix: $("genPrefix").value.trim(),
      days: parseInt($("genDays").value) || 3650,
    });
    toast("Identity minted — cert_id " + identity.cert_id.slice(0, 20) + "…", "ok");
    await refreshState();
  } catch (e) { toast(e.message, "bad"); }
};

// ---------------------------------------------------------------- printer
$("btnSavePrinter").onclick = async () => {
  try {
    await post("/api/printer/config", {
      ip: $("pIp").value.trim(), serial: $("pSerial").value.trim(),
      access_code: $("pCode").value.trim(), user_id: $("pUid").value.trim(),
    });
    toast("Printer saved", "ok");
    await refreshState();
  } catch (e) { toast(e.message, "bad"); }
};

// ---------------------------------------------------------------- usb
$("btnUsbScan").onclick = async () => {
  try {
    const { candidates } = await api("/api/usb/list");
    const box = $("usbList");
    if (!candidates.length) {
      box.innerHTML = `<div class="u"><span>No removable drives detected — type the path above.</span></div>`;
      return;
    }
    box.innerHTML = candidates.map((c) =>
      `<div class="u"><span>${c}</span><button data-p="${c}">Use</button></div>`).join("");
    box.querySelectorAll("button").forEach((b) => {
      b.onclick = () => { $("usbPath").value = b.dataset.p;
        $("usbImportPath").value = b.dataset.p + "/BambooSense"; };
    });
  } catch (e) { toast(e.message, "bad"); }
};

$("btnExport").onclick = async () => {
  const path = $("usbPath").value.trim();
  if (!path) return toast("Pick or type a USB folder", "bad");
  try {
    const r = await post("/api/usb/export", { path });
    $("usbOut").textContent = "Wrote " + r.files.join(", ") + "  →  " + r.folder;
    toast("Bundle written to USB", "ok");
  } catch (e) { toast(e.message, "bad"); }
};

$("btnImport").onclick = async () => {
  const path = $("usbImportPath").value.trim();
  if (!path) return toast("Enter the bundle path", "bad");
  try {
    const r = await post("/api/usb/import", { path });
    $("usbOut").textContent = "Loaded from " + r.loaded_from;
    toast("Bundle loaded into client", "ok");
    // clear inputs so render() refills from server state
    ["pIp", "pSerial", "pUid"].forEach((k) => ($(k).value = ""));
    await refreshState();
  } catch (e) { toast(e.message, "bad"); }
};

// ---------------------------------------------------------------- install
$("btnInstall").onclick = async () => {
  toast("Installing on printer…");
  try {
    const r = await post("/api/printer/install", {});
    $("installOut").textContent = r.installed
      ? "✓ Printer confirmed the certificate."
      : "No confirmation seen. Replies: " + JSON.stringify(r.security).slice(0, 300);
    toast(r.installed ? "Certificate installed" : "Install not confirmed", r.installed ? "ok" : "bad");
    await refreshState();
  } catch (e) { toast(e.message, "bad"); $("installOut").textContent = e.message; }
};

// ---------------------------------------------------------------- control
function showAck(r) {
  const ack = r.ack || {};
  kv($("ctlOut"), {
    command: (r.sent && r.sent.command) || ack.command || "—",
    result: ack.result || "(no ack)",
    reason: ack.reason, err_code: ack.err_code, sequence_id: ack.sequence_id,
  });
  if (ack.result === "SUCCESS") toast("SUCCESS", "ok");
  else if (ack.result) toast(ack.result + (ack.reason ? ": " + ack.reason : ""), "bad");
  else toast("Sent — no ack seen", "");
}

async function sendPrint(obj, note) {
  if (note) toast(note);
  try { showAck(await post("/api/printer/command", { print: obj })); }
  catch (e) { toast(e.message, "bad"); }
}

$("btnStatus").onclick = async () => {
  toast("Polling printer…");
  try {
    const r = await api("/api/printer/status");
    const s = r.summary || {};
    $("gcodeState").textContent = s.gcode_state || "(no report)";
    const cards = [
      ["progress", s.mc_percent != null ? s.mc_percent + "%" : "—"],
      ["layer", s.layer_num != null ? `${s.layer_num}/${s.total_layer_num ?? "?"}` : "—"],
      ["nozzle", s.nozzle_temper != null ? s.nozzle_temper + "°" : "—"],
      ["bed", s.bed_temper != null ? s.bed_temper + "°" : "—"],
      ["chamber", s.chamber_temper != null ? s.chamber_temper + "°" : "—"],
      ["eta min", s.mc_remaining_time ?? "—"],
    ];
    $("statGrid").innerHTML = cards.map(([l, n]) =>
      `<div class="stat"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");
    toast(r.report_count ? "Status updated" : "No report — check creds/IP", r.report_count ? "ok" : "bad");
  } catch (e) { toast(e.message, "bad"); }
};

$("btnLightOn").onclick  = async () => { try { await post("/api/printer/light", { on: true }); toast("Light on", "ok"); } catch (e) { toast(e.message, "bad"); } };
$("btnLightOff").onclick = async () => { try { await post("/api/printer/light", { on: false }); toast("Light off", "ok"); } catch (e) { toast(e.message, "bad"); } };

$("btnPause").onclick  = () => sendPrint({ command: "pause" }, "Pausing…");
$("btnResume").onclick = () => sendPrint({ command: "resume" }, "Resuming…");
$("btnStop").onclick   = () => { if (confirm("Stop the current print?")) sendPrint({ command: "stop" }, "Stopping…"); };
$("btnClear").onclick  = () => sendPrint({ command: "clean_print_error" }, "Clearing error…");
$("btnSpeed").onclick  = () => sendPrint({ command: "print_speed", param: $("speedSel").value }, "Setting speed…");
$("btnRaw").onclick    = () => {
  let obj;
  try { obj = JSON.parse($("rawCmd").value); }
  catch (e) { return toast("Invalid JSON: " + e.message, "bad"); }
  sendPrint(obj, "Sending…");
};

refreshState().catch((e) => toast(e.message, "bad"));
