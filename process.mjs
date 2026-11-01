import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  parseProcStat, parseProcStatus, parsePS, cpuPercent,
  mergePlatforms, totals, groupByOwner, endTaskDecision,
  redactCommandLine, confirmationFor, processKey, pushRing, PROTECTED_NAMES,
} from "./lib.mjs";

const execFileP = promisify(execFile);
const PORT = Number(process.env.PICODE_EXT_PORT || 8799);
const EXT_DIR = process.env.PICODE_EXT_DIR || process.cwd();
const DATA = process.env.PICODE_EXT_DATA || path.join(os.tmpdir(), "taskboard-data");
const SECRET = process.env.PICODE_EXT_PROXY_SECRET || "";
const HOST = process.env.PICODE_URL || "";
const TOKEN = process.env.PICODE_EXT_TOKEN || "";
const CA = process.env.PICODE_CA_FILE || "";
const PLATFORM = process.platform;
const TEST = process.env.TASKBOARD_TEST === "1";
const NOWIN = process.env.TASKBOARD_NOWIN === "1";
let IS_WSL = false;
if (PLATFORM === "linux") {
  try {
    IS_WSL = !!(process.env.WSL_DISTRO_NAME || process.env.WSL_INTEROP) || /microsoft/i.test(fs.readFileSync("/proc/version", "utf8"));
  } catch { /* a native Linux host has no Windows side */ }
}

let VERSION = "0.1.0";
try { VERSION = JSON.parse(fs.readFileSync(path.join(EXT_DIR, "picode-extension.json"), "utf8")).version; } catch { /* keep */ }

fs.mkdirSync(DATA, { recursive: true });

const DEFAULTS = { update_ms: "2000", show_windows: true, alerts: false };
const state = {
  startedAt: Date.now(),
  settings: { ...DEFAULTS },
  identity: null,
  agents: [],
  workspaces: [],
  tmux: [],
  sample: null,
  paused: false,
  lastPageAt: 0,
  lastSampleAt: 0,
  pageInterval: null,
  windowsReason: "",
  windowsBackoffUntil: 0,
  protect: new Set([1, process.pid]),
  ancestors: new Set(),
  prev: new Map(),
  rings: new Map(),
  totalsRing: [],
  memRing: [],
  ops: new Map(),
  alerts: new Map(),
  cwd: new Map(),
  prevStat: null,
  prevWinSys: null,
  hostError: "",
  hostOk: false,
};
let inFlight = null;
let timer = null;

function log(...args) { console.log(new Date().toISOString(), ...args); }

function json(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(text), "Cache-Control": "no-store" });
  res.end(text);
}

function readBody(req, limit = 32768) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (d) => {
      size += d.length;
      if (size > limit) { reject(new Error("body too large")); req.destroy(); return; }
      chunks.push(d);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function hostRequest(method, target, body) {
  return new Promise((resolve, reject) => {
    if (!HOST || !TOKEN) return reject(new Error("Host API is not available"));
    let u;
    try { u = new URL(target, HOST); } catch (e) { return reject(e); }
    const isTls = u.protocol === "https:";
    const mod = isTls ? https : http;
    const text = body == null ? "" : JSON.stringify(body);
    const opts = {
      method,
      headers: {
        "X-PiCode-Extension-Token": TOKEN,
        ...(text ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) } : {}),
      },
    };
    if (isTls && CA) { try { opts.ca = fs.readFileSync(CA); } catch { /* default store */ } }
    const req = mod.request(u, opts, (res) => {
      let raw = "";
      res.setEncoding("utf8");
      res.on("data", (d) => { raw += d; });
      res.on("end", () => {
        if (res.statusCode < 200 || res.statusCode >= 300) return reject(new Error("Host API " + res.statusCode + (raw ? ": " + raw.slice(0, 200) : "")));
        if (!raw) return resolve(null);
        try { resolve(JSON.parse(raw)); } catch (e) { reject(e); }
      });
    });
    req.on("error", reject);
    req.setTimeout(4000, () => req.destroy(new Error("Host API timeout")));
    if (text) req.write(text);
    req.end();
  });
}

const hostGet = (target) => hostRequest("GET", target);
const hostPost = (target, body) => hostRequest("POST", target, body);

async function loadSettings() {
  if (!HOST || !TOKEN) return;
  try {
    const out = await hostGet("/api/ext/v1/settings");
    const values = out && out.values ? out.values : {};
    state.settings = {
      update_ms: String(values.update_ms || DEFAULTS.update_ms),
      show_windows: values.show_windows !== false,
      alerts: values.alerts === true,
    };
  } catch (e) {
    if (!state.hostError) log("settings:", e.message);
  }
}

async function loadIdentity() {
  if (!HOST || !TOKEN) return;
  try {
    state.identity = await hostGet("/api/ext/v1/me");
    state.hostOk = true;
  } catch (e) {
    state.hostError = e.message;
  }
}

async function loadAgents() {
  if (!HOST || !TOKEN) return;
  try {
    const [agents, workspaces] = await Promise.all([hostGet("/api/ext/v1/agents"), hostGet("/api/ext/v1/workspaces")]);
    state.agents = Array.isArray(agents?.agents) ? agents.agents : [];
    state.workspaces = Array.isArray(workspaces?.workspaces) ? workspaces.workspaces : [];
    state.hostOk = true;
    state.hostError = "";
  } catch (e) {
    state.hostError = e.message;
  }
}

function workspaceById(id) {
  return state.workspaces.find((w) => w.id === id) || null;
}

function workspaceForPath(cwd) {
  if (!cwd) return null;
  let best = null;
  for (const w of state.workspaces) {
    if (!w.path) continue;
    const root = w.path.endsWith(path.sep) ? w.path : w.path + path.sep;
    if ((cwd === w.path || cwd.startsWith(root)) && (!best || w.path.length > best.path.length)) best = w;
  }
  return best;
}

async function refreshTmux() {
  state.tmux = [];
  const dataDir = state.identity && state.identity.dataDir;
  if (!dataDir) return;
  const socket = path.join(dataDir, "tmux.sock");
  if (!fs.existsSync(socket)) return;
  try {
    const { stdout } = await execFileP("tmux", ["-S", socket, "list-panes", "-a", "-F", "#{session_name}\t#{pane_pid}\t#{pane_current_path}\t#{pane_current_command}"], { timeout: 2500, maxBuffer: 1 << 20 });
    for (const line of String(stdout || "").split("\n")) {
      const [session, pid, cwd, command] = line.split("\t");
      if (!session || !/^\d+$/.test(String(pid || ""))) continue;
      const m = /^picode-(?:sh-|as-)?(.+)$/.exec(session);
      const id = m ? m[1] : "";
      const agent = state.agents.find((a) => a.id === id) || null;
      const ws = (agent && workspaceById(agent.workspaceId)) || workspaceForPath(cwd);
      if (!agent && !ws) continue;
      state.tmux.push({
        session, pid: Number(pid), cwd: cwd || "", command: command || "",
        owner: {
          agent: agent ? agent.name : "",
          workspace: ws ? ws.name : "",
          workspaceId: ws ? ws.id : "",
          confidence: agent ? "exact" : "exact",
        },
      });
    }
  } catch { /* tmux is optional */ }
}

function ancestorPids() {
  const out = new Set();
  if (PLATFORM !== "linux") return out;
  let pid = process.pid;
  for (let i = 0; i < 16 && pid > 1; i++) {
    let text = "";
    try { text = fs.readFileSync("/proc/" + pid + "/stat", "utf8"); } catch { break; }
    const p = parseProcStat(text);
    if (!p || p.ppid <= 0) break;
    out.add(p.ppid);
    pid = p.ppid;
  }
  return out;
}

function refreshProtect() {
  state.ancestors = ancestorPids();
  state.protect = new Set([1, process.pid, ...state.ancestors]);
  if (PLATFORM === "win32") {
    state.protect.add(0).add(4);
    if (process.ppid > 0) state.protect.add(process.ppid);
  }
}

function cpuStat() {
  try {
    const line = fs.readFileSync("/proc/stat", "utf8").split("\n")[0];
    const f = line.trim().split(/\s+/).slice(1, 9).map(Number);
    if (f.length < 4 || f.some((n) => !Number.isFinite(n))) return null;
    const idle = f[3] + (f[4] || 0);
    const total = f.reduce((a, b) => a + b, 0);
    return { at: Date.now(), total, idle };
  } catch { return null; }
}

function memInfo() {
  try {
    const text = fs.readFileSync("/proc/meminfo", "utf8");
    const grab = (key) => {
      const m = new RegExp("^" + key + ":\\s+(\\d+)", "m").exec(text);
      return m ? Number(m[1]) * 1024 : 0;
    };
    return { total: grab("MemTotal"), available: grab("MemAvailable") };
  } catch { return { total: 0, available: 0 }; }
}

function linuxProcesses() {
  const out = [];
  const uid = typeof process.getuid === "function" ? process.getuid() : -1;
  const cpus = os.cpus().length || 1;
  const now = Date.now();
  let names;
  try { names = fs.readdirSync("/proc"); } catch { return out; }
  for (const name of names) {
    if (!/^\d+$/.test(name)) continue;
    let text;
    try { text = fs.readFileSync("/proc/" + name + "/stat", "utf8"); } catch { continue; }
    const p = parseProcStat(text);
    if (!p) continue;
    let owner = uid;
    try { owner = fs.statSync("/proc/" + name).uid; } catch { /* keep our uid */ }
    const key = processKey("linux", p.pid, p.startKey);
    const prev = state.prev.get(key);
    p.cpuPct = prev ? cpuPercent(prev.cpuSeconds, p.cpuSeconds, now - prev.at, cpus) : null;
    p.sameUser = owner === uid;
    p.uid = owner;
    p.readBytes = 0;
    p.writeBytes = 0;
    if (p.sameUser) {
      try {
        const io = fs.readFileSync("/proc/" + name + "/io", "utf8");
        const r = /^read_bytes:\s+(\d+)/m.exec(io);
        const w = /^write_bytes:\s+(\d+)/m.exec(io);
        if (r) p.readBytes = Number(r[1]);
        if (w) p.writeBytes = Number(w[1]);
      } catch { /* the kernel can hide io */ }
    }
    p.diskBps = null;
    if (prev && now - prev.at <= 30000) {
      const io = (Number(p.readBytes) || 0) + (Number(p.writeBytes) || 0);
      const before = Number(prev.io) || 0;
      if (io >= before) p.diskBps = Math.round((io - before) / ((now - prev.at) / 1000));
    }
    out.push(p);
  }
  const next = new Map();
  for (const p of out) next.set(processKey("linux", p.pid, p.startKey), { cpuSeconds: p.cpuSeconds, at: now, io: (Number(p.readBytes) || 0) + (Number(p.writeBytes) || 0) });
  for (const [key, value] of state.prev) if (key.startsWith("win:") && now - value.at < 60000) next.set(key, value);
  state.prev = next;
  return out;
}

function helperPath() {
  const arch = process.arch === "arm64" ? "arm64" : "amd64";
  return path.join(EXT_DIR, "bin", "picode-proc-windows-" + arch + ".exe");
}

async function windowsSide() {
  const applicable = PLATFORM === "win32" || IS_WSL;
  if (!applicable) {
    return { applicable: false, available: false, reason: "This computer is not running Windows.", processes: [], sys: null };
  }
  if (NOWIN || !state.settings.show_windows) {
    return { applicable: true, available: false, reason: NOWIN ? "The Windows helper is off in this environment." : "Windows apps are off in the extension settings.", processes: [], sys: null };
  }
  if (Date.now() < state.windowsBackoffUntil) {
    return { applicable: true, available: false, reason: state.windowsReason || "The Windows helper is unavailable.", processes: [], sys: null };
  }
  const exe = helperPath();
  if (!fs.existsSync(exe)) {
    state.windowsReason = "The Windows helper is missing from this package.";
    state.windowsBackoffUntil = Date.now() + 60000;
    return { applicable: true, available: false, reason: state.windowsReason, processes: [], sys: null };
  }
  try {
    const { stdout } = await execFileP(exe, ["--json"], { timeout: 2500, maxBuffer: 8 << 20, windowsHide: true });
    const data = JSON.parse(String(stdout || ""));
    if (!data || data.ok !== true || !Array.isArray(data.processes)) throw new Error(data && data.error ? data.error : "The Windows helper answered nothing.");
    const cpus = Number(data.cpus) || os.cpus().length || 1;
    const now = Date.now();
    const next = new Map();
    const processes = [];
    for (const raw of data.processes) {
      const startKey = String(raw.startKey || "");
      if (!startKey) { processes.push({ ...raw, pid: Number(raw.pid), sameUser: !raw.denied, cpuPct: null }); continue; }
      const key = "win:" + raw.pid + ":" + startKey;
      const prev = state.prev.get(key);
      const cpuSeconds = (Number(raw.cpu100ns) || 0) / 1e7;
      const cpuPct = prev ? cpuPercent(prev.cpuSeconds, cpuSeconds, now - prev.at, cpus) : null;
      const io = (Number(raw.readBytes) || 0) + (Number(raw.writeBytes) || 0);
      const diskBps = prev && now - prev.at <= 30000 && io >= (Number(prev.io) || 0)
        ? Math.round((io - (Number(prev.io) || 0)) / ((now - prev.at) / 1000)) : null;
      next.set(key, { cpuSeconds, at: now, io });
      processes.push({
        pid: Number(raw.pid), ppid: Number(raw.ppid) || 0, name: String(raw.name || ""),
        threads: Number(raw.threads) || 0, startKey, startedAt: Number(raw.startedAt) || 0,
        workingSet: Number(raw.workingSet) || 0, privateBytes: Number(raw.privateBytes) || 0,
        readBytes: Number(raw.readBytes) || 0, writeBytes: Number(raw.writeBytes) || 0,
        diskBps, denied: !!raw.denied, sameUser: !raw.denied, cpuPct,
      });
    }
    for (const [key, value] of next) state.prev.set(key, value);
    let machine = null;
    if (data.sys && state.prevWinSys) {
      const dt = (Number(data.sys.kernel) + Number(data.sys.user)) - (Number(state.prevWinSys.kernel) + Number(state.prevWinSys.user));
      const di = Number(data.sys.idle) - Number(state.prevWinSys.idle);
      if (dt > 0) machine = Math.max(0, Math.min(100, Math.round(((dt - di) / dt) * 1000) / 10));
    }
    if (data.sys) state.prevWinSys = data.sys;
    state.windowsReason = "";
    state.windowsBackoffUntil = 0;
    return { applicable: true, available: true, reason: "", processes, sys: data.sys, machine, memTotal: Number(data.memTotal) || 0, memAvail: Number(data.memAvail) || 0, cpus };
  } catch (e) {
    state.windowsReason = "The Windows helper did not answer. WSL interop may be off.";
    state.windowsBackoffUntil = Date.now() + 30000;
    log("windows:", e.message);
    return { applicable: true, available: false, reason: state.windowsReason, processes: [], sys: null };
  }
}

function macProcesses() {
  return execFileP("ps", ["-axo", "pid=,ppid=,time=,rss=,comm="], { timeout: 2500, maxBuffer: 4 << 20 })
    .then(({ stdout }) => {
      const raw = parsePS(stdout);
      const cpus = os.cpus().length || 1;
      const now = Date.now();
      const next = new Map();
      const out = raw.map((p) => {
        const key = processKey("darwin", p.pid, String(p.cpuSeconds));
        const prev = state.prev.get(key);
        next.set(key, { cpuSeconds: p.cpuSeconds, at: now });
        return { ...p, startKey: String(p.cpuSeconds), cpuPct: prev ? cpuPercent(prev.cpuSeconds, p.cpuSeconds, now - prev.at, cpus) : null, sameUser: true };
      });
      state.prev = next;
      return out;
    })
    .catch(() => []);
}

function readCwd(pid) {
  if (PLATFORM !== "linux") return "";
  const cache = state.cwd.get(pid);
  if (cache && Date.now() - cache.at < 10000) return cache.path;
  let value = "";
  try { value = fs.readlinkSync("/proc/" + pid + "/cwd"); } catch { /* denied */ }
  state.cwd.set(pid, { at: Date.now(), path: value });
  return value;
}

function ownerMap(linux) {
  const owners = {};
  if (!linux.length) return owners;
  const children = new Map();
  for (const p of linux) {
    if (!children.has(p.ppid)) children.set(p.ppid, []);
    children.get(p.ppid).push(p.pid);
  }
  const assign = (root, owner) => {
    const queue = [root];
    const seen = new Set();
    while (queue.length) {
      const pid = queue.shift();
      if (seen.has(pid)) continue;
      seen.add(pid);
      owners[pid] = owner;
      for (const child of children.get(pid) || []) queue.push(child);
    }
  };
  for (const pane of state.tmux) if (pane.owner) assign(pane.pid, pane.owner);
  const top = [...linux].sort((a, b) => (b.cpuPct ?? -1) - (a.cpuPct ?? -1)).slice(0, 80);
  for (const p of top) {
    if (owners[p.pid] || !p.sameUser) continue;
    const cwd = readCwd(p.pid);
    const ws = workspaceForPath(cwd);
    if (!ws) continue;
    owners[p.pid] = { agent: "", workspace: ws.name, workspaceId: ws.id, confidence: "likely" };
  }
  return owners;
}

function hostFacts(win, linux) {
  const linuxMem = memInfo();
  const winTotal = win.available ? win.memTotal : 0;
  const linuxTotal = linuxMem.total;
  const macTotal = PLATFORM === "darwin" ? os.totalmem() : 0;
  const total = winTotal || linuxTotal || macTotal;
  const available = win.available ? win.memAvail : (linuxTotal ? linuxMem.available : os.freemem());
  const cpus = win.available ? win.cpus : os.cpus().length || 1;
  return {
    name: os.hostname(), cpus, memTotal: total, memAvailable: available,
    memUsed: Math.max(0, total - available), source: win.available ? "windows" : (PLATFORM === "darwin" ? "darwin" : "linux"),
  };
}

async function collect() {
  const now = Date.now();
  if (PLATFORM === "linux") refreshProtect();
  let linux = [];
  if (PLATFORM === "linux") linux = linuxProcesses();
  else if (PLATFORM === "darwin") linux = await macProcesses();
  const win = await windowsSide();
  const owners = ownerMap(linux);
  const merged = mergePlatforms(linux, win.processes, win.available);
  for (const p of merged) {
    if (p.platform === "linux" && owners[p.pid]) p.owner = owners[p.pid];
    if (p.platform === "windows") p.owner = null;
    const key = p.key || processKey(p.platform, p.pid, p.startKey);
    const ring = pushRing(state.rings.get(key) || [], p.cpuPct == null ? null : p.cpuPct, 30);
    state.rings.set(key, ring);
    p.spark = ring;
    p.protected = PROTECTED_NAMES.has(String(p.name || "").toLowerCase()) || state.protect.has(Number(p.pid)) || !!p.denied;
  }
  const live = new Set(merged.map((p) => p.key || processKey(p.platform, p.pid, p.startKey)));
  for (const key of state.rings.keys()) if (!live.has(key)) state.rings.delete(key);
  const host = hostFacts(win, linux);
  let machineCpu = null;
  if (PLATFORM === "linux") {
    const stat = cpuStat();
    if (stat && state.prevStat) {
      const dt = stat.total - state.prevStat.total;
      const di = stat.idle - state.prevStat.idle;
      if (dt > 0) machineCpu = Math.max(0, Math.min(100, Math.round(((dt - di) / dt) * 1000) / 10));
    }
    if (stat) state.prevStat = stat;
  } else if (win.available && win.machine != null) {
    machineCpu = win.machine;
  }
  if (machineCpu == null) {
    const sum = merged.reduce((a, p) => a + (p.cpuPct == null ? 0 : p.cpuPct), 0);
    machineCpu = Math.round(Math.min(100, sum) * 10) / 10;
  }
  const sum = totals(merged, host.cpus, host.memTotal, machineCpu);
  sum.processMem = merged.reduce((a, p) => a + (Number(p.memBytes) || 0), 0);
  const groups = groupByOwner(merged, owners);
  for (const g of groups) {
    const meta = Object.values(owners).find((o) => (o.agent || o.workspace) === (g.agent || g.workspace));
    if (meta) g.workspaceId = meta.workspaceId || "";
  }
  state.totalsRing = pushRing(state.totalsRing, machineCpu, 120);
  state.memRing = pushRing(state.memRing, host.memUsed, 120);
  state.lastSampleAt = now;
  state.sample = {
    at: new Date(now).toISOString(), sampledAt: now, intervalMs: effectiveInterval(),
    paused: state.paused, platform: PLATFORM, version: VERSION,
    host, windows: { applicable: win.applicable !== false, available: win.available, reason: win.reason || "" },
    totals: sum, processes: merged, agents: groups,
    history: { cpu: state.totalsRing, mem: state.memRing, spanMs: state.totalsRing.length * effectiveInterval() },
    settings: { update_ms: Number(state.settings.update_ms) || 2000, show_windows: state.settings.show_windows, alerts: state.settings.alerts },
    protectedPids: [...state.protect],
  };
  maybeAlert(groups);
  return state.sample;
}

function effectiveInterval() {
  if (state.paused) return 0;
  const requested = state.pageInterval || state.settings.update_ms;
  const base = Math.max(1000, Math.min(10000, Number(requested) || 2000));
  return Date.now() - state.lastPageAt > 60000 ? Math.max(base, 10000) : base;
}

async function sampleNow() {
  if (inFlight) return inFlight;
  inFlight = collect().catch((e) => { log("sample:", e.message); }).finally(() => { inFlight = null; });
  return inFlight;
}

function maybeAlert(groups) {
  if (!state.settings.alerts || !HOST || !TOKEN) return;
  const now = Date.now();
  for (const g of groups) {
    if (!g.name || g.name === "Other") continue;
    const rec = state.alerts.get(g.name) || { since: 0, last: 0 };
    if (g.cpuPct >= 80) {
      if (!rec.since) rec.since = now;
      if (now - rec.since >= 60000 && (!rec.last || now - rec.last >= 30 * 60000)) {
        rec.last = now;
        const title = g.name + " is using " + Math.round(g.cpuPct) + "% CPU";
        const body = g.name + (g.workspace ? " in " + g.workspace : "") + " has used " + Math.round(g.cpuPct) + "% of this machine for over a minute. Open Processes in the bottom dock to see what it is doing.";
        hostPost("/api/ext/v1/inbox", { title: title.slice(0, 200), body: body.slice(0, 2000), workspaceId: g.workspaceId || "" }).catch((e) => log("alert:", e.message));
      }
    } else {
      rec.since = 0;
    }
    state.alerts.set(g.name, rec);
  }
}

function findProcess(platform, pid, startKey) {
  const list = state.sample ? state.sample.processes : [];
  return list.find((p) => p.platform === platform && Number(p.pid) === Number(pid) && String(p.startKey) === String(startKey)) || null;
}

function currentLinux(pid) {
  let text;
  try { text = fs.readFileSync("/proc/" + pid + "/stat", "utf8"); } catch { return null; }
  const p = parseProcStat(text);
  if (!p) return null;
  let uid = null;
  try { uid = fs.statSync("/proc/" + pid).uid; } catch { /* keep null */ }
  return { ...p, uid, sameUser: typeof process.getuid === "function" ? uid === process.getuid() : true };
}

function protectReason(proc, pid) {
  if (state.protect.has(Number(pid))) return "This is COGNIX[WS] or a process it depends on.";
  if (PROTECTED_NAMES.has(String(proc.name || "").toLowerCase())) return "This is a system process.";
  return "";
}

function newOperation(pid, platform, startKey, name) {
  const id = "op-" + crypto.randomBytes(8).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");
  const revision = crypto.createHash("sha256").update([id, pid, platform, startKey, Date.now(), nonce].join("|")).digest("hex");
  const op = { id, pid: Number(pid), platform, startKey: String(startKey), name: String(name || ""), revision, status: "prepared", createdAt: Date.now(), expiresAt: Date.now() + 5 * 60000 };
  state.ops.set(id, op);
  return op;
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

async function executeOperation(op, confirmedRevision) {
  if (!op || op.status !== "prepared") return { status: 409, error: "This operation is no longer prepared." };
  if (Date.now() > op.expiresAt) { op.status = "expired"; return { status: 409, error: "This operation expired. Try again." }; }
  if (!safeEqual(op.revision, confirmedRevision)) return { status: 403, error: "The owner confirmation does not match this operation." };
  const proc = findProcess(op.platform, op.pid, op.startKey);
  if (!proc) { op.status = "failed"; return { status: 409, error: "The process is no longer listed. Refresh and try again." }; }
  const protectedReason = protectReason(proc, op.pid);
  if (protectedReason) { op.status = "failed"; return { status: 409, error: protectedReason }; }
  const decision = endTaskDecision({
    pid: op.pid, startKey: op.startKey, platform: op.platform, proc,
    protectedPids: state.protect, selfPid: process.pid, sameUser: proc.sameUser !== false, denied: !!proc.denied,
  });
  if (!decision.ok) { op.status = "failed"; return { status: 409, error: decision.reason }; }

  if (op.platform === "windows") {
    try {
      const { stdout } = await execFileP(helperPath(), ["--kill", String(op.pid), "--start", op.startKey], { timeout: 4000, maxBuffer: 1 << 20, windowsHide: true });
      const out = JSON.parse(String(stdout || ""));
      if (!out.ok) throw new Error(out.error || "The Windows helper refused.");
      op.status = "done";
      op.signal = "TerminateProcess";
    } catch (e) {
      op.status = "failed";
      return { status: 409, error: "The process was not ended: " + e.message };
    }
  } else {
    const now = currentLinux(op.pid);
    if (!now) { op.status = "failed"; return { status: 409, error: "The process already exited." }; }
    if (now.sameUser === false) { op.status = "failed"; return { status: 409, error: "This process belongs to another user." }; }
    if (String(now.startKey) !== String(op.startKey)) { op.status = "failed"; return { status: 409, error: "The process changed since it was listed." }; }
    const again = protectReason(now, op.pid);
    if (again) { op.status = "failed"; return { status: 409, error: again }; }
    try {
      process.kill(op.pid, "SIGTERM");
      await new Promise((resolve) => setTimeout(resolve, 2000));
      const after = currentLinux(op.pid);
      if (after && String(after.startKey) === String(op.startKey)) {
        process.kill(op.pid, "SIGKILL");
        op.signal = "SIGKILL";
      } else {
        op.signal = "SIGTERM";
      }
      op.status = "done";
    } catch (e) {
      op.status = "failed";
      return { status: 409, error: "The process was not ended: " + e.message };
    }
  }
  op.finishedAt = Date.now();
  hostPost("/api/ext/v1/events", { name: "ended", data: { pid: op.pid, name: op.name, platform: op.platform, signal: op.signal } })
    .catch((e) => log("event:", e.message));
  log("ended", op.platform, op.pid, op.name, op.signal);
  return { status: 200, operation: publicOperation(op) };
}

function publicOperation(op) {
  return { id: op.id, pid: op.pid, platform: op.platform, name: op.name, status: op.status, signal: op.signal || "", createdAt: op.createdAt, finishedAt: op.finishedAt || 0 };
}

function cmdlineFor(pid) {
  if (PLATFORM !== "linux") return { status: 501, error: "Command lines for Windows processes are not available in this version." };
  let uid = null;
  try { uid = fs.statSync("/proc/" + pid).uid; } catch { return { status: 404, error: "That process is no longer running." }; }
  if (typeof process.getuid === "function" && uid !== process.getuid()) return { status: 403, error: "This process belongs to another user." };
  try {
    const raw = fs.readFileSync("/proc/" + pid + "/cmdline", "utf8");
    const parts = raw.split("\u0000").filter(Boolean);
    return { status: 200, cmdline: redactCommandLine(parts.join(" ")), masked: true };
  } catch {
    return { status: 403, error: "The kernel did not let this process read that command line." };
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, "http://127.0.0.1");
    const p = u.pathname;
    if (p === "/healthz") return json(res, 200, { ok: true, version: VERSION, uptimeMs: Date.now() - state.startedAt, sampledAt: state.lastSampleAt });
    if (SECRET && req.headers["x-picode-proxy-secret"] !== SECRET) return json(res, 403, { error: "forbidden" });

    if (p === "/snapshot" && req.method === "GET") {
      state.lastPageAt = Date.now();
      if (!state.sample || (!state.paused && Date.now() - state.lastSampleAt > 5000)) await sampleNow();
      return json(res, 200, state.sample || { at: new Date().toISOString(), sampledAt: 0, processes: [], agents: [], totals: { cpuPct: null, processMem: 0, count: 0 }, history: { cpu: [], mem: [] }, windows: { available: false, reason: "Still reading." }, host: { name: os.hostname(), cpus: os.cpus().length, memTotal: 0, memAvailable: 0, memUsed: 0, source: PLATFORM }, settings: { update_ms: Number(state.settings.update_ms) || 2000, show_windows: state.settings.show_windows, alerts: state.settings.alerts }, paused: state.paused });
    }

    if (p === "/refresh" && req.method === "POST") {
      state.lastPageAt = Date.now();
      await sampleNow();
      return json(res, 200, state.sample || {});
    }

    if (p === "/speed" && req.method === "POST") {
      let body = {};
      try { body = JSON.parse((await readBody(req)) || "{}"); } catch { return json(res, 400, { error: "invalid body" }); }
      const ms = Number(body.ms);
      if (![1000, 2000, 5000].includes(ms)) return json(res, 400, { error: "speed must be 1000, 2000 or 5000" });
      state.pageInterval = ms;
      state.lastPageAt = Date.now();
      await sampleNow();
      return json(res, 200, { intervalMs: effectiveInterval() });
    }

    if (p === "/pause" && req.method === "POST") {
      let body = {};
      try { body = JSON.parse((await readBody(req)) || "{}"); } catch { return json(res, 400, { error: "invalid body" }); }
      state.paused = body.paused === true;
      if (state.paused) {
        if (state.sample) state.sample.paused = true;
      } else {
        state.lastPageAt = Date.now();
        await sampleNow();
      }
      return json(res, 200, { paused: state.paused, intervalMs: effectiveInterval() });
    }

    if (p.startsWith("/process/") && p.endsWith("/cmdline") && req.method === "GET") {
      const pid = Number(p.split("/")[2]);
      if (!Number.isFinite(pid) || pid <= 0) return json(res, 400, { error: "invalid pid" });
      const out = cmdlineFor(pid);
      return json(res, out.status, out.status === 200 ? { cmdline: out.cmdline, masked: out.masked } : { error: out.error });
    }

    if (p === "/operations" && req.method === "POST") {
      let body = {};
      try { body = JSON.parse((await readBody(req)) || "{}"); } catch { return json(res, 400, { error: "invalid body" }); }
      if (body.action !== "end") return json(res, 400, { error: "unknown action" });
      const platform = body.platform === "windows" ? "windows" : body.platform === "linux" ? "linux" : "";
      if (!platform) return json(res, 400, { error: "platform is required" });
      if (!state.sample) await sampleNow();
      const proc = findProcess(platform, body.pid, body.startKey);
      const decision = endTaskDecision({
        pid: body.pid, startKey: body.startKey, platform, proc,
        protectedPids: state.protect, selfPid: process.pid, sameUser: proc ? proc.sameUser !== false : false, denied: proc ? !!proc.denied : true,
      });
      if (!decision.ok) return json(res, 409, { error: decision.reason });
      const op = newOperation(body.pid, platform, body.startKey, proc.name);
      return json(res, 201, { operation: publicOperation(op), confirmation: confirmationFor({ id: op.id, name: op.name, pid: op.pid, revision: op.revision }) });
    }

    if (p.startsWith("/operations/") && req.method === "GET") {
      const id = p.split("/")[2] || "";
      const op = state.ops.get(id);
      if (!op) return json(res, 404, { error: "operation not found" });
      if (op.status !== "prepared") return json(res, 410, { error: "this operation is no longer prepared" });
      return json(res, 200, { operation: publicOperation(op), confirmation: confirmationFor({ id: op.id, name: op.name, pid: op.pid, revision: op.revision }) });
    }

    if (p.startsWith("/operations/") && p.endsWith("/cancel") && req.method === "POST") {
      const id = p.split("/")[2] || "";
      const op = state.ops.get(id);
      if (!op) return json(res, 404, { error: "operation not found" });
      if (op.status === "prepared") op.status = "cancelled";
      return json(res, 200, { operation: publicOperation(op) });
    }

    if (p === "/__picode/confirm" && req.method === "POST") {
      const header = String(req.headers["x-picode-owner-confirmed"] || "");
      let body = {};
      try { body = JSON.parse((await readBody(req)) || "{}"); } catch { return json(res, 400, { error: "invalid body" }); }
      const op = state.ops.get(String(body.operationId || ""));
      if (!op) return json(res, 404, { error: "operation not found" });
      if (!header || !safeEqual(header, op.revision)) return json(res, 403, { error: "the owner confirmation is missing" });
      const out = await executeOperation(op, header);
      if (out.status !== 200) return json(res, 200, { operation: publicOperation(op), error: out.error });
      return json(res, 200, { operation: out.operation });
    }

    return json(res, 404, { error: "unknown route" });
  } catch (e) {
    return json(res, 500, { error: e.message || "internal error" });
  }
});

function tick() {
  if (state.paused) return;
  const interval = effectiveInterval();
  if (Date.now() - state.lastSampleAt >= interval && !inFlight) void sampleNow();
}

async function boot() {
  await loadIdentity();
  await loadSettings();
  await loadAgents();
  await refreshTmux();
  refreshProtect();
  await sampleNow();
  timer = setInterval(tick, 1000);
  timer.unref?.();
  setInterval(() => {
    loadSettings().catch(() => {});
    loadAgents().then(refreshTmux).catch(() => {});
  }, 30000).unref?.();
  server.listen(PORT, "127.0.0.1", () => log("taskboard listening on 127.0.0.1:" + PORT + " (platform " + PLATFORM + ", data " + DATA + ")"));
}

process.on("SIGTERM", () => { try { server.close(); } catch { /* closing */ } process.exit(0); });
process.on("SIGINT", () => { try { server.close(); } catch { /* closing */ } process.exit(0); });

if (TEST) {
  await loadIdentity();
  await loadSettings();
  await sampleNow();
  server.listen(PORT, "127.0.0.1", () => log("taskboard test listening on 127.0.0.1:" + PORT));
} else {
  await boot();
}
