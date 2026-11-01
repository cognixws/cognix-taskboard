// Taskboard's pure rules: kernel parsing, CPU deltas, ordering, owner
// grouping, the end-task decision table and command-line masking. No I/O
// here, so every rule is reachable without a machine.

export const PAGE_SIZE = 4096;
export const LINUX_CLK_TCK = 100;

// Names that End task refuses before it even looks at a PID. The process
// also protects its own ancestors; this set is the last line, not the only.
export const PROTECTED_NAMES = new Set([
  "init", "systemd", "kthreadd", "kworker", "kthread", "migration",
  "picode", "picode-desktop", "picode-shell", "picode-nmh", "tmux", "tmux: server",
  "system", "secure system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
  "winlogon.exe", "services.exe", "lsass.exe",
]);

// A process key keeps the two PID namespaces apart: WSL and Windows both
// have low PIDs, and a Windows PID 8124 is not the Linux PID 8124.
export function processKey(platform, pid, startKey) {
  return String(platform || "") + ":" + String(pid) + ":" + String(startKey || "");
}

// /proc/<pid>/stat. comm may hold spaces and parentheses, so the fields
// after the last ')' are the only safe split.
export function parseProcStat(text) {
  const raw = String(text || "");
  const close = raw.lastIndexOf(")");
  const open = raw.indexOf("(");
  if (open < 0 || close < open) return null;
  const pid = Number(raw.slice(0, open).trim());
  const comm = raw.slice(open + 1, close);
  const f = raw.slice(close + 1).trim().split(/\s+/);
  if (!Number.isFinite(pid) || f.length < 22) return null;
  const utime = Number(f[11]);
  const stime = Number(f[12]);
  const threads = Number(f[17]);
  const startTicks = f[19];
  const rssPages = Number(f[21]);
  if (![utime, stime, threads, rssPages].every(Number.isFinite)) return null;
  return {
    pid,
    name: comm,
    state: f[0] || "",
    ppid: Number(f[1]) || 0,
    cpuSeconds: (utime + stime) / LINUX_CLK_TCK,
    threads: threads || 0,
    startKey: String(startTicks || ""),
    rssBytes: Math.max(0, rssPages) * PAGE_SIZE,
  };
}

// /proc/<pid>/status, for the uid and a more exact resident size.
export function parseProcStatus(text) {
  const out = { uid: null, rssBytes: null, name: "" };
  for (const line of String(text || "").split("\n")) {
    const i = line.indexOf(":");
    if (i < 0) continue;
    const key = line.slice(0, i).trim();
    const value = line.slice(i + 1).trim();
    if (key === "Uid") out.uid = Number(value.split(/\s+/)[0]);
    else if (key === "VmRSS") out.rssBytes = (Number(value.split(/\s+/)[0]) || 0) * 1024;
    else if (key === "Name") out.name = value;
  }
  return out;
}

// `ps -axo pid=,ppid=,time=,rss=,comm=` on macOS. time is cumulative CPU:
// MM:SS or HH:MM:SS. rss is KiB. This is a delta source like /proc, not the
// average ps %cpu would print.
export function parsePS(text) {
  const out = [];
  for (const line of String(text || "").split("\n")) {
    const row = line.trim();
    if (!row) continue;
    const m = /^(\d+)\s+(\d+)\s+(?:(\d+):)?(\d+):(\d+)\s+(\d+)\s+(.+)$/.exec(row);
    if (!m) continue;
    const hours = Number(m[3] || 0);
    const minutes = Number(m[4] || 0);
    const seconds = Number(m[5] || 0);
    out.push({
      pid: Number(m[1]),
      ppid: Number(m[2]),
      cpuSeconds: hours * 3600 + minutes * 60 + seconds,
      rssBytes: Number(m[6]) * 1024,
      name: m[7].trim().split("/").pop() || m[7].trim(),
    });
  }
  return out;
}

// Percent of the whole machine, the way Task Manager counts it: one busy
// core of eight is 12.5%. null means "first sighting", never a fake zero.
export function cpuPercent(prevSeconds, nextSeconds, wallMs, cpus) {
  if (prevSeconds == null || nextSeconds == null) return null;
  const wall = Number(wallMs) / 1000;
  const n = Number(cpus) || 1;
  if (!(wall > 0) || !Number.isFinite(prevSeconds) || !Number.isFinite(nextSeconds)) return null;
  const pct = ((nextSeconds - prevSeconds) / wall / n) * 100;
  if (!Number.isFinite(pct) || pct < 0) return 0;
  return Math.min(100, Math.round(pct * 10) / 10);
}

export function formatBytes(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n <= 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  const text = v >= 10 || Number.isInteger(v) ? String(Math.round(v)) : v.toFixed(1);
  return text + " " + units[i];
}

export function formatPercent(pct) {
  if (pct == null || !Number.isFinite(Number(pct))) return "—";
  const n = Number(pct);
  return (n < 10 ? n.toFixed(1) : String(Math.round(n))) + "%";
}

export function formatDuration(seconds) {
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m " + String(s % 60).padStart(2, "0") + "s";
  return Math.floor(s / 3600) + "h " + String(Math.floor((s % 3600) / 60)).padStart(2, "0") + "m";
}

// Sort with a deterministic tie-breaker, and unknown CPU last rather than
// pretending it is zero.
export function sortProcesses(list, key = "cpu", dir = "desc") {
  const sign = dir === "asc" ? 1 : -1;
  const value = (p) => {
    if (key === "mem") return Number(p.memBytes) || 0;
    if (key === "name") return String(p.name || "");
    if (key === "pid") return Number(p.pid) || 0;
    if (key === "threads") return Number(p.threads) || 0;
    if (key === "disk") return (Number(p.readBytes) || 0) + (Number(p.writeBytes) || 0);
    return p.cpuPct == null ? -1 : Number(p.cpuPct);
  };
  return [...(list || [])].sort((a, b) => {
    const av = value(a);
    const bv = value(b);
    if (av !== bv) return (av < bv ? -1 : 1) * sign;
    const an = String(a.name || "");
    const bn = String(b.name || "");
    if (an !== bn) return an.localeCompare(bn);
    return (Number(a.pid) || 0) - (Number(b.pid) || 0);
  });
}

export function filterProcesses(list, query) {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return [...(list || [])];
  return (list || []).filter((p) => {
    const owner = p.owner || {};
    return [
      p.name, p.pid, p.user, owner.agent, owner.workspace, p.command,
    ].some((v) => v != null && String(v).toLowerCase().includes(q));
  });
}

// The two sides of a Windows install. Windows PIDs live in their own
// namespace, so every row carries its platform and a key that includes it.
export function mergePlatforms(linux, windows, windowsAvailable = true) {
  const out = [];
  for (const p of linux || []) {
    out.push({ ...p, platform: "linux", key: processKey("linux", p.pid, p.startKey) });
  }
  if (windowsAvailable) {
    for (const p of windows || []) {
      out.push({
        ...p,
        platform: "windows",
        key: processKey("windows", p.pid, p.startKey),
        cpuPct: p.cpuPct == null ? null : p.cpuPct,
        memBytes: Number(p.workingSet) || 0,
        privateBytes: Number(p.privateBytes) || 0,
        sameUser: !p.denied,
        protected: PROTECTED_NAMES.has(String(p.name || "").toLowerCase()),
      });
    }
  }
  return out;
}

// Sums are labelled as sums: shared pages are counted once per process, as
// Task Manager's memory column does. totCPU is the machine's own figure.
export function totals(list, cpus, memTotal, machineCpuPct = null) {
  let cpu = 0;
  let mem = 0;
  let known = 0;
  for (const p of list || []) {
    if (p.cpuPct != null) { cpu += Number(p.cpuPct) || 0; known++; }
    mem += Number(p.memBytes) || 0;
  }
  return {
    cpuPct: machineCpuPct != null ? machineCpuPct : (list || []).length ? Math.round(Math.min(100, cpu) * 10) / 10 : null,
    memBytes: mem,
    memTotal: Number(memTotal) || 0,
    count: (list || []).length,
    cpus: Number(cpus) || 1,
    cpuKnown: known,
  };
}

// ownerByPid: { [pid]: { agent, workspace, confidence } }. PIDs are Linux
// PIDs; Windows rows get their owner from the workspace by cwd when the
// caller could match one.
export function groupByOwner(list, ownerByPid = {}) {
  const groups = new Map();
  for (const p of list || []) {
    const owner = (p.platform === "linux" ? ownerByPid[p.pid] : null) || p.owner || null;
    const name = owner && (owner.agent || owner.workspace) ? (owner.agent || owner.workspace) : "Other";
    const key = owner ? (owner.agent || owner.workspace) : "other";
    if (!groups.has(key)) {
      groups.set(key, {
        key, name,
        agent: owner?.agent || "",
        workspace: owner?.workspace || "",
        confidence: owner?.confidence || "unknown",
        count: 0, cpuPct: 0, memBytes: 0, top: null, exact: 0,
      });
    }
    const g = groups.get(key);
    g.count++;
    if (owner?.confidence === "exact") g.exact++;
    g.cpuPct += p.cpuPct == null ? 0 : Number(p.cpuPct) || 0;
    g.memBytes += Number(p.memBytes) || 0;
    if (!g.top || (p.cpuPct ?? -1) > (g.top.cpuPct ?? -1) || ((p.cpuPct ?? -1) === (g.top.cpuPct ?? -1) && (p.memBytes || 0) > (g.top.memBytes || 0))) {
      g.top = { pid: p.pid, name: p.name, cpuPct: p.cpuPct, memBytes: p.memBytes };
    }
  }
  const out = [...groups.values()].map((g) => ({
    ...g,
    cpuPct: Math.round(g.cpuPct * 10) / 10,
    confidence: g.confidence === "unknown" && g.exact ? "exact" : g.confidence,
  }));
  return out.sort((a, b) => b.cpuPct - a.cpuPct || b.memBytes - a.memBytes || a.name.localeCompare(b.name));
}

// The decision table, in one function. Every branch has a test.
export function endTaskDecision({ pid, startKey, platform, proc, protectedPids = new Set(), selfPid = 0, sameUser = true, denied = false }) {
  const n = Number(pid);
  if (!Number.isFinite(n) || n <= 0) return { ok: false, reason: "That is not a process." };
  if (n === Number(selfPid) || protectedPids.has(n)) {
    return { ok: false, reason: "This is COGNIX[WS] or a process it depends on." };
  }
  if (!proc) return { ok: false, reason: "The process is no longer listed. Refresh and try again." };
  if (proc.startKey && String(proc.startKey) !== String(startKey)) {
    return { ok: false, reason: "The process changed since it was listed. Refresh and try again." };
  }
  const name = String(proc.name || "").toLowerCase();
  if (PROTECTED_NAMES.has(name)) return { ok: false, reason: "This is a system process." };
  if (denied || proc.denied) return { ok: false, reason: "This process belongs to another user or is protected." };
  if (!sameUser) return { ok: false, reason: "This process belongs to another user." };
  if (platform === "windows" && !proc.startKey) {
    return { ok: false, reason: "This process did not report a start token; it cannot be ended safely." };
  }
  return { ok: true, reason: "" };
}

// Command lines are shown on demand and masked before they reach the page.
// Nothing here is ever written to disk.
export function redactCommandLine(input) {
  let s = String(input || "").replace(/[\u0000-\u001f\u007f]/g, " ");
  s = s.replace(/(\b(?:--?)?(?:token|key|secret|password|passwd|pass|api[-_]?key|auth|credential)\b\s*[=:]\s*)([^\s"']+)/gi, "$1***");
  s = s.replace(/(\b(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]{8,}/gi, "$1***");
  s = s.replace(/\bsk-[A-Za-z0-9_-]{10,}\b/g, "sk-***");
  s = s.replace(/\bgh[pousr]_[A-Za-z0-9]{10,}\b/g, "gh*_***");
  s = s.replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "xox*-***");
  s = s.replace(/\b[A-Za-z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD)[A-Za-z0-9_]*=([^\s"']+)/g, (m) => m.slice(0, m.indexOf("=") + 1) + "***");
  s = s.replace(/([a-z][a-z0-9+.-]*:\/\/)[^/\s:@]+:[^@\s/]+@/gi, "$1***@");
  if (s.length > 500) s = s.slice(0, 497) + "…";
  return s;
}

// The host's confirmation is drawn from this, never from the page.
export function confirmationFor({ id, name, pid, revision }) {
  return {
    revision: String(revision || ""),
    title: "End " + String(name || "this process") + "?",
    message: "This asks " + String(name || "the process") + " (PID " + String(pid) + ") to stop. It may lose unsaved work. COGNIX[WS] does not elevate.",
    confirmLabel: "End task",
    danger: true,
  };
}

// The page's sparkline: keep a bounded ring and fill only real samples.
export function pushRing(ring, value, max = 120) {
  const next = Array.isArray(ring) ? ring.slice(-(max - 1)) : [];
  next.push(value == null ? null : Number(value));
  return next;
}

export function sparkPath(values, width = 120, height = 18) {
  const list = (values || []).filter((v) => v != null && Number.isFinite(Number(v)));
  if (list.length < 2) return "";
  const max = Math.max(1, ...list.map(Number));
  const step = width / (list.length - 1);
  return list.map((v, i) => {
    const x = (i * step).toFixed(1);
    const y = (height - (Number(v) / max) * (height - 2) - 1).toFixed(1);
    return (i ? "L" : "M") + x + " " + y;
  }).join(" ");
}
