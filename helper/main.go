// Taskboard's Windows process helper. It is one-shot by design: the
// extension's Node process runs it for one snapshot (or one end-task) and
// lets it exit, so nothing is left behind when the supervisor stops the
// extension. Stdlib only: kernel32 and psapi through syscall, no cgo, no
// external modules.
//
//	helper.exe --json                 list processes
//	helper.exe --kill <pid> --start <startKey>
//
// It runs as the signed-in user. It never asks for elevation and never
// retries a refused OpenProcess; the caller shows what it could not read.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	th32csSnapProcess = 0x00000002
	processQueryLimited = 0x1000
	processQueryInformation = 0x0400
	processVMRead = 0x0010
	processTerminate = 0x0001
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	psapi    = syscall.NewLazyDLL("psapi.dll")

	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = kernel32.NewProc("Process32FirstW")
	procProcess32NextW           = kernel32.NewProc("Process32NextW")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
	procGetProcessTimes          = kernel32.NewProc("GetProcessTimes")
	procTerminateProcess         = kernel32.NewProc("TerminateProcess")
	procGlobalMemoryStatusEx     = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetProcessIoCounters     = kernel32.NewProc("GetProcessIoCounters")
	procGetSystemTimes           = kernel32.NewProc("GetSystemTimes")
	procGetProcessMemoryInfo     = psapi.NewProc("GetProcessMemoryInfo")
)

type processEntry32W struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [260]uint16
}

type memoryCounters struct {
	CB                      uint32
	PageFaultCount          uint32
	PeakWorkingSetSize      uintptr
	WorkingSetSize          uintptr
	QuotaPeakPagedPoolUsage uintptr
	QuotaPagedPoolUsage     uintptr
	QuotaPeakNonPagedPool   uintptr
	QuotaNonPagedPool       uintptr
	PagefileUsage           uintptr
	PeakPagefileUsage       uintptr
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type process struct {
	PID         uint32 `json:"pid"`
	PPID        uint32 `json:"ppid"`
	Name        string `json:"name"`
	CPU100ns    uint64 `json:"cpu100ns"`
	WorkingSet  uint64 `json:"workingSet"`
	PrivateBytes uint64 `json:"privateBytes"`
	Threads     uint32 `json:"threads"`
	StartedAt   int64  `json:"startedAt"`
	StartKey    string `json:"startKey"`
	ReadBytes   uint64 `json:"readBytes"`
	WriteBytes  uint64 `json:"writeBytes"`
	Denied      bool   `json:"denied,omitempty"`
}

type systemTimes struct {
	Idle   uint64 `json:"idle"`
	Kernel uint64 `json:"kernel"`
	User   uint64 `json:"user"`
}

type snapshot struct {
	OK        bool        `json:"ok"`
	OS        string      `json:"os"`
	Host      string      `json:"host"`
	CPUs      int         `json:"cpus"`
	MemTotal  uint64      `json:"memTotal"`
	MemAvail  uint64      `json:"memAvail"`
	Sys       systemTimes `json:"sys"`
	Processes []process   `json:"processes"`
}

func toU64(ft syscall.Filetime) uint64 {
	return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

func startKeyOf(ft syscall.Filetime) string {
	return fmt.Sprintf("%d", toU64(ft))
}

func startedUnix(ft syscall.Filetime) int64 {
	// FILETIME counts 100 ns intervals since 1601-01-01.
	const epoch = 116444736000000000
	v := toU64(ft)
	if v < epoch {
		return 0
	}
	return int64((v - epoch) / 10000000)
}

func memory() (total, avail uint64) {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	ok, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if ok == 0 {
		return 0, 0
	}
	return m.TotalPhys, m.AvailPhys
}

func open(pid uint32, access uint32) (syscall.Handle, error) {
	h, _, err := procOpenProcess.Call(uintptr(access), 0, uintptr(pid))
	if h == 0 {
		return 0, err
	}
	return syscall.Handle(h), nil
}

func closeHandle(h syscall.Handle) {
	if h != 0 {
		procCloseHandle.Call(uintptr(h))
	}
}

func readProcess(pid, ppid, threads uint32, name string) process {
	p := process{PID: pid, PPID: ppid, Name: name, Threads: threads}
	h, err := open(pid, processQueryLimited|processVMRead)
	if err != nil {
		h, err = open(pid, processQueryLimited)
	}
	if err != nil {
		p.Denied = true
		return p
	}
	defer closeHandle(h)

	var creation, exit, kernel, user syscall.Filetime
	if ok, _, _ := procGetProcessTimes.Call(uintptr(h), uintptr(unsafe.Pointer(&creation)), uintptr(unsafe.Pointer(&exit)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user))); ok != 0 {
		p.CPU100ns = toU64(kernel) + toU64(user)
		p.StartKey = startKeyOf(creation)
		p.StartedAt = startedUnix(creation)
	}

	var mem memoryCounters
	mem.CB = uint32(unsafe.Sizeof(mem))
	if ok, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&mem)), uintptr(mem.CB)); ok != 0 {
		p.WorkingSet = uint64(mem.WorkingSetSize)
		p.PrivateBytes = uint64(mem.PagefileUsage)
	}

	var io ioCounters
	if ok, _, _ := procGetProcessIoCounters.Call(uintptr(h), uintptr(unsafe.Pointer(&io))); ok != 0 {
		p.ReadBytes = io.ReadTransferCount
		p.WriteBytes = io.WriteTransferCount
	}
	return p
}

func list() (snapshot, error) {
	h, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if h == ^uintptr(0) || h == 0 {
		return snapshot{}, fmt.Errorf("CreateToolhelp32Snapshot: %v", err)
	}
	defer closeHandle(syscall.Handle(h))

	entry := processEntry32W{Size: uint32(unsafe.Sizeof(processEntry32W{}))}
	out := snapshot{OK: true, OS: "windows", CPUs: runtime.NumCPU(), Processes: []process{}}
	out.Host, _ = os.Hostname()
	out.MemTotal, out.MemAvail = memory()
	var idle, kernel, user syscall.Filetime
	if ok, _, _ := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user))); ok != 0 {
		out.Sys = systemTimes{Idle: toU64(idle), Kernel: toU64(kernel), User: toU64(user)}
	}

	ok, _, _ := procProcess32FirstW.Call(h, uintptr(unsafe.Pointer(&entry)))
	for ok != 0 {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		out.Processes = append(out.Processes, readProcess(entry.ProcessID, entry.ParentProcessID, entry.Threads, name))
		entry.Size = uint32(unsafe.Sizeof(processEntry32W{}))
		ok, _, _ = procProcess32NextW.Call(h, uintptr(unsafe.Pointer(&entry)))
	}
	return out, nil
}

func kill(pid uint32, startKey string) (map[string]any, error) {
	h, err := open(pid, processQueryLimited|processTerminate)
	if err != nil {
		return nil, fmt.Errorf("open %d: %w", pid, err)
	}
	defer closeHandle(h)

	var creation, exit, kernel, user syscall.Filetime
	if ok, _, _ := procGetProcessTimes.Call(uintptr(h), uintptr(unsafe.Pointer(&creation)), uintptr(unsafe.Pointer(&exit)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user))); ok == 0 {
		return nil, fmt.Errorf("read process %d", pid)
	}
	if startKey != "" && startKeyOf(creation) != startKey {
		return nil, fmt.Errorf("the process changed since it was listed")
	}
	ok, _, err := procTerminateProcess.Call(uintptr(h), 1)
	if ok == 0 {
		return nil, fmt.Errorf("terminate %d: %v", pid, err)
	}
	return map[string]any{"ok": true, "pid": pid, "startKey": startKeyOf(creation)}, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: helper --json | --kill <pid> --start <startKey>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "--json":
		s, err := list()
		if err != nil {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": err.Error()})
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(s)
	case "--kill":
		start, pidArg := "", ""
		rest := os.Args[2:]
		for i := 0; i < len(rest); i++ {
			if rest[i] == "--start" && i+1 < len(rest) {
				start = rest[i+1]
				i++
				continue
			}
			pidArg = rest[i]
		}
		pid, err := strconvAtoi(pidArg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "usage: helper --kill <pid> --start <startKey>")
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": "invalid pid"})
			os.Exit(2)
		}
		out, err := kill(uint32(pid), start)
		if err != nil {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": err.Error()})
			os.Exit(3)
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
	default:
		fmt.Fprintln(os.Stderr, "unknown action")
		os.Exit(2)
	}
}

func strconvAtoi(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}
