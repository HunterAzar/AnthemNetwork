package main

import (
	"strings"
	"syscall"
	"unsafe"
)

const (
	Th32csSnapprocess = 0x00000002
	ProcessAllAccess  = 0x1F0FFF
)

type PROCESSENTRY32 struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [260]uint16
}

func FindProcessByName(name string) uint32 {
	handle, _, _ := procCreateToolhelp32Snapshot.Call(Th32csSnapprocess, 0)
	if handle == 0 {
		return 0
	}
	defer procCloseHandle.Call(handle)

	var entry PROCESSENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32First.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return 0
	}

	for {
		exeName := syscall.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(exeName, name) {
			return entry.ProcessID
		}

		ret, _, _ := procProcess32Next.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return 0
}

func TerminateProcess(pid uint32) bool {
	handle, _, _ := procOpenProcess.Call(ProcessAllAccess, 0, uintptr(pid))
	if handle == 0 {
		return false
	}
	defer procCloseHandle.Call(handle)

	ret, _, _ := procTerminateProcess.Call(handle, 0)
	return ret != 0
}
