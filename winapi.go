package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	comctl32 = syscall.NewLazyDLL("comctl32.dll")

	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = kernel32.NewProc("Process32FirstW")
	procProcess32Next            = kernel32.NewProc("Process32NextW")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procTerminateProcess         = kernel32.NewProc("TerminateProcess")
	procGetExtendedTcpTable      = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable      = iphlpapi.NewProc("GetExtendedUdpTable")
	procInitCommonControlsEx     = comctl32.NewProc("InitCommonControlsEx")
)

type INITCOMMONCONTROLSEX struct {
	dwSize uint32
	dwICC  uint32
}

func initCommonControls() {
	var icc INITCOMMONCONTROLSEX
	icc.dwSize = uint32(unsafe.Sizeof(icc))
	icc.dwICC = 0x0000FFFF

	if procInitCommonControlsEx != nil {
		ret, _, err := procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))
		if ret == 0 {
			fmt.Printf("Warning: InitCommonControlsEx failed: %v\n", err)
		}
	}
}
