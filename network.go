package main

import (
	"fmt"
	"unsafe"
)

type ConnectionInfo struct {
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	Protocol   string
}

type MibTcprowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type MibUdprowOwnerPid struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

func GetProcessConnections(pid uint32) map[string]ConnectionInfo {
	connections := make(map[string]ConnectionInfo)

	for _, conn := range getTCPConnections(pid) {
		key := fmt.Sprintf("tcp_%s_%d", conn.RemoteAddr, conn.RemotePort)
		connections[key] = conn
	}

	for _, conn := range getUDPConnections(pid) {
		key := fmt.Sprintf("udp_%d", conn.LocalPort)
		connections[key] = conn
	}

	return connections
}

func getTCPConnections(pid uint32) []ConnectionInfo {
	var connections []ConnectionInfo
	var size uint32 = 0

	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, 2, 5, 0)
	if size == 0 {
		return connections
	}

	buffer := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
		0, 2, 5, 0)

	if ret != 0 {
		return connections
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buffer[0]))
	rows := (*[1 << 20]MibTcprowOwnerPid)(unsafe.Pointer(&buffer[4]))[:numEntries:numEntries]

	for _, row := range rows {
		if row.OwningPid == pid && row.RemoteAddr != 0 {
			connections = append(connections, ConnectionInfo{
				LocalPort:  uint16(row.LocalPort>>8 | row.LocalPort<<8),
				RemoteAddr: formatIP(row.RemoteAddr),
				RemotePort: uint16(row.RemotePort>>8 | row.RemotePort<<8),
				Protocol:   "TCP",
			})
		}
	}

	return connections
}

func getUDPConnections(pid uint32) []ConnectionInfo {
	var connections []ConnectionInfo
	var size uint32 = 0

	procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, 2, 1, 0)
	if size == 0 {
		return connections
	}

	buffer := make([]byte, size)
	ret, _, _ := procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
		0, 2, 1, 0)

	if ret != 0 {
		return connections
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buffer[0]))
	rows := (*[1 << 20]MibUdprowOwnerPid)(unsafe.Pointer(&buffer[4]))[:numEntries:numEntries]

	for _, row := range rows {
		if row.OwningPid == pid {
			connections = append(connections, ConnectionInfo{
				LocalPort:  uint16(row.LocalPort>>8 | row.LocalPort<<8),
				RemoteAddr: "",
				RemotePort: 0,
				Protocol:   "UDP",
			})
		}
	}

	return connections
}

func formatIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}
