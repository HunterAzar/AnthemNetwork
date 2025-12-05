package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type Config struct {
	WiresharkPath string `json:"wireshark_path"`
	AnthemPath    string `json:"anthem_path"`
	CapturePath   string `json:"capture_path"`
	Interface     string `json:"interface"`
}

const configFile = "network_capture_config.json"

const (
	TH32CS_SNAPPROCESS = 0x00000002
	PROCESS_ALL_ACCESS = 0x1F0FFF
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = kernel32.NewProc("Process32FirstW")
	procProcess32Next            = kernel32.NewProc("Process32NextW")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
	procGetExtendedTcpTable      = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable      = iphlpapi.NewProc("GetExtendedUdpTable")
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

type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type MIB_UDPROW_OWNER_PID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

type ConnectionInfo struct {
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	Protocol   string
}

func getDefaultCaptureDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, "Desktop", "AnthemNetworkCaptures")
}

func getValidatedDir(name, savedPath, defaultPath string) string {
	reader := bufio.NewReader(os.Stdin)

	if savedPath != "" {
		if info, err := os.Stat(savedPath); err == nil && info.IsDir() {
			fmt.Printf("Found saved %s directory: %s\n", name, savedPath)
			fmt.Print("Use this directory? (Y/n): ")
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))
			if response == "" || response == "y" || response == "yes" {
				return savedPath
			}
		} else {
			fmt.Printf("Saved %s directory no longer exists: %s\n", name, savedPath)
		}
	}

	if defaultPath != "" {
		fmt.Printf("Enter %s directory (or press Enter for default):\n[%s]\n> ", name, defaultPath)
	} else {
		fmt.Printf("Enter %s directory:\n> ", name)
	}

	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" && defaultPath != "" {
			input = defaultPath
		}

		if input != "" {

			err := os.MkdirAll(input, 0755)
			if err == nil {
				return input
			}
			fmt.Printf("Could not create directory: %s (%v)\n", input, err)
		}

		fmt.Printf("Please enter a valid %s directory: ", name)
	}
}

func main() {
	fmt.Println("=== Windows Network Traffic Capture Tool ===\n")

	config := loadConfig()

	wiresharkPath := getValidatedPath("Wireshark", config.WiresharkPath,
		`C:\Program Files\Wireshark\Wireshark.exe`)
	config.WiresharkPath = wiresharkPath
	fmt.Printf("Using Wireshark: %s\n", wiresharkPath)

	anthemPath := getValidatedPath("Anthem", config.AnthemPath,
		`C:\Program Files (x86)\Origin Games\Anthem\Anthem.exe`)
	config.AnthemPath = anthemPath
	fmt.Printf("Using Anthem: %s\n\n", anthemPath)

	captureDirDefault := getDefaultCaptureDir()
	captureDir := getValidatedDir("capture output", config.CapturePath, captureDirDefault)
	config.CapturePath = captureDir
	fmt.Printf("Capture files will be saved to: %s\n\n", captureDir)

	tsharkPath := filepath.Join(filepath.Dir(wiresharkPath), "tshark.exe")

	interfaceNum := selectInterface(tsharkPath, &config)
	config.Interface = interfaceNum
	fmt.Printf("Selected interface: %s\n\n", interfaceNum)

	saveConfig(config)

	fmt.Print("Press Enter to start the application and begin capture...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

	captureFile := startCapture(wiresharkPath, interfaceNum)
	defer os.Remove(captureFile)

	startApplication(anthemPath)

	appPID := waitForProcess("Anthem.exe")
	time.Sleep(1 * time.Second)
	if appPID == 0 {
		fmt.Println("Error: Could not find Anthem.exe process")
		return
	}
	fmt.Printf("Found Anthem.exe with PID: %d\n\n", appPID)

	connections := monitorConnections("Anthem.exe", appPID)

	stopCapture()

	if len(connections) > 0 {
		filterAndSave(wiresharkPath, captureFile, captureDir, connections)
	} else {
		fmt.Println("\nNo connections captured. Exiting.")
	}
}

func loadConfig() Config {
	config := Config{}
	data, err := os.ReadFile(configFile)
	if err != nil {
		return config
	}
	json.Unmarshal(data, &config)
	return config
}

func saveConfig(config Config) {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Printf("Warning: Could not save config: %v\n", err)
		return
	}
	if err := os.WriteFile(configFile, data, 0644); err != nil {
		fmt.Printf("Warning: Could not write config file: %v\n", err)
	}
}

func getValidatedPath(name, savedPath, defaultPath string) string {
	reader := bufio.NewReader(os.Stdin)

	if savedPath != "" {
		if _, err := os.Stat(savedPath); err == nil {
			fmt.Printf("Found saved %s path: %s\n", name, savedPath)
			fmt.Print("Use this path? (Y/n): ")
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))
			if response == "" || response == "y" || response == "yes" {
				return savedPath
			}
		} else {
			fmt.Printf("Saved %s path no longer exists: %s\n", name, savedPath)
		}
	}

	if _, err := os.Stat(defaultPath); err == nil {
		fmt.Printf("Enter %s path (or press Enter for default):\n[%s]\n> ", name, defaultPath)
	} else {
		fmt.Printf("Enter %s path:\n> ", name)
		defaultPath = ""
	}

	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" && defaultPath != "" {
			return defaultPath
		}

		if input != "" {
			if _, err := os.Stat(input); err == nil {
				return input
			}
			fmt.Printf("Path does not exist: %s\n", input)
		}

		fmt.Printf("Please enter a valid %s path: ", name)
	}
}

func findProcessByName(name string) uint32 {
	handle, _, _ := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
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

func waitForProcess(name string) uint32 {
	fmt.Printf("Waiting for %s process to start...\n", name)
	for i := 0; i < 30; i++ {
		pid := findProcessByName(name)
		if pid != 0 {
			return pid
		}
		time.Sleep(1 * time.Second)
	}
	return 0
}

func selectInterface(tsharkPath string, config *Config) string {
	if config.Interface != "" {
		fmt.Printf("Previously used interface: %s\n", config.Interface)
		fmt.Print("Use this interface? (y/n): ")

		var response string
		fmt.Scanln(&response)

		if strings.ToLower(strings.TrimSpace(response)) == "y" {
			fmt.Printf("Using interface: %s\n\n", config.Interface)
			return config.Interface
		}
	}

	fmt.Println("\nListing available network interfaces...")
	cmd := exec.Command(tsharkPath, "-D")
	output, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error listing interfaces: %v\n", err)
		fmt.Print("Enter interface number manually: ")
		var interfaceNum string
		fmt.Scanln(&interfaceNum)
		return interfaceNum
	}

	fmt.Println("Available interfaces:")
	fmt.Println(string(output))

	fmt.Print("Select interface number: ")
	var interfaceNum string
	fmt.Scanln(&interfaceNum)

	return strings.TrimSpace(interfaceNum)
}

func startCapture(wiresharkPath string, interfaceNum string) string {
	captureFile := filepath.Join(os.TempDir(), fmt.Sprintf("capture_%d.pcapng", time.Now().Unix()))
	fmt.Printf("\nStarting Wireshark capture to: %s\n", captureFile)

	tsharkPath := filepath.Join(filepath.Dir(wiresharkPath), "tshark.exe")

	captureCmd := exec.Command(tsharkPath, "-i", interfaceNum, "-w", captureFile)

	if err := captureCmd.Start(); err != nil {
		fmt.Printf("Error starting capture: %v\n", err)
		os.Exit(1)
	}

	go func() {
		captureCmd.Wait()
	}()

	time.Sleep(2 * time.Second)
	fmt.Println("Capture started!\n")

	return captureFile
}

func stopCapture() {
	fmt.Println("\nApplication closed. Stopping capture...")

	time.Sleep(1 * time.Second)
}

func startApplication(anthemPath string) *exec.Cmd {
	fmt.Println("Launching application...")
	appCmd := exec.Command(anthemPath)
	if err := appCmd.Start(); err != nil {
		fmt.Printf("Error starting application: %v\n", err)
		os.Exit(1)
	}
	return appCmd
}

func monitorConnections(procName string, initialPID uint32) map[string]ConnectionInfo {
	connections := make(map[string]ConnectionInfo)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	pid := initialPID

	if pid == 0 {
		fmt.Printf("Process %s not found. Waiting up to 15 seconds for it to start...\n", procName)
		timeout := time.After(60 * time.Second)
		checkTicker := time.NewTicker(500 * time.Millisecond)
		defer checkTicker.Stop()

		processFound := false
		for !processFound {
			select {
			case <-timeout:
				fmt.Printf("Timeout: %s did not start within 15 seconds.\n", procName)
				return connections
			case <-checkTicker.C:
				pid = findProcessByName(procName)
				if pid != 0 {
					fmt.Printf("Process %s found with PID %d. Starting monitoring...\n", procName, pid)
					processFound = true
				}
			}
		}
	}

	fmt.Println("Monitoring network connections...")
	fmt.Println("Close the application to stop monitoring and filter capture.\n")

	for {
		select {
		case <-ticker.C:

			currentPID := findProcessByName(procName)

			if currentPID == 0 {
				fmt.Printf("%s not found. Waiting up to 15 seconds for it to restart...\n", procName)
				timeout := time.After(15 * time.Second)
				checkTicker := time.NewTicker(500 * time.Millisecond)

				processFound := false
				for !processFound {
					select {
					case <-timeout:
						checkTicker.Stop()
						fmt.Printf("%s is no longer running. Stopping monitoring.\n", procName)
						return connections
					case <-checkTicker.C:
						currentPID = findProcessByName(procName)
						if currentPID != 0 {
							checkTicker.Stop()
							fmt.Printf("Process %s found again with PID %d. Resuming monitoring...\n", procName, currentPID)
							pid = currentPID
							processFound = true
						}
					}
				}
				continue
			}

			if currentPID != pid {
				fmt.Printf("Detected PID change for %s: %d -> %d\n", procName, pid, currentPID)
				pid = currentPID
			}

			newConns := getProcessConnections(pid)
			for key, conn := range newConns {
				if _, exists := connections[key]; !exists {
					connections[key] = conn
					if conn.RemoteAddr != "" {
						fmt.Printf("New connection (PID %d): %s -> %s:%d\n",
							pid, conn.Protocol, conn.RemoteAddr, conn.RemotePort)
					} else {
						fmt.Printf("New connection (PID %d): %s port %d\n",
							pid, conn.Protocol, conn.LocalPort)
					}
				}
			}
		}
	}
}

func getProcessConnections(pid uint32) map[string]ConnectionInfo {
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
	rows := (*[1 << 20]MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buffer[4]))[:numEntries:numEntries]

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
	rows := (*[1 << 20]MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&buffer[4]))[:numEntries:numEntries]

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

func filterAndSave(wiresharkPath, captureFile, captureDir string, connections map[string]ConnectionInfo) {

	if err := os.MkdirAll(captureDir, 0755); err != nil {
		fmt.Printf("Error creating capture directory %s: %v\n", captureDir, err)
		fmt.Printf("Falling back to current directory.\n")
		captureDir = "."
	}

	fmt.Printf("\nFound %d unique connections\n", len(connections))
	fmt.Println("Building Wireshark filter...")

	filter := buildWiresharkFilter(connections)
	fmt.Printf("Filter: %s\n\n", filter)

	outputFile := filepath.Join(
		captureDir,
		fmt.Sprintf("anthem_filtered_%d.pcapng", time.Now().Unix()),
	)
	fmt.Printf("Filtering capture and saving to: %s\n", outputFile)

	tsharkPath := filepath.Join(filepath.Dir(wiresharkPath), "tshark.exe")
	filterCmd := exec.Command(tsharkPath,
		"-r", captureFile,
		"-Y", filter,
		"-w", outputFile)

	if err := filterCmd.Run(); err != nil {
		fmt.Printf("Error filtering capture: %v\n", err)
		fmt.Printf("Original capture saved at: %s\n", captureFile)
		return
	}

	fmt.Println("Filtered capture saved successfully!")
	fmt.Printf("\nDone! Filtered capture: %s\n", outputFile)
}

func buildWiresharkFilter(connections map[string]ConnectionInfo) string {
	var filters []string

	for _, conn := range connections {
		if conn.RemoteAddr != "" {
			if conn.Protocol == "tcp" {
				filters = append(filters, fmt.Sprintf("(ip.addr == %s and tcp.port == %d)",
					conn.RemoteAddr, conn.RemotePort))
			} else if conn.Protocol == "udp" {
				filters = append(filters, fmt.Sprintf("(ip.addr == %s and udp.port == %d)",
					conn.RemoteAddr, conn.RemotePort))
			} else {
				filters = append(filters, fmt.Sprintf("((ip.addr == %s and tcp.port == %d) or (ip.addr == %s and udp.port == %d))",
					conn.RemoteAddr, conn.RemotePort, conn.RemoteAddr, conn.RemotePort))
			}
		} else {
			filters = append(filters, fmt.Sprintf("udp.port == %d", conn.LocalPort))
		}
	}

	if len(filters) == 0 {
		return "ip"
	}

	return strings.Join(filters, " or ")
}
