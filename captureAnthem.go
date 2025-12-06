package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
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

type MyMainWindow struct {
	*walk.MainWindow
	wiresharkEdit  *walk.LineEdit
	anthemEdit     *walk.LineEdit
	captureEdit    *walk.LineEdit
	interfaceCombo *walk.ComboBox
	startBtn       *walk.PushButton
	stopCaptureBtn *walk.PushButton
	stopBothBtn    *walk.PushButton
	logEdit        *walk.TextEdit
	statusBar      *walk.StatusBarItem
	config         Config
	captureFile    string
	captureCmd     *exec.Cmd
	isCapturing    bool
	stopCapture    chan bool
	anthemPID      uint32
	connections    map[string]ConnectionInfo
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

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Panic occurred: %v\n", r)
			panic(r)
		}
	}()
	initCommonControls()

	mw := &MyMainWindow{
		config:      loadConfig(),
		stopCapture: make(chan bool),
		connections: make(map[string]ConnectionInfo),
	}

	if err := (MainWindow{
		AssignTo: &mw.MainWindow,
		Title:    "Network Traffic Capture Tool",
		MinSize:  Size{Width: 800, Height: 600},
		Layout:   VBox{},
		StatusBarItems: []StatusBarItem{
			{
				AssignTo: &mw.statusBar,
				Text:     "Ready",
			},
		},
		Children: []Widget{
			GroupBox{
				Title:  "Configuration",
				Layout: Grid{Columns: 3},
				Children: []Widget{
					Label{Text: "Wireshark Path:"},
					LineEdit{
						AssignTo: &mw.wiresharkEdit,
						Text:     mw.config.WiresharkPath,
					},
					PushButton{
						Text: "Browse...",
						OnClicked: func() {
							dlg := new(walk.FileDialog)
							dlg.Title = "Select Wireshark.exe"
							dlg.Filter = "Executable Files (*.exe)|*.exe"
							if ok, _ := dlg.ShowOpen(mw); ok {
								mw.wiresharkEdit.SetText(dlg.FilePath)
							}
						},
					},

					Label{Text: "Anthem Path:"},
					LineEdit{
						AssignTo: &mw.anthemEdit,
						Text:     mw.config.AnthemPath,
					},
					PushButton{
						Text: "Browse...",
						OnClicked: func() {
							dlg := new(walk.FileDialog)
							dlg.Title = "Select Anthem.exe"
							dlg.Filter = "Executable Files (*.exe)|*.exe"
							if ok, _ := dlg.ShowOpen(mw); ok {
								mw.anthemEdit.SetText(dlg.FilePath)
							}
						},
					},

					Label{Text: "Capture Directory:"},
					LineEdit{
						AssignTo: &mw.captureEdit,
						Text:     mw.config.CapturePath,
					},
					PushButton{
						Text: "Browse...",
						OnClicked: func() {
							dlg := new(walk.FileDialog)
							dlg.Title = "Select Capture Directory"
							if ok, _ := dlg.ShowBrowseFolder(mw); ok {
								mw.captureEdit.SetText(dlg.FilePath)
							}
						},
					},

					Label{Text: "Network Interface:"},
					ComboBox{
						AssignTo: &mw.interfaceCombo,
						Editable: false,
					},
					PushButton{
						Text: "Refresh",
						OnClicked: func() {
							mw.refreshInterfaces()
						},
					},
				},
			},

			Composite{
				Layout: HBox{},
				Children: []Widget{
					PushButton{
						AssignTo: &mw.startBtn,
						Text:     "Start Capture",
						OnClicked: func() {
							go mw.startCapture()
						},
					},
					PushButton{
						AssignTo: &mw.stopCaptureBtn,
						Text:     "Stop Capture Only",
						Enabled:  false,
						OnClicked: func() {
							go mw.stopCaptureOnly()
						},
					},
					PushButton{
						AssignTo: &mw.stopBothBtn,
						Text:     "Stop Capture & Close Anthem",
						Enabled:  false,
						OnClicked: func() {
							go mw.stopCaptureAndCloseAnthem()
						},
					},
					HSpacer{},
				},
			},

			GroupBox{
				Title:  "Log",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{
						AssignTo: &mw.logEdit,
						ReadOnly: true,
						VScroll:  true,
					},
				},
			},
		},
	}.Create()); err != nil {
		panic(err)
	}

	if mw.captureEdit.Text() == "" {
		mw.captureEdit.SetText(getDefaultCaptureDir())
	}

	if mw.config.Interface != "" {
		mw.interfaceCombo.SetText(mw.config.Interface)
	}

	if mw.config.WiresharkPath != "" {
		go mw.refreshInterfaces()
	}

	mw.Run()
}

func (mw *MyMainWindow) log(message string) {
	timestamp := time.Now().Format("15:04:05")
	logMsg := fmt.Sprintf("[%s] %s\r\n", timestamp, message)

	mw.Synchronize(func() {
		mw.logEdit.AppendText(logMsg)
	})

	logFile := filepath.Join(getDefaultCaptureDir(), "capture_log.txt")

	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		defer f.Close()
		f.WriteString(message + "\n")
	}
}

func (mw *MyMainWindow) updateStatus(status string) {
	mw.Synchronize(func() {
		if mw.statusBar != nil {
			mw.statusBar.SetText(status)
		}
	})
}

func (mw *MyMainWindow) refreshInterfaces() {
	wiresharkPath := mw.wiresharkEdit.Text()
	if wiresharkPath == "" {
		mw.log("Please set Wireshark path first")
		return
	}

	tsharkPath := filepath.Join(filepath.Dir(wiresharkPath), "tshark.exe")
	if _, err := os.Stat(tsharkPath); err != nil {
		mw.log(fmt.Sprintf("tshark.exe not found at: %s", tsharkPath))
		return
	}

	mw.log(fmt.Sprintf("Trying to run tshark at: %s", tsharkPath))
	cmd := exec.Command(tsharkPath, "-D")
	output, err := cmd.CombinedOutput()

	if err != nil {
		mw.log(fmt.Sprintf("Error listing interfaces: %v", err))
		return
	}

	lines := strings.Split(string(output), "\n")
	var interfaces []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			interfaces = append(interfaces, line)
		}
	}

	mw.Synchronize(func() {
		mw.interfaceCombo.SetModel([]string{})
		mw.interfaceCombo.SetModel(interfaces)

		if mw.config.Interface != "" {
			for i, iface := range interfaces {
				if iface == mw.config.Interface {
					mw.interfaceCombo.SetCurrentIndex(i)
					break
				}
			}
		}
	})

	mw.log("Interfaces refreshed")
}

func (mw *MyMainWindow) stopCaptureOnly() {
	mw.log("Stopping capture only...")
	select {
	case mw.stopCapture <- false:
	default:
	}
}

func (mw *MyMainWindow) stopCaptureAndCloseAnthem() {
	mw.log("Stopping capture and closing Anthem...")
	select {
	case mw.stopCapture <- true:
	default:
	}
}

func (mw *MyMainWindow) startCapture() {
	wiresharkPath := mw.wiresharkEdit.Text()
	if wiresharkPath == "" {
		mw.Synchronize(func() {
			walk.MsgBox(mw, "Error", "Please select Wireshark path", walk.MsgBoxIconError)
		})
		return
	}

	anthemPath := mw.anthemEdit.Text()
	if anthemPath == "" {
		mw.Synchronize(func() {
			walk.MsgBox(mw, "Error", "Please select Anthem path", walk.MsgBoxIconError)
		})
		return
	}

	captureDir := mw.captureEdit.Text()
	if captureDir == "" {
		captureDir = getDefaultCaptureDir()
	}

	interfaceIdx := mw.interfaceCombo.CurrentIndex()
	if interfaceIdx < 0 {
		mw.Synchronize(func() {
			walk.MsgBox(mw, "Error", "Please select network interface", walk.MsgBoxIconError)
		})
		return
	}

	interfaceFull := mw.interfaceCombo.Text()

	if interfaceFull == "" {
		mw.log("No network interface selected")
		return
	}

	interfaceNum := strings.Fields(interfaceFull)[0]
	interfaceNum = strings.TrimRight(interfaceNum, ". ")

	mw.log(fmt.Sprintf("Interface full: '%s'", interfaceFull))
	mw.log(fmt.Sprintf("Interface number: '%s'", interfaceNum))

	mw.config.WiresharkPath = wiresharkPath
	mw.config.AnthemPath = anthemPath
	mw.config.CapturePath = captureDir
	mw.config.Interface = interfaceFull
	saveConfig(mw.config)

	mw.Synchronize(func() {
		mw.startBtn.SetEnabled(false)
		mw.stopCaptureBtn.SetEnabled(true)
		mw.stopBothBtn.SetEnabled(true)
	})
	mw.updateStatus("Capturing...")

	mw.runCapture(wiresharkPath, anthemPath, captureDir, interfaceNum)

	mw.Synchronize(func() {
		mw.startBtn.SetEnabled(true)
		mw.stopCaptureBtn.SetEnabled(false)
		mw.stopBothBtn.SetEnabled(false)
	})
	mw.updateStatus("Ready")
}

func (mw *MyMainWindow) runCapture(wiresharkPath, anthemPath, captureDir, interfaceNum string) {
	defer func() {
		if r := recover(); r != nil {
			mw.log(fmt.Sprintf("Panic in runCapture: %v", r))
			if mw.captureCmd != nil && mw.captureCmd.Process != nil {
				mw.captureCmd.Process.Kill()
			}
		}
	}()

	if err := os.MkdirAll(captureDir, 0755); err != nil {
		mw.log(fmt.Sprintf("Error creating capture directory: %v", err))
		return
	}

	mw.captureFile = filepath.Join(os.TempDir(), fmt.Sprintf("capture_%d.pcapng", time.Now().Unix()))
	mw.log(fmt.Sprintf("Starting capture to: %s", mw.captureFile))

	tsharkPath := filepath.Join(filepath.Dir(wiresharkPath), "tshark.exe")

	if _, err := os.Stat(tsharkPath); os.IsNotExist(err) {
		mw.log(fmt.Sprintf("tshark.exe not found at: %s", tsharkPath))
		return
	}

	mw.captureCmd = exec.Command(tsharkPath, "-i", interfaceNum, "-w", mw.captureFile)

	if err := mw.captureCmd.Start(); err != nil {
		mw.log(fmt.Sprintf("Error starting capture: %v", err))
		return
	}

	mw.isCapturing = true
	go func() {
		err := mw.captureCmd.Wait()
		if err != nil {
			mw.log(fmt.Sprintf("Capture process ended with error: %v", err))
		}
		mw.isCapturing = false
	}()

	time.Sleep(2 * time.Second)
	mw.log("Capture started!")

	if _, err := os.Stat(anthemPath); os.IsNotExist(err) {
		mw.log(fmt.Sprintf("Anthem.exe not found at: %s", anthemPath))
		return
	}

	mw.log("Launching Anthem...")
	appCmd := exec.Command(anthemPath)

	if err := appCmd.Start(); err != nil {
		mw.log(fmt.Sprintf("Error starting Anthem: %v", err))
		if mw.captureCmd != nil && mw.captureCmd.Process != nil {
			mw.captureCmd.Process.Kill()
		}
		return
	}

	mw.log("Waiting for Anthem.exe process...")
	appPID := mw.waitForProcess("Anthem.exe")
	if appPID == 0 {
		mw.log("Error: Could not find Anthem.exe process")
		if mw.captureCmd != nil && mw.captureCmd.Process != nil {
			mw.captureCmd.Process.Kill()
		}
		return
	}

	mw.anthemPID = appPID
	mw.log(fmt.Sprintf("Found Anthem.exe with PID: %d", appPID))
	mw.log("Monitoring connections... Use stop buttons to finish.")

	mw.connections = make(map[string]ConnectionInfo)
	mw.monitorConnections("Anthem.exe", appPID)
}

func (mw *MyMainWindow) waitForProcess(name string) uint32 {
	for i := 0; i < 30; i++ {
		pid := findProcessByName(name)
		if pid != 0 {
			return pid
		}
		time.Sleep(1 * time.Second)
	}
	return 0
}

func (mw *MyMainWindow) monitorConnections(procName string, initialPID uint32) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	pid := initialPID
	timeout := time.After(5 * time.Minute)

	for {
		select {
		case closeAnthem := <-mw.stopCapture:
			mw.log("Stop signal received")
			if closeAnthem {
				mw.log("Closing Anthem...")
				terminateProcess(pid)
			}
			mw.finalizeCapture()
			return

		case <-timeout:
			mw.log("Monitoring timeout reached")
			mw.finalizeCapture()
			return

		case <-ticker.C:
			currentPID := findProcessByName(procName)

			if currentPID == 0 {
				mw.log(fmt.Sprintf("%s not found, waiting...", procName))
				waitForProcessTimeout := time.After(15 * time.Second)
				checkTicker := time.NewTicker(500 * time.Millisecond)

				processFound := false
				for !processFound {
					select {
					case <-waitForProcessTimeout:
						checkTicker.Stop()
						mw.log(fmt.Sprintf("%s is no longer running", procName))
						mw.finalizeCapture()
						return
					case <-checkTicker.C:
						currentPID = findProcessByName(procName)
						if currentPID != 0 {
							checkTicker.Stop()
							mw.log(fmt.Sprintf("Process %s found again with PID %d", procName, currentPID))
							pid = currentPID
							processFound = true
						}
					}
				}
				continue
			}

			if currentPID != pid {
				mw.log(fmt.Sprintf("Detected PID change: %d -> %d", pid, currentPID))
				pid = currentPID
			}

			newConns := getProcessConnections(pid)
			for key, conn := range newConns {
				if _, exists := mw.connections[key]; !exists {
					mw.connections[key] = conn
					if conn.RemoteAddr != "" {
						mw.log(fmt.Sprintf("New connection: %s -> %s:%d", conn.Protocol, conn.RemoteAddr, conn.RemotePort))
					} else {
						mw.log(fmt.Sprintf("New connection: %s port %d", conn.Protocol, conn.LocalPort))
					}
				}
			}
		}
	}
}

func (mw *MyMainWindow) finalizeCapture() {
	mw.log("Stopping capture...")
	if mw.captureCmd != nil && mw.captureCmd.Process != nil {
		mw.captureCmd.Process.Kill()
	}
	time.Sleep(1 * time.Second)

	if len(mw.connections) > 0 {
		mw.log(fmt.Sprintf("Found %d unique connections", len(mw.connections)))
		captureDir := mw.captureEdit.Text()
		if captureDir == "" {
			captureDir = getDefaultCaptureDir()
		}
		wiresharkPath := mw.wiresharkEdit.Text()
		mw.filterAndSave(wiresharkPath, captureDir, mw.connections)
	} else {
		mw.log("No connections captured")
	}

	if mw.captureFile != "" {
		os.Remove(mw.captureFile)
	}

	mw.log("Capture complete!")
	mw.updateStatus("Capture complete")
}

func (mw *MyMainWindow) filterAndSave(wiresharkPath, captureDir string, connections map[string]ConnectionInfo) {
	filter := buildWiresharkFilter(connections)
	mw.log(fmt.Sprintf("Filter: %s", filter))

	outputFile := filepath.Join(captureDir, fmt.Sprintf("anthem_filtered_%d.pcapng", time.Now().Unix()))
	mw.log(fmt.Sprintf("Saving to: %s", outputFile))

	tsharkPath := filepath.Join(filepath.Dir(wiresharkPath), "tshark.exe")
	filterCmd := exec.Command(tsharkPath, "-r", mw.captureFile, "-Y", filter, "-w", outputFile)

	if err := filterCmd.Run(); err != nil {
		mw.log(fmt.Sprintf("Error filtering capture: %v", err))
		return
	}

	mw.log("Filtered capture saved successfully!")
	mw.log(fmt.Sprintf("Output: %s", outputFile))
}

func getDefaultCaptureDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, "Desktop", "AnthemNetworkCaptures")
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
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configFile, data, 0644)
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

func terminateProcess(pid uint32) bool {
	handle, _, _ := procOpenProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(pid))
	if handle == 0 {
		return false
	}
	defer procCloseHandle.Call(handle)

	ret, _, _ := procTerminateProcess.Call(handle, 0)
	return ret != 0
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

func buildWiresharkFilter(connections map[string]ConnectionInfo) string {
	var filters []string

	for _, conn := range connections {
		if conn.RemoteAddr != "" {
			protocol := strings.ToLower(conn.Protocol)
			filters = append(filters, fmt.Sprintf("(ip.addr == %s and %s.port == %d)",
				conn.RemoteAddr, protocol, conn.RemotePort))
		} else {
			filters = append(filters, fmt.Sprintf("udp.port == %d", conn.LocalPort))
		}
	}

	if len(filters) == 0 {
		return "ip"
	}

	return strings.Join(filters, " or ")
}
