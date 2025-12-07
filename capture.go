package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

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
		pid := FindProcessByName(name)
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
				TerminateProcess(pid)
			}
			mw.finalizeCapture()
			return

		case <-timeout:
			mw.log("Monitoring timeout reached")
			mw.finalizeCapture()
			return

		case <-ticker.C:
			currentPID := FindProcessByName(procName)

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
						currentPID = FindProcessByName(procName)
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

			newConns := GetProcessConnections(pid)
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
			captureDir = GetDefaultCaptureDir()
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
	filter := BuildWiresharkFilter(connections)
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

func BuildWiresharkFilter(connections map[string]ConnectionInfo) string {
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
