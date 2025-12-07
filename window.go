package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/lxn/walk"
)

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

func NewMainWindow() *MyMainWindow {
	return &MyMainWindow{
		config:      LoadConfig(),
		stopCapture: make(chan bool),
		connections: make(map[string]ConnectionInfo),
	}
}

func (mw *MyMainWindow) log(message string) {
	timestamp := time.Now().Format("15:04:05")
	logMsg := fmt.Sprintf("[%s] %s\r\n", timestamp, message)

	mw.Synchronize(func() {
		mw.logEdit.AppendText(logMsg)
	})

	logFile := filepath.Join(GetDefaultCaptureDir(), "capture_log.txt")
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
		captureDir = GetDefaultCaptureDir()
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
	SaveConfig(mw.config)

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
