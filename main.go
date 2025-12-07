package main

import (
	"fmt"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Panic occurred: %v\n", r)
			panic(r)
		}
	}()

	initCommonControls()

	mw := NewMainWindow()

	if err := mw.Build(); err != nil {
		panic(err)
	}

	mw.Initialize()
	mw.Run()
}

func (mw *MyMainWindow) Build() error {
	return MainWindow{
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
						Text:      "Browse...",
						OnClicked: mw.browseWireshark,
					},

					Label{Text: "Anthem Path:"},
					LineEdit{
						AssignTo: &mw.anthemEdit,
						Text:     mw.config.AnthemPath,
					},
					PushButton{
						Text:      "Browse...",
						OnClicked: mw.browseAnthem,
					},

					Label{Text: "Capture Directory:"},
					LineEdit{
						AssignTo: &mw.captureEdit,
						Text:     mw.config.CapturePath,
					},
					PushButton{
						Text:      "Browse...",
						OnClicked: mw.browseCaptureDir,
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
	}.Create()
}

func (mw *MyMainWindow) Initialize() {
	if mw.captureEdit.Text() == "" {
		mw.captureEdit.SetText(GetDefaultCaptureDir())
	}

	if mw.config.Interface != "" {
		mw.interfaceCombo.SetText(mw.config.Interface)
	}

	if mw.config.WiresharkPath != "" {
		go mw.refreshInterfaces()
	}
}

func (mw *MyMainWindow) browseWireshark() {
	dlg := new(walk.FileDialog)
	dlg.Title = "Select Wireshark.exe"
	dlg.Filter = "Executable Files (*.exe)|*.exe"
	if ok, _ := dlg.ShowOpen(mw); ok {
		mw.wiresharkEdit.SetText(dlg.FilePath)
	}
}

func (mw *MyMainWindow) browseAnthem() {
	dlg := new(walk.FileDialog)
	dlg.Title = "Select Anthem.exe"
	dlg.Filter = "Executable Files (*.exe)|*.exe"
	if ok, _ := dlg.ShowOpen(mw); ok {
		mw.anthemEdit.SetText(dlg.FilePath)
	}
}

func (mw *MyMainWindow) browseCaptureDir() {
	dlg := new(walk.FileDialog)
	dlg.Title = "Select Capture Directory"
	if ok, _ := dlg.ShowBrowseFolder(mw); ok {
		mw.captureEdit.SetText(dlg.FilePath)
	}
}
