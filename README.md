# Tool for capturing network of given application

It is supposed to be used with Anthem, but you can just enter path of any application.
Feel free to edit it or whatever

**It's not compatible with system any other than Windows!!!** (tested only on win10 lol)

## Disclaimer

Capture file can still contain data as EA profile data, personal data or authentication data.
Don't share those capture files with the public!!!

#### Requirements
1. Wireshark installed
2. Ability to read
3. Free space on disk


#### Building from source
1. Install golang
2. Run `rsrc -manifest captureAnthem.manifest -o rsrc.sys`
3. Build with `go build -ldflags="-H windowsgui" -o app.exe` or run with `go run -ldflags="-H windowsgui" `
