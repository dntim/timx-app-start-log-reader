# Process Start/Stop Log Reader

A .NET 9 console application that lists process launches and exits from the Windows Security event log.

## Overview

This tool reads Event IDs 4688 (process start) and 4689 (process exit) from the Windows Security log and pairs them to show how long each instance of a process ran. It's useful for tracking application usage and debugging process lifecycle issues.

## Features

- 📊 **Process tracking**: Matches process starts with exits to calculate runtime duration
- ⚡ **Fast streaming**: Efficiently reads event logs without loading everything into memory
- 🔐 **Auto-elevation**: Automatically requests Administrator privileges if needed
- 📅 **Time filtering**: Configurable lookback period (default 30 days)
- 📝 **Clear output**: Formatted table showing start time, finish time, duration, and process name

## Requirements

- Windows OS
- .NET 9.0 Runtime ([Download here](https://dotnet.microsoft.com/download/dotnet/9.0))
- Administrator privileges (for reading Security event log)
- Windows process auditing enabled (see setup below)

## Installation

### Option 1: Download Pre-built Executable
1. Download the latest release from the [Releases](../../releases) page
2. Extract `timx-app-start-log-reader.exe` to a folder of your choice
3. Run the executable (it will request elevation automatically)

### Option 2: Build from Source
```powershell
git clone https://github.com/dntim/timx-app-start-log-reader.git
cd timx-app-start-log-reader
dotnet publish -c Release -o publish
```

The executable will be in the `publish` folder.

## Usage

### Interactive Mode
Simply run the executable and follow the prompts:
```powershell
.\timx-app-start-log-reader.exe
```

You'll be asked for:
- **Process name**: e.g., `javaw` or `javaw.exe`
- **Days to look back**: e.g., `30` (default if left blank)

### Command-Line Mode
Pass parameters directly:
```powershell
.\timx-app-start-log-reader.exe javaw 30
```

### Example Output
```
Start                 Finish                Duration  Process
----------------------------------------------------------------------
2025-10-31 22:12:03   2025-10-31 23:05:44   00:53:41  javaw.exe
2025-10-31 14:30:15   2025-10-31 16:22:08   01:51:53  javaw.exe
2025-10-30 09:15:22   2025-10-30 12:45:33   03:30:11  javaw.exe
```

## Enabling Process Tracking

Process auditing must be enabled in Windows for this tool to work.

### Windows Home Edition
Run these commands as Administrator:
```cmd
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
```

Optional - to include command line in events:
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

### Windows Pro/Enterprise Edition
1. **Enable audit policies:**
   - Open `secpol.msc` (Local Security Policy)
   - Navigate to: Security Settings → Advanced Audit Policy Configuration → System Audit Policies → Detailed Tracking
   - Enable: **Audit Process Creation** (Success)
   - Enable: **Audit Process Termination** (Success)

2. **Optional - Include command line:**
   - Open `gpedit.msc` (Group Policy Editor)
   - Navigate to: Computer Configuration → Administrative Templates → System → Audit Process Creation
   - Enable: **Include command line in process creation events**

After enabling, wait for events to accumulate before running the tool.

## How It Works

1. Reads events from the Windows Security log using Event IDs 4688 and 4689
2. Parses event XML to extract process information (ProcessId, LogonId, timestamps)
3. Pairs process starts with their corresponding exits using `ProcessId + LogonId` as the key
4. Calculates duration for matched pairs
5. Displays results sorted by start time (descending)

## Technical Details

- **Framework**: .NET 9.0
- **Language**: C#
- **Dependencies**: System.Diagnostics.EventLog (9.0.0)
- **Architecture**: Single-file executable (framework-dependent)
- **Platform**: Windows x64

## Troubleshooting

**"No matching events found"**
- Process auditing may not be enabled (see setup above)
- The process may not have run in the specified time period
- Check if the process name is correct

**"Access denied to Security log"**
- The application requires Administrator privileges
- Right-click and "Run as administrator" if auto-elevation fails

## License

MIT License - See [LICENSE](LICENSE) file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Created by **Dmitry Timoshenko** ([@dntim](https://github.com/dntim))

This program was developed with the assistance of GitHub Copilot using GPT-5 and Claude Sonnet 4.5.
