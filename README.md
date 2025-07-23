# Sushhhscanner
## API Risk Visualizer

# Problem Statement
Create a tool that scans SaaS APIs to identify security risks (e.g., unprotected endpoints, weak authentication). The tool should generate a visual risk map and provide simple, actionable recommendations.

----------
----------

# TODO [ Enumerate Directories using CLI or WEB ]

## DIR ENUM 
   
- [x] cli BASE [Primitive-Stage]
- [x] initialiser
- [x] frontend
- [x] middleware 
- [x] [web-logic] backend [Primitive-Stage]
- [x] Custom wordlist support (allow user-supplied wordlists)
- [x] Recursive directory enumeration (with depth control)
- [x] Colored output and table formatting (pretty, aligned, colorized results)
- [x] Progress bar (show scan progress)
- [x] Rate limiting (requests per second)  
      # Note: Delay = wait after each request; Rate limiting = max requests per second (e.g., 10 req/sec)
- [x] Export formats: CSV, PDF, Excel
- [x] Verbose and silent modes
- [x] Error logging to file
- [x] Summary statistics (status code breakdown, fastest/slowest responses, etc.)
- [x] **NEW: Text User Interface (TUI) mode**

## Usage

### CLI Mode
```bash
# Basic usage
python server/cli.py https://example.com

# With options
python server/cli.py https://example.com --wordlist directories --workers 100 --delay 0.5

# Export results
python server/cli.py https://example.com --export-csv results.csv --export-pdf results.pdf

# Using launcher script
python server/run.py --cli https://example.com --wordlist directories --workers 100
```

### TUI Mode (Text User Interface)
```bash
# Launch TUI mode
python server/run.py --tui

# Or directly
python server/tui.py

# Or via CLI with --tui flag
python server/cli.py --tui
```

### TUI Features
- Interactive form-based input
- Real-time scan progress
- Live results table with color-coded status codes
- Export results to multiple formats (JSON, CSV, Excel, PDF)
- Start/Stop scan controls
- Clear results functionality

## Features TODO

- [x] Integration with other tools (optionally run vulnerability scan on found URLs)
- [ ] Enhanced PDF
- [ ] CLI Enhanced


## fixes

- [ ] Summary statistics [ fix .xlsx .pdf to include summary and error logs ]
- [x] del rdundancy overwrite the files on every scanf
- [ ] look for 429 or 403 and lower the speed
- [ ] !IMPORTANT handleCaptcha
- [ ] [cli.py] clean code - the colors using Fore are everywhere - organise it
- [x] [run.py] clean and update test , add tui along with cli , let install be but remove web since there is already a client [ integrate that ]
- [ ] integrate with existing client.py 
- [ ] multiple api support
- [ ] format pdf
- [ ] resolution to technical and non technical staff upon vuln scan
- [ ] using local llm 
- [X] prevent being flagged [partial]
