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
- [ ] CLI Enhanced

### Features TODO
- [x] Custom wordlist support (allow user-supplied wordlists)
- [ ] Recursive directory enumeration (with depth control)
- [ ] Colored output and table formatting (pretty, aligned, colorized results)
- [ ] Progress bar (show scan progress)
- [ ] Rate limiting (requests per second)  
      # Note: Delay = wait after each request; Rate limiting = max requests per second (e.g., 10 req/sec)
- [ ] Export formats: CSV, PDF, Excel
- [ ] Verbose and silent modes
- [ ] Error logging to file
- [ ] Summary statistics (status code breakdown, fastest/slowest responses, etc.)
- [ ] Integration with other tools (optionally run vulnerability scan on found URLs)

## Progress
Features currently under testing:
- [ ] Recursive directory enumeration
- [ ] Colored output and table formatting
- [ ] Progress bar
- [ ] Export formats: CSV, PDF, Excel
- [ ] Verbose and silent modes
- [ ] Error logging to file
- [ ] Summary statistics
- [ ] Integration with other tools

## fixes

- [ ] !IMPORTANT handleCaptcha
- [ ] [cli.py] clean code - the colors using Fore are everywhere - organise it
- [X] prevent being flagged [partial]
