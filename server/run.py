#!/usr/bin/env python3

"""
Launcher for Advanced Directory Enumerator
Choose between CLI and TUI modes
"""

import sys
import os
import argparse

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Directory Enumerator Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py --cli https://example.com
  python run.py --tui
  python run.py --cli https://example.com --wordlist directories --workers 100
        """
    )
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--cli", action="store_true", help="Run in CLI mode")
    mode_group.add_argument("--tui", action="store_true", help="Run in TUI mode")
    
    # Pass through all other arguments to CLI
    parser.add_argument("args", nargs=argparse.REMAINDER, help="Arguments to pass to CLI mode")
    
    args = parser.parse_args()
    
    if args.tui:
        # Launch TUI mode
        try:
            from tui import main as tui_main
            tui_main()
        except ImportError as e:
            print(f"Error: TUI not available: {e}")
            print("Please install textual: pip install textual")
            sys.exit(1)
        except Exception as e:
            print(f"Error launching TUI: {e}")
            sys.exit(1)
    
    elif args.cli:
        # Launch CLI mode with remaining arguments
        try:
            from cli import main as cli_main
            # Set sys.argv to the remaining arguments
            sys.argv = [sys.argv[0]] + args.args
            import asyncio
            asyncio.run(cli_main())
        except ImportError as e:
            print(f"Error: CLI not available: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error launching CLI: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main() 