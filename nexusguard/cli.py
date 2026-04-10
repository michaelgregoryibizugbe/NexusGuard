"""
CLI Entry Point for NexusGuard
"""

import argparse
import sys
import os

from nexusguard.tui.app import run_tui
from nexusguard.web.app import run_web


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        prog='nexusguard',
        description='🛡️ NexusGuard - Advanced IPS/IDS System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nexusguard tui                  Launch TUI mode
  nexusguard web                  Launch Web GUI (port 8080)
  nexusguard web --port 9000      Launch Web GUI (port 9000)
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # TUI command
    tui_parser = subparsers.add_parser('tui', help='Launch Terminal UI')
    
    # Web command
    web_parser = subparsers.add_parser('web', help='Launch Web GUI')
    web_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    web_parser.add_argument('--port', type=int, default=8080, help='Port to bind to')
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(0)
    
    if args.command == 'tui':
        print("🛡️  Launching NexusGuard TUI...")
        run_tui()
        
    elif args.command == 'web':
        print(f"🛡️  Launching NexusGuard Web GUI on {args.host}:{args.port}...")
        run_web(host=args.host, port=args.port)


if __name__ == '__main__':
    main()
