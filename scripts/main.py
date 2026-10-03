#!/usr/bin/env python3
"""
Burp Suite Extension Development Skill

Main script for creating and managing Burp Suite extension projects.

Usage:
    python main.py create my-extension --lang java
    python main.py create my-extension --lang python
    python main.py list-templates
"""

import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Burp Suite Extension Development Tools"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Create command
    create_parser = subparsers.add_parser("create", help="Create a new extension project")
    create_parser.add_argument("name", type=str, help="Project name")
    create_parser.add_argument("--lang", "-l", type=str, choices=["java", "python"], 
                              default="java", help="Programming language")
    create_parser.add_argument("--package", "-p", type=str, default="com.yourname",
                              help="Java package name")
    create_parser.add_argument("--output", "-o", type=Path, default=Path.cwd(),
                              help="Output directory")
    
    # List templates command
    subparsers.add_parser("list-templates", help="List available templates")
    
    args = parser.parse_args()
    
    if args.command == "create":
        # Import and run create_project
        script_dir = Path(__file__).parent
        sys.path.insert(0, str(script_dir))
        from create_project import main as create_main
        sys.argv = ["create_project.py", args.name, "--lang", args.lang, 
                    "--package", args.package, "--output", str(args.output)]
        return create_main()
    
    elif args.command == "list-templates":
        print("\nAvailable templates:")
        print("  java     - Java extension with Maven build (default)")
        print("  python   - Python extension using Jython")
        print("\nUsage:")
        print("  python main.py create my-extension --lang java")
        print("  python main.py create my-extension --lang python")
        return 0
    
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
