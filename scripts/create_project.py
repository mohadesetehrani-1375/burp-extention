#!/usr/bin/env python3
"""
Burp Suite Extension Project Generator

Creates a new Burp Suite extension project with proper structure and templates.

Usage:
    python create_project.py my-extension --lang java
    python create_project.py my-extension --lang python
    python create_project.py my-extension --lang java --package com.mycompany
"""

import argparse
import os
import shutil
import sys
from pathlib import Path


def create_java_project(project_dir: Path, name: str, package: str):
    """Create a Java extension project."""
    # Create directory structure
    package_path = project_dir / "src" / "main" / "java" / package.replace(".", "/")
    package_path.mkdir(parents=True, exist_ok=True)
    
    # Copy templates
    template_dir = Path(__file__).parent.parent / "templates" / "java"
    
    # Copy and customize pom.xml
    pom_content = (template_dir / "pom.xml").read_text()
    pom_content = pom_content.replace("com.yourname", package)
    pom_content = pom_content.replace("burp-extension", name)
    (project_dir / "pom.xml").write_text(pom_content)
    
    # Copy and customize BurpExtender.java
    extender_content = (template_dir / "BurpExtender.java").read_text()
    extender_content = extender_content.replace("com.yourname.burp", f"{package}.burp")
    extender_content = extender_content.replace("My Burp Extension", name.replace("-", " ").title())
    (package_path / "BurpExtender.java").write_text(extender_content)
    
    # Copy HttpListener.java
    listener_content = (template_dir / "HttpListener.java").read_text()
    listener_content = listener_content.replace("com.yourname.burp", f"{package}.burp")
    (package_path / "HttpListener.java").write_text(listener_content)
    
    # Create README
    readme_content = f"""# {name}

Burp Suite extension for security testing.

## Build

```bash
mvn clean package
```

## Load in Burp Suite

1. Open Burp Suite
2. Go to Extender → Extensions
3. Click Add
4. Select the JAR file from target/
5. Click Next

## Development

Edit the Java files in `src/main/java/{package.replace('.', '/')}/`

- `BurpExtender.java` - Main entry point
- `HttpListener.java` - HTTP traffic listener
"""
    (project_dir / "README.md").write_text(readme_content)
    
    return ["pom.xml", "README.md", f"src/main/java/{package.replace('.', '/')}/BurpExtender.java", 
            f"src/main/java/{package.replace('.', '/')}/HttpListener.java"]


def create_python_project(project_dir: Path, name: str):
    """Create a Python extension project."""
    # Copy templates
    template_dir = Path(__file__).parent.parent / "templates" / "python"
    
    # Copy and customize burp_extender.py
    extender_content = (template_dir / "burp_extender.py").read_text()
    extender_content = extender_content.replace("My Python Extension", name.replace("-", " ").title())
    (project_dir / "burp_extender.py").write_text(extender_content)
    
    # Create requirements.txt
    (project_dir / "requirements.txt").write_text("# No external dependencies required\n# Jython is provided by Burp Suite\n")
    
    # Create README
    readme_content = f"""# {name}

Burp Suite extension for security testing (Python/Jython).

## Load in Burp Suite

1. Open Burp Suite
2. Go to Extender → Extensions
3. Click Add
4. Select Python as extension type
5. Browse to `burp_extender.py`
6. Click Next

## Development

Edit `burp_extender.py` to implement your extension logic.

Note: This extension uses Jython (Python 2.7 compatible).
"""
    (project_dir / "README.md").write_text(readme_content)
    
    return ["burp_extender.py", "requirements.txt", "README.md"]


def main():
    parser = argparse.ArgumentParser(
        description="Create a new Burp Suite extension project"
    )
    parser.add_argument(
        "name",
        type=str,
        help="Project name (lowercase with hyphens)"
    )
    parser.add_argument(
        "--lang", "-l",
        type=str,
        choices=["java", "python"],
        default="java",
        help="Programming language (default: java)"
    )
    parser.add_argument(
        "--package", "-p",
        type=str,
        default="com.yourname",
        help="Java package name (default: com.yourname)"
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path.cwd(),
        help="Output directory (default: current directory)"
    )
    
    args = parser.parse_args()
    
    # Validate project name
    if not args.name.isalnum() and "-" not in args.name:
        print("Error: Project name must be alphanumeric with hyphens only")
        return 1
    
    project_dir = args.output / args.name
    
    # Check if directory exists
    if project_dir.exists():
        print(f"Error: Directory already exists: {project_dir}")
        return 1
    
    # Create project directory
    project_dir.mkdir(parents=True)
    
    try:
        if args.lang == "java":
            files = create_java_project(project_dir, args.name, args.package)
        else:
            files = create_python_project(project_dir, args.name)
        
        print(f"\nCreated {args.lang} project: {args.name}/")
        for f in files:
            print(f"  + {f}")
        
        print("\nNext steps:")
        if args.lang == "java":
            print("  1. cd " + args.name)
            print("  2. mvn clean package")
            print("  3. Load target/*.jar in Burp Suite")
        else:
            print("  1. cd " + args.name)
            print("  2. Load burp_extender.py in Burp Suite")
        
        print()
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        shutil.rmtree(project_dir)
        return 1


if __name__ == "__main__":
    sys.exit(main())
