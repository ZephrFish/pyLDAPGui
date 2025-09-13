#!/usr/bin/env python3
"""
Simplified build script for pyLDAPGui
This version builds faster by excluding some optimisations
"""

import os
import sys
import subprocess
import shutil
import platform
from pathlib import Path


def build_simple():
    """Simple build without extras for CI/CD speed"""
    system = platform.system().lower()
    print(f"Building pyLDAPGui for {system} (simplified)")
    
    # Clean old builds
    for directory in ['build', 'dist']:
        if Path(directory).exists():
            shutil.rmtree(directory)
    
    # Base command - minimal options for speed
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "pyLDAPGui",
        "--noconfirm",
        "--clean"
    ]
    
    # Platform-specific options
    if system == "windows":
        cmd.extend([
            "--onefile",
            "--windowed",
            "--add-data", f"assets{os.pathsep}assets",
            "--add-data", f"utilities{os.pathsep}utilities"
        ])
        # Try to use icon if available
        if Path("assets/pyldap_gui.ico").exists():
            cmd.extend(["--icon", "assets/pyldap_gui.ico"])
            
    elif system == "darwin":
        # macOS - use onedir for speed, skip .app bundle
        cmd.extend([
            "--onedir",
            "--windowed",
            "--add-data", "assets:assets",
            "--add-data", "utilities:utilities"
        ])
        # Skip icon to avoid conversion issues
        
    else:  # Linux
        cmd.extend([
            "--onefile",
            "--add-data", "assets:assets",
            "--add-data", "utilities:utilities"
        ])
    
    # Add essential hidden imports only
    cmd.extend([
        "--hidden-import", "ldap3",
        "--hidden-import", "PyQt6.QtCore",
        "--hidden-import", "PyQt6.QtGui",
        "--hidden-import", "PyQt6.QtWidgets"
    ])
    
    # Add main script
    cmd.append("main.py")
    
    print("Running:", " ".join(cmd))
    
    try:
        subprocess.run(cmd, check=True)
        print("Build completed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Build failed: {e}")
        return False
    except KeyboardInterrupt:
        print("\nBuild interrupted by user")
        return False


if __name__ == "__main__":
    success = build_simple()
    sys.exit(0 if success else 1)