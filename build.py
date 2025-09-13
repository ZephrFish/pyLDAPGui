#!/usr/bin/env python3
"""
# Unified Build Script for pyLDAPGui
~ Description : Single build script that handles executable creation for all platforms
                (Windows, macOS, Linux) with automatic platform detection

@ Usage:
  - python build.py              : Build for current platform
  - python build.py --clean      : Clean build directories before building
  - python build.py --version X  : Build with specific version number

@ Features:
  - Automatic platform detection
  - PyInstaller integration
  - Clean build option
  - Version management
  - Icon handling for all platforms
"""

import os
import sys
import subprocess
import shutil
import platform
import argparse
from pathlib import Path


class Builder:
    """
    # pyLDAPGui Builder
    ~ Description : Manages the build process for all supported platforms
    
    @ Attributes:
        version     : Version string for the build
        system      : Current platform (windows, darwin, linux)
        root_dir    : Project root directory
        build_dir   : Build output directory
        dist_dir    : Distribution output directory
    """
    
    def __init__(self, version="1.0.0"):
        self.version = version
        self.system = platform.system().lower()
        self.root_dir = Path(__file__).parent
        self.build_dir = self.root_dir / "build"
        self.dist_dir = self.root_dir / "dist"
        
    def clean(self):
        """Clean build and dist directories"""
        print("Cleaning build directories...")
        for directory in [self.build_dir, self.dist_dir]:
            if directory.exists():
                shutil.rmtree(directory)
        print("Build directories cleaned")
        
    def build(self):
        """
        # Main build method
        ~ Description : Detects platform and runs appropriate build process
        
        @ Returns:
            bool : Success status
        """
        print(f"Building pyLDAPGui v{self.version} for {self.system.title()}")
        
        # Ensure requirements are installed
        if not self._check_requirements():
            return False
            
        # Use direct PyInstaller command based on platform
        if self.system == "windows":
            return self._build_windows()
        elif self.system == "darwin":
            return self._build_macos()
        else:  # Linux
            return self._build_linux()
            
    def _check_requirements(self):
        """Check if PyInstaller is installed"""
        try:
            import PyInstaller
            return True
        except ImportError:
            print("PyInstaller not found. Installing...")
            try:
                subprocess.run([
                    sys.executable, "-m", "pip", "install", "pyinstaller"
                ], check=True)
                return True
            except:
                print("Failed to install PyInstaller")
                return False
                
    def _build_windows(self):
        """Build for Windows"""
        print("Building Windows executable...")
        
        # Check for icon
        icon_path = self.root_dir / "assets" / "pyldap_gui.ico"
        if not icon_path.exists():
            print("Warning: Icon file not found, building without icon")
            icon_args = []
        else:
            icon_args = ["--icon", str(icon_path)]
            
        # Build command
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onefile",
            "--windowed",
            "--name", "pyLDAPGui",
            "--clean",
            "--noconfirm",
            "--add-data", f"assets{os.pathsep}assets",
            "--add-data", f"utilities{os.pathsep}utilities",
            "--add-data", f"README.md{os.pathsep}.",
            "--hidden-import", "ldap3",
            "--hidden-import", "cryptography",
            "--hidden-import", "PyQt6.QtCore",
            "--hidden-import", "PyQt6.QtGui",
            "--hidden-import", "PyQt6.QtWidgets",
            "--hidden-import", "python_socks",
            "--hidden-import", "neo4j"
        ] + icon_args + ["main.py"]
        
        try:
            subprocess.run(cmd, check=True)
            print(f"Build complete! Executable in: {self.dist_dir}/pyLDAPGui.exe")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Build failed: {e}")
            return False
            
    def _build_macos(self):
        """Build for macOS"""
        print("Building macOS application...")
        print("Note: macOS requires --onedir mode for .app bundles")
        
        # Check for icon - try multiple options
        icon_path = None
        icon_options = [
            self.root_dir / "assets" / "pyldap_gui.icns",
            self.root_dir / "assets" / "image.png",
            self.root_dir / "assets" / "pyldap_gui.png",
            self.root_dir / "assets" / "pyldap_gui.ico"
        ]
        
        for icon_option in icon_options:
            if icon_option.exists() and icon_option.stat().st_size > 0:
                icon_path = icon_option
                print(f"Using icon: {icon_path.name}")
                # For macOS, if we have a PNG or ICO, PyInstaller will convert it with Pillow
                if icon_path.suffix in ['.png', '.ico']:
                    print("Note: PyInstaller will convert the icon to .icns format")
                break
        
        if not icon_path:
            print("Warning: No valid icon file found, building without icon")
            icon_args = []
        else:
            icon_args = ["--icon", str(icon_path)]
            
        # Build command
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onedir",  # Required for macOS
            "--windowed",
            "--name", "pyLDAPGui",
            "--clean",
            "--noconfirm",
            "--add-data", "assets:assets",
            "--add-data", "utilities:utilities",
            "--add-data", "README.md:.",
            "--hidden-import", "ldap3",
            "--hidden-import", "cryptography",
            "--hidden-import", "PyQt6.QtCore",
            "--hidden-import", "PyQt6.QtGui", 
            "--hidden-import", "PyQt6.QtWidgets",
            "--hidden-import", "python_socks",
            "--hidden-import", "neo4j",
            "--osx-bundle-identifier", "com.zephrfish.pyldapgui"
        ] + icon_args + ["main.py"]
        
        try:
            subprocess.run(cmd, check=True)
            print(f"Build complete! Application in: {self.dist_dir}/pyLDAPGui.app")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Build failed: {e}")
            return False
            
    def _build_linux(self):
        """Build for Linux"""
        print("Building Linux executable...")
        
        # Build command
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onefile",
            "--name", "pyLDAPGui",
            "--clean",
            "--noconfirm",
            "--add-data", "assets:assets",
            "--add-data", "utilities:utilities",
            "--add-data", "README.md:.",
            "--hidden-import", "ldap3",
            "--hidden-import", "cryptography",
            "--hidden-import", "PyQt6.QtCore",
            "--hidden-import", "PyQt6.QtGui",
            "--hidden-import", "PyQt6.QtWidgets",
            "--hidden-import", "python_socks",
            "--hidden-import", "neo4j",
            "main.py"
        ]
        
        try:
            subprocess.run(cmd, check=True)
            print(f"Build complete! Executable in: {self.dist_dir}/pyLDAPGui")
            
            # Make executable
            exe_path = self.dist_dir / "pyLDAPGui"
            if exe_path.exists():
                exe_path.chmod(0o755)
                
            return True
        except subprocess.CalledProcessError as e:
            print(f"Build failed: {e}")
            return False
            
    def create_version_info(self):
        """Create version info file for Windows builds"""
        if self.system != "windows":
            return
            
        version_parts = self.version.split('.')
        while len(version_parts) < 4:
            version_parts.append('0')
            
        version_info = f'''VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({','.join(version_parts)}),
    prodvers=({','.join(version_parts)}),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'ZephrFish'),
         StringStruct(u'FileDescription', u'pyLDAPGui - LDAP Browser'),
         StringStruct(u'FileVersion', u'{self.version}'),
         StringStruct(u'InternalName', u'pyLDAPGui'),
         StringStruct(u'LegalCopyright', u'2025 ZephrFish. MIT License.'),
         StringStruct(u'OriginalFilename', u'pyLDAPGui.exe'),
         StringStruct(u'ProductName', u'pyLDAPGui'),
         StringStruct(u'ProductVersion', u'{self.version}')])
    ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
'''
        with open(self.root_dir / "version_info.txt", 'w') as f:
            f.write(version_info)


def main():
    """
    # Main entry point
    ~ Description : Parses arguments and runs build process
    """
    parser = argparse.ArgumentParser(description='Build pyLDAPGui executable')
    parser.add_argument('--version', default='1.0.0', help='Version number')
    parser.add_argument('--clean', action='store_true', help='Clean before building')
    
    args = parser.parse_args()
    
    # Create builder
    builder = Builder(version=args.version)
    
    # Clean if requested
    if args.clean:
        builder.clean()
        
    # Create version info for Windows
    builder.create_version_info()
    
    # Run build
    success = builder.build()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()