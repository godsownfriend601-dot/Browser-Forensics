#!/usr/bin/env python3
"""Browser Profile Detection Module.

Auto-detects installed browsers and their profile locations across
Windows, Linux, and macOS systems.

Supported browsers:
- Google Chrome
- Chromium
- Microsoft Edge
- Brave Browser
- Opera
- Vivaldi
- Firefox (for unified detection)
"""

import os
import sys
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class BrowserType(Enum):
    """Supported browser types."""
    FIREFOX = "firefox"
    CHROME = "chrome"
    CHROMIUM = "chromium"
    EDGE = "edge"
    BRAVE = "brave"
    OPERA = "opera"
    VIVALDI = "vivaldi"


class BrowserFamily(Enum):
    """Browser engine family."""
    GECKO = "gecko"      # Firefox
    CHROMIUM = "chromium"  # Chrome, Edge, Brave, etc.


@dataclass
class BrowserProfile:
    """Represents a detected browser profile."""
    browser_type: BrowserType
    browser_family: BrowserFamily
    profile_name: str
    profile_path: Path
    user_data_dir: Path  # Parent directory containing Local State
    is_default: bool = False
    display_name: str = ""
    
    def __post_init__(self):
        if not self.display_name:
            self.display_name = f"{self.browser_type.value.title()} - {self.profile_name}"


@dataclass 
class BrowserInstallation:
    """Represents an installed browser."""
    browser_type: BrowserType
    browser_family: BrowserFamily
    user_data_dir: Path
    profiles: List[BrowserProfile] = field(default_factory=list)
    version: Optional[str] = None
    executable_path: Optional[Path] = None


# =============================================================================
# Platform-specific profile locations
# =============================================================================

def get_chromium_paths_linux() -> Dict[BrowserType, List[Path]]:
    """Get Chromium-based browser paths on Linux."""
    home = Path.home()
    config_dir = home / ".config"
    snap_dir = home / "snap"
    flatpak_dir = home / ".var" / "app"
    
    return {
        BrowserType.CHROME: [
            config_dir / "google-chrome",
            snap_dir / "chromium" / "common" / "chromium",
        ],
        BrowserType.CHROMIUM: [
            config_dir / "chromium",
            snap_dir / "chromium" / "common" / "chromium",
        ],
        BrowserType.EDGE: [
            config_dir / "microsoft-edge",
            config_dir / "microsoft-edge-dev",
            config_dir / "microsoft-edge-beta",
        ],
        BrowserType.BRAVE: [
            config_dir / "BraveSoftware" / "Brave-Browser",
            config_dir / "BraveSoftware" / "Brave-Browser-Beta",
            config_dir / "BraveSoftware" / "Brave-Browser-Nightly",
        ],
        BrowserType.OPERA: [
            config_dir / "opera",
            config_dir / "opera-beta",
            config_dir / "opera-developer",
        ],
        BrowserType.VIVALDI: [
            config_dir / "vivaldi",
            config_dir / "vivaldi-snapshot",
        ],
    }


def get_chromium_paths_windows() -> Dict[BrowserType, List[Path]]:
    """Get Chromium-based browser paths on Windows."""
    local_appdata = Path(os.environ.get("LOCALAPPDATA", ""))
    appdata = Path(os.environ.get("APPDATA", ""))
    
    if not local_appdata.exists():
        return {}
    
    return {
        BrowserType.CHROME: [
            local_appdata / "Google" / "Chrome" / "User Data",
        ],
        BrowserType.CHROMIUM: [
            local_appdata / "Chromium" / "User Data",
        ],
        BrowserType.EDGE: [
            local_appdata / "Microsoft" / "Edge" / "User Data",
        ],
        BrowserType.BRAVE: [
            local_appdata / "BraveSoftware" / "Brave-Browser" / "User Data",
        ],
        BrowserType.OPERA: [
            appdata / "Opera Software" / "Opera Stable",
            appdata / "Opera Software" / "Opera GX Stable",
        ],
        BrowserType.VIVALDI: [
            local_appdata / "Vivaldi" / "User Data",
        ],
    }


def get_chromium_paths_macos() -> Dict[BrowserType, List[Path]]:
    """Get Chromium-based browser paths on macOS."""
    home = Path.home()
    app_support = home / "Library" / "Application Support"
    
    return {
        BrowserType.CHROME: [
            app_support / "Google" / "Chrome",
        ],
        BrowserType.CHROMIUM: [
            app_support / "Chromium",
        ],
        BrowserType.EDGE: [
            app_support / "Microsoft Edge",
        ],
        BrowserType.BRAVE: [
            app_support / "BraveSoftware" / "Brave-Browser",
        ],
        BrowserType.OPERA: [
            app_support / "com.operasoftware.Opera",
        ],
        BrowserType.VIVALDI: [
            app_support / "Vivaldi",
        ],
    }


def get_firefox_paths() -> Dict[BrowserType, List[Path]]:
    """Get Firefox profile paths across platforms."""
    home = Path.home()
    
    if sys.platform == "win32":
        appdata = Path(os.environ.get("APPDATA", ""))
        return {
            BrowserType.FIREFOX: [
                appdata / "Mozilla" / "Firefox" / "Profiles",
            ]
        }
    elif sys.platform == "darwin":
        return {
            BrowserType.FIREFOX: [
                home / "Library" / "Application Support" / "Firefox" / "Profiles",
            ]
        }
    else:  # Linux
        return {
            BrowserType.FIREFOX: [
                home / ".mozilla" / "firefox",
                home / "snap" / "firefox" / "common" / ".mozilla" / "firefox",
            ]
        }


# =============================================================================
# Profile Detection Functions
# =============================================================================

def detect_chromium_profiles(user_data_dir: Path, browser_type: BrowserType) -> List[BrowserProfile]:
    """Detect all profiles in a Chromium user data directory.
    
    Chromium stores profiles in folders like:
    - Default (main profile)
    - Profile 1, Profile 2, etc. (additional profiles)
    
    Args:
        user_data_dir: Path to the User Data directory
        browser_type: Type of browser
    
    Returns:
        List of detected BrowserProfile objects
    """
    profiles = []
    
    if not user_data_dir.exists():
        return profiles
    
    # Read Local State to get profile info
    local_state_path = user_data_dir / "Local State"
    profile_info = {}
    
    if local_state_path.exists():
        try:
            with open(local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
                profile_info = local_state.get("profile", {}).get("info_cache", {})
        except (json.JSONDecodeError, IOError):
            pass
    
    # Find profile directories
    potential_profiles = ["Default"] + [f"Profile {i}" for i in range(1, 20)]
    
    for profile_name in potential_profiles:
        profile_path = user_data_dir / profile_name
        
        # Check if it's a valid Chromium profile (has History or Preferences)
        if profile_path.exists() and (
            (profile_path / "History").exists() or
            (profile_path / "Preferences").exists()
        ):
            # Get display name from Local State if available
            display_name = profile_name
            if profile_name in profile_info:
                display_name = profile_info[profile_name].get("name", profile_name)
            
            profiles.append(BrowserProfile(
                browser_type=browser_type,
                browser_family=BrowserFamily.CHROMIUM,
                profile_name=profile_name,
                profile_path=profile_path,
                user_data_dir=user_data_dir,
                is_default=(profile_name == "Default"),
                display_name=f"{browser_type.value.title()} - {display_name}"
            ))
    
    return profiles


def detect_firefox_profiles(profiles_dir: Path) -> List[BrowserProfile]:
    """Detect all Firefox profiles in a profiles directory.
    
    Firefox uses profiles.ini and random folder names like:
    - xxxx.default
    - xxxx.default-release
    
    Args:
        profiles_dir: Path to Firefox profiles directory
    
    Returns:
        List of detected BrowserProfile objects
    """
    profiles = []
    
    if not profiles_dir.exists():
        return profiles
    
    # Look for profile directories (contain places.sqlite)
    for item in profiles_dir.iterdir():
        if item.is_dir() and (item / "places.sqlite").exists():
            # Parse profile name from folder name (e.g., "abc123.default-release")
            folder_name = item.name
            profile_name = folder_name
            is_default = "default" in folder_name.lower()
            
            profiles.append(BrowserProfile(
                browser_type=BrowserType.FIREFOX,
                browser_family=BrowserFamily.GECKO,
                profile_name=profile_name,
                profile_path=item,
                user_data_dir=profiles_dir,
                is_default=is_default,
                display_name=f"Firefox - {profile_name}"
            ))
    
    return profiles


# =============================================================================
# Main Detection Functions
# =============================================================================

def detect_all_browsers() -> List[BrowserInstallation]:
    """Detect all installed browsers and their profiles.
    
    Returns:
        List of BrowserInstallation objects with detected profiles
    """
    installations = []
    
    # Get platform-specific paths
    if sys.platform == "win32":
        chromium_paths = get_chromium_paths_windows()
    elif sys.platform == "darwin":
        chromium_paths = get_chromium_paths_macos()
    else:
        chromium_paths = get_chromium_paths_linux()
    
    firefox_paths = get_firefox_paths()
    
    # Detect Chromium-based browsers
    for browser_type, paths in chromium_paths.items():
        for user_data_dir in paths:
            if user_data_dir.exists():
                profiles = detect_chromium_profiles(user_data_dir, browser_type)
                if profiles:
                    installations.append(BrowserInstallation(
                        browser_type=browser_type,
                        browser_family=BrowserFamily.CHROMIUM,
                        user_data_dir=user_data_dir,
                        profiles=profiles,
                    ))
    
    # Detect Firefox
    for browser_type, paths in firefox_paths.items():
        for profiles_dir in paths:
            if profiles_dir.exists():
                profiles = detect_firefox_profiles(profiles_dir)
                if profiles:
                    installations.append(BrowserInstallation(
                        browser_type=browser_type,
                        browser_family=BrowserFamily.GECKO,
                        user_data_dir=profiles_dir,
                        profiles=profiles,
                    ))
    
    return installations


def detect_browser_from_path(profile_path: Path) -> Optional[Tuple[BrowserType, BrowserFamily]]:
    """Detect browser type from a profile path.
    
    Args:
        profile_path: Path to a browser profile
    
    Returns:
        Tuple of (BrowserType, BrowserFamily) or None if unknown
    """
    path_str = str(profile_path).lower()
    
    # Check for Firefox indicators
    if any(x in path_str for x in [".mozilla", "firefox"]):
        if (profile_path / "places.sqlite").exists():
            return (BrowserType.FIREFOX, BrowserFamily.GECKO)
    
    # Check for Chromium indicators
    chromium_indicators = {
        "google-chrome": BrowserType.CHROME,
        "google/chrome": BrowserType.CHROME,
        "chromium": BrowserType.CHROMIUM,
        "microsoft-edge": BrowserType.EDGE,
        "microsoft/edge": BrowserType.EDGE,
        "bravesoftware": BrowserType.BRAVE,
        "brave-browser": BrowserType.BRAVE,
        "opera": BrowserType.OPERA,
        "vivaldi": BrowserType.VIVALDI,
    }
    
    for indicator, browser_type in chromium_indicators.items():
        if indicator in path_str:
            # Verify it's a Chromium profile
            if (profile_path / "History").exists() or (profile_path / "Preferences").exists():
                return (browser_type, BrowserFamily.CHROMIUM)
    
    # Generic detection based on files present
    if (profile_path / "places.sqlite").exists():
        return (BrowserType.FIREFOX, BrowserFamily.GECKO)
    if (profile_path / "History").exists():
        return (BrowserType.CHROMIUM, BrowserFamily.CHROMIUM)
    
    return None


def get_default_profile(browser_type: BrowserType) -> Optional[BrowserProfile]:
    """Get the default profile for a specific browser.
    
    Args:
        browser_type: Type of browser to find
    
    Returns:
        Default BrowserProfile or None if not found
    """
    installations = detect_all_browsers()
    
    for installation in installations:
        if installation.browser_type == browser_type:
            # Return the default profile, or the first one
            for profile in installation.profiles:
                if profile.is_default:
                    return profile
            if installation.profiles:
                return installation.profiles[0]
    
    return None


def list_all_profiles() -> List[BrowserProfile]:
    """Get a flat list of all detected browser profiles.
    
    Returns:
        List of all BrowserProfile objects
    """
    profiles = []
    for installation in detect_all_browsers():
        profiles.extend(installation.profiles)
    return profiles


def print_detected_browsers():
    """Print a summary of detected browsers and profiles."""
    installations = detect_all_browsers()
    
    if not installations:
        print("No browsers detected.")
        return
    
    print("\n" + "=" * 60)
    print("DETECTED BROWSERS AND PROFILES")
    print("=" * 60)
    
    for installation in installations:
        print(f"\n[{installation.browser_type.value.upper()}]")
        print(f"  Family: {installation.browser_family.value}")
        print(f"  Data Dir: {installation.user_data_dir}")
        print(f"  Profiles:")
        for profile in installation.profiles:
            default_marker = " (default)" if profile.is_default else ""
            print(f"    - {profile.display_name}{default_marker}")
            print(f"      Path: {profile.profile_path}")
    
    print("\n" + "=" * 60)


# =============================================================================
# CLI for testing
# =============================================================================

if __name__ == "__main__":
    print_detected_browsers()
