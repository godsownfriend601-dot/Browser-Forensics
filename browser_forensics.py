#!/usr/bin/env python3
"""Browser Forensics Extraction Tool.

A comprehensive Python utility for extracting and analyzing forensic artifacts
from web browsers including Firefox and Chromium-based browsers (Chrome, Edge,
Brave, Opera, Vivaldi).

Supports:
- Firefox: browsing history, cookies, passwords, form data, bookmarks
- Chromium: browsing history, cookies, passwords, autofill, bookmarks, downloads

Usage:
    python browser_forensics.py                    # Auto-detect browsers
    python browser_forensics.py --browser firefox  # Firefox only
    python browser_forensics.py --browser chrome   # Chrome only
    python browser_forensics.py /path/to/profile   # Specific profile path
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Import browser profile detection
from browser_profiles import (
    BrowserProfile,
    BrowserType,
    BrowserFamily,
    BrowserInstallation,
    detect_all_browsers,
    detect_browser_from_path,
    list_all_profiles,
)

# Import Chromium modules
from chromium_extractor import (
    ChromiumDatabaseExtractor,
    ChromiumJSONExtractor,
    extract_chromium_profile,
)
from chromium_decrypt import (
    decrypt_chromium_passwords,
    check_decryption_requirements,
    DecryptedCredential,
)

# Import Firefox modules (existing)
from extractor import FirefoxDatabaseExtractor, FirefoxJSONExtractor
from nss_decrypt import (
    decrypt_firefox_passwords,
    check_master_password_required,
    run_environment_check as firefox_env_check,
)
from utils import setup_logging


# =============================================================================
# ANSI Colors (reused from main.py)
# =============================================================================

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'


def colorize(text: str, color: str) -> str:
    """Apply color to text if terminal supports it."""
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.RESET}"
    return text


def safe_print(text: str):
    """Print text with fallback for encoding issues."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode('ascii', 'replace').decode('ascii'))


# =============================================================================
# UI Functions
# =============================================================================

def get_system_info() -> dict:
    """Get system/OS information."""
    import platform
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "hostname": platform.node(),
    }


def print_banner():
    """Print the tool banner."""
    banner = f"""
{colorize('=' * 72, Colors.CYAN)}
{colorize('  BROWSER FORENSICS EXTRACTION TOOL', Colors.BOLD + Colors.WHITE)}
{colorize('  Firefox | Chrome | Edge | Brave | Opera | Vivaldi', Colors.YELLOW)}
{colorize('=' * 72, Colors.CYAN)}
"""
    safe_print(banner)


def print_system_info():
    """Print detected system information."""
    info = get_system_info()
    print(f"\n{colorize('[*] System Detected:', Colors.CYAN)}")
    print(f"    {colorize('OS:', Colors.WHITE)} {info['os']} {info['os_release']}")
    print(f"    {colorize('Host:', Colors.WHITE)} {info['hostname']}")
    print(f"    {colorize('Arch:', Colors.WHITE)} {info['machine']}")


def print_detected_browsers_ui(installations: List[BrowserInstallation], filter_browser: Optional[str] = None):
    """Print detected browsers in a nice format.
    
    Args:
        installations: List of detected browser installations
        filter_browser: Optional browser type to filter (e.g., 'chrome', 'firefox')
    """
    # Filter installations if browser type specified
    if filter_browser and filter_browser != "auto":
        installations = [
            inst for inst in installations 
            if inst.browser_type.value.lower() == filter_browser.lower()
        ]
    
    if not installations:
        if filter_browser and filter_browser != "auto":
            print(f"\n{colorize(f'[!] No {filter_browser.upper()} browser detected on this system.', Colors.RED)}")
        else:
            print(f"\n{colorize('[!] No browsers detected on this system.', Colors.RED)}")
        return None
    
    # Count total profiles
    total_profiles = sum(len(inst.profiles) for inst in installations)
    print(f"\n{colorize('[+] Found', Colors.GREEN)} {colorize(str(len(installations)), Colors.YELLOW)} {colorize('browser(s) with', Colors.GREEN)} {colorize(str(total_profiles), Colors.YELLOW)} {colorize('profile(s)', Colors.GREEN)}")
    
    print(f"\n{colorize('Available Profiles:', Colors.CYAN)}")
    print(f"{colorize('─' * 50, Colors.CYAN)}")
    
    idx = 1
    profile_map = {}  # idx -> profile
    
    for installation in installations:
        browser_name = installation.browser_type.value.upper()
        family = "Gecko" if installation.browser_family == BrowserFamily.GECKO else "Chromium"
        
        print(f"\n  {colorize(browser_name, Colors.BOLD + Colors.WHITE)} ({family})")
        
        for profile in installation.profiles:
            default_marker = colorize(' (default)', Colors.GREEN) if profile.is_default else ''
            # Extract the actual profile name from display_name (format: "Browser - ProfileName")
            if " - " in profile.display_name:
                actual_name = profile.display_name.split(" - ", 1)[1]
            else:
                actual_name = profile.profile_name
            print(f"    {colorize(f'[{idx}]', Colors.YELLOW)} {actual_name}{default_marker}")
            profile_map[idx] = profile
            idx += 1
    
    print(f"\n  {colorize('[0]', Colors.RED)} Exit")
    return profile_map


def prompt_browser_selection(filter_browser: Optional[str] = None) -> Optional[BrowserProfile]:
    """Prompt user to select a browser profile.
    
    Shows system info, detects browsers, and lets user choose.
    
    Args:
        filter_browser: Optional browser type to filter (e.g., 'chrome', 'firefox')
    
    Returns:
        Selected BrowserProfile or None if cancelled
    """
    # First, show system info
    print_system_info()
    
    # Detect and show browsers
    print(f"\n{colorize('[*] Scanning for installed browsers...', Colors.CYAN)}")
    installations = detect_all_browsers()
    profile_map = print_detected_browsers_ui(installations, filter_browser)
    
    if not profile_map:
        return None
    
    # Find default profile
    default_idx = 1
    for idx, profile in profile_map.items():
        if profile.is_default:
            default_idx = idx
            break
    
    prompt = f"\n{colorize('?', Colors.GREEN)} Select browser profile [{default_idx}]: "
    
    while True:
        try:
            response = input(prompt).strip()
            
            if not response:
                return profile_map[default_idx]
            
            if response == '0':
                return None
            
            try:
                choice = int(response)
                if choice in profile_map:
                    selected = profile_map[choice]
                    print(f"  {colorize('[+]', Colors.GREEN)} Selected: {selected.display_name}")
                    return selected
                else:
                    print(f"  {colorize(f'Please enter a number between 1 and {len(profile_map)}, or 0 to exit', Colors.YELLOW)}")
            except ValueError:
                print(f"  {colorize('Please enter a valid number', Colors.YELLOW)}")
                
        except (KeyboardInterrupt, EOFError):
            print()
            return None


def print_credentials_chromium(credentials: List[DecryptedCredential]):
    """Print decrypted Chromium credentials."""
    if not credentials:
        print(f"\n{colorize('[*] No saved passwords found in this profile.', Colors.YELLOW)}")
        return
    
    print(f"\n{colorize('=' * 70, Colors.RED)}")
    print(f"{colorize('[!] DECRYPTED SAVED PASSWORDS', Colors.BOLD + Colors.RED)}")
    print(f"{colorize('=' * 70, Colors.RED)}")
    
    for i, cred in enumerate(credentials, 1):
        print(f"\n{colorize(f'[{i}]', Colors.YELLOW)} {colorize(cred.signon_realm, Colors.MAGENTA)}")
        print(f"    {colorize('URL:', Colors.CYAN)} {cred.url}")
        print(f"    {colorize('Username:', Colors.CYAN)} {colorize(cred.username, Colors.GREEN + Colors.BOLD)}")
        print(f"    {colorize('Password:', Colors.CYAN)} {colorize(cred.password, Colors.RED + Colors.BOLD)}")
        if cred.times_used:
            print(f"    {colorize('Times Used:', Colors.CYAN)} {cred.times_used}")
        if cred.date_last_used:
            print(f"    {colorize('Last Used:', Colors.CYAN)} {cred.date_last_used}")
    
    print(f"\n{colorize('═' * 70, Colors.RED)}")
    print(f"{colorize(f'Total: {len(credentials)} saved password(s) decrypted', Colors.BOLD + Colors.RED)}")
    print(f"{colorize('═' * 70, Colors.RED)}\n")


def print_goodbye():
    """Print goodbye message."""
    print(f"\n{colorize('=' * 70, Colors.CYAN)}")
    print(f"{colorize('Thank you for using Browser Forensics Tool!', Colors.BOLD + Colors.CYAN)}")
    print(f"{colorize('   Goodbye!', Colors.CYAN)}")
    print(f"{colorize('=' * 70, Colors.CYAN)}\n")


# =============================================================================
# Extraction Functions
# =============================================================================

def extract_chromium_forensics(
    profile: BrowserProfile,
    output_dir: Path,
    logger: logging.Logger,
    decrypt_passwords: bool = True,
) -> Tuple[bool, Dict]:
    """Extract forensic data from a Chromium-based browser.
    
    Args:
        profile: BrowserProfile to extract from
        output_dir: Output directory
        logger: Logger instance
        decrypt_passwords: Whether to attempt password decryption
    
    Returns:
        Tuple of (success, summary_dict)
    """
    summary = {
        "browser": profile.browser_type.value,
        "profile": profile.profile_name,
        "profile_path": str(profile.profile_path),
        "extraction_time": datetime.now(timezone.utc).isoformat(),
        "results": {},
        "credentials": [],
        "errors": [],
    }
    
    print(f"\n{colorize('[*] Extracting data from:', Colors.CYAN)} {profile.display_name}")
    print(f"    {colorize('Profile Path:', Colors.CYAN)} {profile.profile_path}")
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Extract database data
    print(f"\n{colorize('[+] Extracting SQLite databases...', Colors.GREEN)}")
    
    try:
        with ChromiumDatabaseExtractor(profile) as db_extractor:
            # Find databases
            databases = db_extractor.find_databases()
            print(f"    Found {len(databases)} database(s): {', '.join(databases)}")
            
            # Extract all forensic data
            db_results = db_extractor.extract_all_forensic_data(output_dir)
            
            for category, results in db_results.items():
                total_rows = sum(r.rows_extracted for r in results if r.success)
                if total_rows > 0:
                    print(f"    {colorize('✓', Colors.GREEN)} {category}: {total_rows} rows")
                    summary["results"][category] = {
                        "rows": total_rows,
                        "files": [str(r.output_path.name) for r in results if r.output_path]
                    }
    except Exception as e:
        logger.error(f"Database extraction failed: {e}")
        summary["errors"].append(f"Database extraction: {e}")
        print(f"    {colorize('✗', Colors.RED)} Database extraction failed: {e}")
    
    # Extract JSON data (bookmarks, extensions)
    print(f"\n{colorize('[+] Extracting JSON artifacts...', Colors.GREEN)}")
    
    try:
        json_extractor = ChromiumJSONExtractor(profile)
        
        # Bookmarks
        bookmarks_path = output_dir / "bookmarks.csv"
        if json_extractor.export_bookmarks_to_csv(bookmarks_path):
            bookmarks = json_extractor.flatten_bookmarks()
            print(f"    {colorize('✓', Colors.GREEN)} Bookmarks: {len(bookmarks)} entries")
            summary["results"]["Bookmarks"] = {"rows": len(bookmarks), "files": ["bookmarks.csv"]}
        
        # Extensions
        extensions_path = output_dir / "extensions.csv"
        if json_extractor.export_extensions_to_csv(extensions_path):
            extensions = json_extractor.get_extensions()
            print(f"    {colorize('✓', Colors.GREEN)} Extensions: {len(extensions)} installed")
            summary["results"]["Extensions"] = {"rows": len(extensions), "files": ["extensions.csv"]}
            
    except Exception as e:
        logger.error(f"JSON extraction failed: {e}")
        summary["errors"].append(f"JSON extraction: {e}")
    
    # Decrypt passwords
    if decrypt_passwords:
        print(f"\n{colorize('[+] Attempting password decryption...', Colors.YELLOW)}")
        
        try:
            credentials, pwd_errors = decrypt_chromium_passwords(
                profile.profile_path,
                profile.user_data_dir
            )
            
            if credentials:
                print(f"    {colorize('✓', Colors.GREEN)} Decrypted {len(credentials)} password(s)")
                summary["credentials"] = [
                    {
                        "url": c.url,
                        "username": c.username,
                        "password": c.password,
                        "realm": c.signon_realm,
                    }
                    for c in credentials
                ]
                
                # Print credentials
                print_credentials_chromium(credentials)
                
                # Save to file (sanitized)
                creds_path = output_dir / "decrypted_passwords.json"
                with open(creds_path, "w", encoding="utf-8") as f:
                    json.dump(summary["credentials"], f, indent=2)
                print(f"    {colorize('Saved to:', Colors.CYAN)} decrypted_passwords.json")
            
            if pwd_errors:
                for err in pwd_errors:
                    summary["errors"].append(f"Password decryption: {err}")
                    logger.warning(f"Password error: {err}")
                    
        except Exception as e:
            logger.error(f"Password decryption failed: {e}")
            summary["errors"].append(f"Password decryption: {e}")
            print(f"    {colorize('✗', Colors.RED)} Password decryption failed: {e}")
    
    # Save summary
    summary_path = output_dir / "extraction_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)
    
    # Print summary
    print(f"\n{colorize('=' * 60, Colors.CYAN)}")
    print(f"{colorize('EXTRACTION COMPLETE', Colors.BOLD + Colors.GREEN)}")
    print(f"{colorize('=' * 60, Colors.CYAN)}")
    print(f"\n{colorize('Output Directory:', Colors.CYAN)} {output_dir}")
    print(f"{colorize('Categories Extracted:', Colors.CYAN)} {len(summary['results'])}")
    total_rows = sum(r.get('rows', 0) for r in summary['results'].values())
    print(f"{colorize('Total Records:', Colors.CYAN)} {total_rows:,}")
    print(f"{colorize('Passwords Decrypted:', Colors.RED)} {len(summary.get('credentials', []))}")
    
    if summary["errors"]:
        print(f"\n{colorize('Warnings/Errors:', Colors.YELLOW)}")
        for err in summary["errors"][:5]:
            print(f"  - {err}")
    
    return True, summary


def extract_firefox_forensics(
    profile_path: Path,
    output_dir: Path,
    logger: logging.Logger,
) -> Tuple[bool, Dict]:
    """Extract forensic data from Firefox (wrapper around existing functionality).
    
    This calls the existing Firefox extraction in main.py.
    """
    # Import and call existing Firefox extraction
    from main import extract_profile_forensic
    
    success = extract_profile_forensic(
        profile_path,
        output_dir,
        logger,
        interactive=True,
        copy_artifacts=False,
        output_provided=False,
    )
    
    return success, {}


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "profile",
        nargs="?",
        help="Path to browser profile directory (auto-detects browser type)",
    )
    
    parser.add_argument(
        "--browser", "-b",
        choices=["firefox", "chrome", "chromium", "edge", "brave", "opera", "vivaldi", "auto"],
        default="auto",
        help="Browser to extract from (default: auto-detect)",
    )
    
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output directory (default: ~/Downloads/browser_forensics_output)",
    )
    
    parser.add_argument(
        "--no-passwords",
        action="store_true",
        help="Skip password decryption",
    )
    
    parser.add_argument(
        "--list-browsers",
        action="store_true",
        help="List all detected browsers and exit",
    )
    
    parser.add_argument(
        "--check-env",
        action="store_true",
        help="Check environment for decryption requirements",
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress non-critical output",
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING if args.quiet else logging.INFO
    logger = setup_logging(log_level)
    
    print_banner()
    
    # Handle --list-browsers
    if args.list_browsers:
        print_system_info()
        print(f"\n{colorize('[*] Scanning for installed browsers...', Colors.CYAN)}")
        installations = detect_all_browsers()
        browser_filter = args.browser if args.browser != "auto" else None
        print_detected_browsers_ui(installations, filter_browser=browser_filter)
        return 0
    
    # Handle --check-env
    if args.check_env:
        print(f"\n{colorize('Environment Check:', Colors.CYAN)}")
        
        # Check Chromium requirements
        print(f"\n{colorize('Chromium Browsers:', Colors.YELLOW)}")
        reqs_met, missing = check_decryption_requirements()
        if reqs_met:
            print(f"  {colorize('✓', Colors.GREEN)} All requirements met")
        else:
            print(f"  {colorize('✗', Colors.RED)} Missing: {', '.join(missing)}")
        
        # Check Firefox requirements
        print(f"\n{colorize('Firefox:', Colors.YELLOW)}")
        firefox_env_check(None)
        
        return 0
    
    # Determine profile to use
    profile: Optional[BrowserProfile] = None
    
    if args.profile:
        # User specified a path
        profile_path = Path(args.profile).expanduser().resolve()
        
        if not profile_path.exists():
            print(f"{colorize('[!] Profile path not found:', Colors.RED)} {profile_path}")
            return 1
        
        # Detect browser type from path
        detected = detect_browser_from_path(profile_path)
        if detected:
            browser_type, browser_family = detected
            
            # Create a BrowserProfile object
            profile = BrowserProfile(
                browser_type=browser_type,
                browser_family=browser_family,
                profile_name=profile_path.name,
                profile_path=profile_path,
                user_data_dir=profile_path.parent,
                is_default=False,
            )
            print(f"{colorize('[+] Detected browser:', Colors.GREEN)} {browser_type.value}")
        else:
            print(f"{colorize('[!] Could not detect browser type from path', Colors.RED)}")
            print(f"    Use --browser flag to specify browser type")
            return 1
    else:
        # Auto-detect and prompt for selection
        # Use browser filter if specified (not 'auto')
        browser_filter = args.browser if args.browser != "auto" else None
        profile = prompt_browser_selection(filter_browser=browser_filter)
        
        if profile is None:
            print_goodbye()
            return 0
    
    # Setup output directory
    if args.output:
        output_dir = Path(args.output)
    else:
        browser_name = profile.browser_type.value
        output_dir = Path.home() / "Downloads" / f"{browser_name}_forensics_output"
    
    # Run extraction based on browser family
    try:
        if profile.browser_family == BrowserFamily.CHROMIUM:
            success, summary = extract_chromium_forensics(
                profile,
                output_dir,
                logger,
                decrypt_passwords=not args.no_passwords,
            )
        else:  # Firefox
            success, summary = extract_firefox_forensics(
                profile.profile_path,
                output_dir,
                logger,
            )
        
        print_goodbye()
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print(f"\n{colorize('Extraction interrupted by user', Colors.YELLOW)}")
        print_goodbye()
        return 130
    except Exception as e:
        logger.exception(f"Extraction failed: {e}")
        print(f"\n{colorize(f'[!] Extraction failed: {e}', Colors.RED)}")
        print_goodbye()
        return 1


if __name__ == "__main__":
    sys.exit(main())
