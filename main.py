#!/usr/bin/env python3
"""Browser Forensics Extraction Tool.

A comprehensive Python utility for extracting and analyzing forensic artifacts
from web browsers including Firefox and Chromium-based browsers (Chrome, Edge,
Brave, Opera, Vivaldi). Results are exported in multiple formats (HTML, CSV, Markdown).

Usage:
    python main.py                              # Auto-detect all browsers
    python main.py -b firefox                   # Firefox only
    python main.py -b chrome                    # Chrome only  
    python main.py -b brave                     # Brave only
    python main.py /path/to/profile             # Specific profile path
    python main.py --list-browsers              # List all detected browsers
    python main.py --help

"""

import argparse
import logging
import sys
import os
import shutil
from datetime import datetime
from pathlib import Path

from extractor import (
    FirefoxDatabaseExtractor,
    FirefoxJSONExtractor,
    ForensicReportGenerator,
    ExtractionResult,
)
from queries import QUERY_REGISTRY
from utils import (
    setup_logging,
    create_output_directory,
    validate_profile_path,
    expand_firefox_path,
    get_profile_info,
    format_bytes,
    ProgressTracker,
    sanitize_filename,
)
from formatters import (
    ForensicData,
    ReportGenerator,
    extract_credentials_from_data,
)
from nss_decrypt import (
    decrypt_firefox_passwords,
    check_master_password_required,
    DecryptedLogin,
    MasterPasswordRequired,
    UnsupportedEnvironment,
    NSSLibraryMissing,
    OSKeyringLocked,
    run_environment_check,
    validate_environment,
)

# Import new forensic modules
from report_builder import ForensicReportBuilder, build_forensic_report
from report_generators import ReportOutputManager
from forensic_models import ProcessingStatus

# Import browser detection and Chromium support
from browser_profiles import (
    BrowserProfile,
    BrowserType,
    BrowserFamily,
    BrowserInstallation,
    detect_all_browsers,
    detect_browser_from_path,
)
from chromium_extractor import ChromiumDatabaseExtractor, ChromiumJSONExtractor
from chromium_decrypt import decrypt_chromium_passwords, check_decryption_requirements, DecryptedCredential



# ANSI color codes for terminal output
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
    """Print text with fallback for encoding issues on Windows."""
    try:
        print(text)
    except UnicodeEncodeError:
        # Fallback: replace problematic characters
        print(text.encode('ascii', 'replace').decode('ascii'))


def print_banner():
    """Print the tool banner."""
    banner = f"""
{colorize('=' * 72, Colors.CYAN)}
{colorize('  BROWSER FORENSICS EXTRACTION TOOL', Colors.BOLD + Colors.WHITE)}
{colorize('  Firefox | Chrome | Edge | Brave | Opera | Vivaldi', Colors.YELLOW)}
{colorize('=' * 72, Colors.CYAN)}
"""
    safe_print(banner)


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


def print_system_info():
    """Print detected system information."""
    info = get_system_info()
    print(f"\n{colorize('[*] System Detected:', Colors.CYAN)}")
    print(f"    {colorize('OS:', Colors.WHITE)} {info['os']} {info['os_release']}")
    print(f"    {colorize('Host:', Colors.WHITE)} {info['hostname']}")
    print(f"    {colorize('Arch:', Colors.WHITE)} {info['machine']}")


def print_detected_browsers_ui(installations: list, filter_browser: str = None):
    """Print detected browsers in a nice format.
    
    Args:
        installations: List of detected browser installations
        filter_browser: Optional browser type to filter (e.g., 'chrome', 'firefox')
    
    Returns:
        Dictionary mapping index to BrowserProfile, or None if no browsers found
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
            # Extract the actual profile name from display_name
            if " - " in profile.display_name:
                actual_name = profile.display_name.split(" - ", 1)[1]
            else:
                actual_name = profile.profile_name
            print(f"    {colorize(f'[{idx}]', Colors.YELLOW)} {actual_name}{default_marker}")
            profile_map[idx] = profile
            idx += 1
    
    print(f"\n  {colorize('[0]', Colors.RED)} Exit")
    return profile_map


def prompt_browser_selection(filter_browser: str = None) -> BrowserProfile:
    """Prompt user to select a browser profile (multi-browser support).
    
    Args:
        filter_browser: Optional browser type to filter
    
    Returns:
        Selected BrowserProfile or None if cancelled
    """
    # Show system info
    print_system_info()
    
    # Detect browsers
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


def print_credentials_chromium(credentials: list):
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


# =============================================================================
# Terminal Print Functions for Specific Data Categories
# =============================================================================

def print_history_terminal(rows: list, limit: int = 50):
    """Print browsing history to terminal."""
    if not rows:
        print(f"\n{colorize('[*] No browsing history found.', Colors.YELLOW)}")
        return
    
    print(f"\n{colorize('=' * 80, Colors.CYAN)}")
    print(f"{colorize('[BROWSING HISTORY]', Colors.BOLD + Colors.CYAN)} ({len(rows)} entries, showing {min(limit, len(rows))})")
    print(f"{colorize('=' * 80, Colors.CYAN)}")
    
    for i, row in enumerate(rows[:limit], 1):
        url = row.get('url', row.get('URL', 'N/A'))
        title = row.get('title', row.get('Title', 'N/A'))
        visit_time = row.get('visit_time', row.get('last_visit_time', row.get('Visit Time', 'N/A')))
        visit_count = row.get('visit_count', row.get('Visit Count', ''))
        
        # Truncate long URLs and titles
        if len(str(url)) > 70:
            url = str(url)[:67] + "..."
        if len(str(title)) > 50:
            title = str(title)[:47] + "..."
        
        print(f"\n{colorize(f'[{i}]', Colors.YELLOW)} {colorize(str(title), Colors.WHITE)}")
        print(f"    {colorize('URL:', Colors.CYAN)} {url}")
        print(f"    {colorize('Time:', Colors.CYAN)} {visit_time}", end="")
        if visit_count:
            print(f"  |  {colorize('Visits:', Colors.CYAN)} {visit_count}")
        else:
            print()
    
    if len(rows) > limit:
        print(f"\n{colorize(f'... and {len(rows) - limit} more entries', Colors.YELLOW)}")
    
    print(f"\n{colorize('─' * 80, Colors.CYAN)}")
    print(f"{colorize(f'Total: {len(rows)} history entries', Colors.BOLD + Colors.CYAN)}")


def print_cookies_terminal(rows: list, limit: int = 50):
    """Print cookies to terminal."""
    if not rows:
        print(f"\n{colorize('[*] No cookies found.', Colors.YELLOW)}")
        return
    
    print(f"\n{colorize('=' * 80, Colors.MAGENTA)}")
    print(f"{colorize('[COOKIES]', Colors.BOLD + Colors.MAGENTA)} ({len(rows)} entries, showing {min(limit, len(rows))})")
    print(f"{colorize('=' * 80, Colors.MAGENTA)}")
    
    for i, row in enumerate(rows[:limit], 1):
        host = row.get('host', row.get('host_key', row.get('Host', 'N/A')))
        name = row.get('name', row.get('Name', 'N/A'))
        value = row.get('value', row.get('Value', ''))
        expiry = row.get('expiry', row.get('expires_utc', row.get('Expiry', 'N/A')))
        
        # Truncate long values
        if len(str(value)) > 40:
            value = str(value)[:37] + "..."
        
        print(f"\n{colorize(f'[{i}]', Colors.YELLOW)} {colorize(str(host), Colors.WHITE)}")
        print(f"    {colorize('Name:', Colors.CYAN)} {name}")
        print(f"    {colorize('Value:', Colors.CYAN)} {colorize(str(value), Colors.GREEN)}")
        print(f"    {colorize('Expires:', Colors.CYAN)} {expiry}")
    
    if len(rows) > limit:
        print(f"\n{colorize(f'... and {len(rows) - limit} more cookies', Colors.YELLOW)}")
    
    print(f"\n{colorize('─' * 80, Colors.MAGENTA)}")
    print(f"{colorize(f'Total: {len(rows)} cookies', Colors.BOLD + Colors.MAGENTA)}")


def print_downloads_terminal(rows: list, limit: int = 30):
    """Print downloads to terminal."""
    if not rows:
        print(f"\n{colorize('[*] No downloads found.', Colors.YELLOW)}")
        return
    
    print(f"\n{colorize('=' * 80, Colors.GREEN)}")
    print(f"{colorize('[DOWNLOADS]', Colors.BOLD + Colors.GREEN)} ({len(rows)} entries)")
    print(f"{colorize('=' * 80, Colors.GREEN)}")
    
    for i, row in enumerate(rows[:limit], 1):
        url = row.get('url', row.get('tab_url', row.get('URL', 'N/A')))
        target = row.get('target', row.get('target_path', row.get('Target', 'N/A')))
        start_time = row.get('start_time', row.get('Start Time', 'N/A'))
        total_bytes = row.get('total_bytes', row.get('Total Bytes', ''))
        
        # Get filename from target path
        if target and target != 'N/A':
            filename = Path(str(target)).name
        else:
            filename = "Unknown"
        
        if len(str(url)) > 60:
            url = str(url)[:57] + "..."
        
        print(f"\n{colorize(f'[{i}]', Colors.YELLOW)} {colorize(filename, Colors.WHITE)}")
        print(f"    {colorize('URL:', Colors.CYAN)} {url}")
        print(f"    {colorize('Path:', Colors.CYAN)} {target}")
        print(f"    {colorize('Time:', Colors.CYAN)} {start_time}", end="")
        if total_bytes:
            size_mb = int(total_bytes) / (1024 * 1024) if str(total_bytes).isdigit() else 0
            print(f"  |  {colorize('Size:', Colors.CYAN)} {size_mb:.2f} MB")
        else:
            print()
    
    if len(rows) > limit:
        print(f"\n{colorize(f'... and {len(rows) - limit} more downloads', Colors.YELLOW)}")
    
    print(f"\n{colorize('─' * 80, Colors.GREEN)}")
    print(f"{colorize(f'Total: {len(rows)} downloads', Colors.BOLD + Colors.GREEN)}")


def print_bookmarks_terminal(rows: list, limit: int = 50):
    """Print bookmarks to terminal."""
    if not rows:
        print(f"\n{colorize('[*] No bookmarks found.', Colors.YELLOW)}")
        return
    
    print(f"\n{colorize('=' * 80, Colors.BLUE)}")
    print(f"{colorize('[BOOKMARKS]', Colors.BOLD + Colors.BLUE)} ({len(rows)} entries)")
    print(f"{colorize('=' * 80, Colors.BLUE)}")
    
    for i, row in enumerate(rows[:limit], 1):
        title = row.get('title', row.get('Title', row.get('name', 'N/A')))
        url = row.get('url', row.get('URL', 'N/A'))
        folder = row.get('folder', row.get('parent_title', row.get('Folder', '')))
        date_added = row.get('date_added', row.get('dateAdded', row.get('Date Added', '')))
        
        if len(str(title)) > 50:
            title = str(title)[:47] + "..."
        if len(str(url)) > 60:
            url = str(url)[:57] + "..."
        
        print(f"\n{colorize(f'[{i}]', Colors.YELLOW)} {colorize(str(title), Colors.WHITE)}")
        print(f"    {colorize('URL:', Colors.CYAN)} {url}")
        if folder:
            print(f"    {colorize('Folder:', Colors.CYAN)} {folder}")
        if date_added:
            print(f"    {colorize('Added:', Colors.CYAN)} {date_added}")
    
    if len(rows) > limit:
        print(f"\n{colorize(f'... and {len(rows) - limit} more bookmarks', Colors.YELLOW)}")
    
    print(f"\n{colorize('─' * 80, Colors.BLUE)}")
    print(f"{colorize(f'Total: {len(rows)} bookmarks', Colors.BOLD + Colors.BLUE)}")


def print_autofill_terminal(rows: list, limit: int = 50):
    """Print autofill/form data to terminal."""
    if not rows:
        print(f"\n{colorize('[*] No autofill/form data found.', Colors.YELLOW)}")
        return
    
    print(f"\n{colorize('=' * 80, Colors.YELLOW)}")
    print(f"{colorize('[AUTOFILL / FORM DATA]', Colors.BOLD + Colors.YELLOW)} ({len(rows)} entries)")
    print(f"{colorize('=' * 80, Colors.YELLOW)}")
    
    for i, row in enumerate(rows[:limit], 1):
        field = row.get('name', row.get('fieldname', row.get('Field', 'N/A')))
        value = row.get('value', row.get('Value', 'N/A'))
        use_count = row.get('count', row.get('use_count', row.get('timesUsed', '')))
        
        # Highlight sensitive fields
        sensitive = any(kw in str(field).lower() for kw in ['email', 'phone', 'address', 'card', 'password', 'ssn', 'name'])
        field_color = Colors.RED if sensitive else Colors.WHITE
        
        if len(str(value)) > 50:
            value = str(value)[:47] + "..."
        
        print(f"\n{colorize(f'[{i}]', Colors.YELLOW)} {colorize(str(field), field_color)}")
        print(f"    {colorize('Value:', Colors.CYAN)} {colorize(str(value), Colors.GREEN)}")
        if use_count:
            print(f"    {colorize('Used:', Colors.CYAN)} {use_count} times")
    
    if len(rows) > limit:
        print(f"\n{colorize(f'... and {len(rows) - limit} more entries', Colors.YELLOW)}")
    
    print(f"\n{colorize('─' * 80, Colors.YELLOW)}")
    print(f"{colorize(f'Total: {len(rows)} autofill entries', Colors.BOLD + Colors.YELLOW)}")


def print_extensions_terminal(rows: list):
    """Print extensions to terminal."""
    if not rows:
        print(f"\n{colorize('[*] No extensions found.', Colors.YELLOW)}")
        return
    
    print(f"\n{colorize('=' * 80, Colors.MAGENTA)}")
    print(f"{colorize('[EXTENSIONS]', Colors.BOLD + Colors.MAGENTA)} ({len(rows)} installed)")
    print(f"{colorize('=' * 80, Colors.MAGENTA)}")
    
    for i, row in enumerate(rows, 1):
        name = row.get('name', row.get('Name', 'N/A'))
        version = row.get('version', row.get('Version', ''))
        enabled = row.get('enabled', row.get('Enabled', True))
        description = row.get('description', row.get('Description', ''))
        
        status = colorize('✓ Enabled', Colors.GREEN) if enabled else colorize('✗ Disabled', Colors.RED)
        
        if len(str(description)) > 60:
            description = str(description)[:57] + "..."
        
        print(f"\n{colorize(f'[{i}]', Colors.YELLOW)} {colorize(str(name), Colors.WHITE)} {colorize(f'v{version}', Colors.CYAN) if version else ''}")
        print(f"    {colorize('Status:', Colors.CYAN)} {status}")
        if description:
            print(f"    {colorize('Description:', Colors.CYAN)} {description}")
    
    print(f"\n{colorize('─' * 80, Colors.MAGENTA)}")
    print(f"{colorize(f'Total: {len(rows)} extensions', Colors.BOLD + Colors.MAGENTA)}")


def print_search_queries_terminal(rows: list, limit: int = 50):
    """Print search queries to terminal."""
    if not rows:
        print(f"\n{colorize('[*] No search queries found.', Colors.YELLOW)}")
        return
    
    print(f"\n{colorize('=' * 80, Colors.CYAN)}")
    print(f"{colorize('[SEARCH QUERIES]', Colors.BOLD + Colors.CYAN)} ({len(rows)} entries)")
    print(f"{colorize('=' * 80, Colors.CYAN)}")
    
    for i, row in enumerate(rows[:limit], 1):
        query = row.get('query', row.get('term', row.get('search_term', row.get('Query', 'N/A'))))
        search_time = row.get('time', row.get('search_time', row.get('Time', '')))
        
        print(f"  {colorize(f'[{i}]', Colors.YELLOW)} {colorize(str(query), Colors.WHITE)}")
        if search_time:
            print(f"      {colorize('Time:', Colors.CYAN)} {search_time}")
    
    if len(rows) > limit:
        print(f"\n{colorize(f'... and {len(rows) - limit} more queries', Colors.YELLOW)}")
    
    print(f"\n{colorize('─' * 80, Colors.CYAN)}")
    print(f"{colorize(f'Total: {len(rows)} search queries', Colors.BOLD + Colors.CYAN)}")


def print_permissions_terminal(rows: list):
    """Print site permissions to terminal."""
    if not rows:
        print(f"\n{colorize('[*] No permissions found.', Colors.YELLOW)}")
        return
    
    print(f"\n{colorize('=' * 80, Colors.RED)}")
    print(f"{colorize('[SITE PERMISSIONS]', Colors.BOLD + Colors.RED)} ({len(rows)} entries)")
    print(f"{colorize('=' * 80, Colors.RED)}")
    
    for i, row in enumerate(rows, 1):
        origin = row.get('origin', row.get('host', row.get('Origin', 'N/A')))
        permission = row.get('type', row.get('permission', row.get('Permission', 'N/A')))
        setting = row.get('permission', row.get('setting', row.get('Setting', '')))
        
        # Color code permissions
        perm_color = Colors.RED if any(p in str(permission).lower() for p in ['camera', 'microphone', 'location', 'notification']) else Colors.WHITE
        
        print(f"\n{colorize(f'[{i}]', Colors.YELLOW)} {colorize(str(origin), Colors.WHITE)}")
        print(f"    {colorize('Permission:', Colors.CYAN)} {colorize(str(permission), perm_color)}")
        if setting:
            print(f"    {colorize('Setting:', Colors.CYAN)} {setting}")
    
    print(f"\n{colorize('─' * 80, Colors.RED)}")
    print(f"{colorize(f'Total: {len(rows)} permissions', Colors.BOLD + Colors.RED)}")


def print_extracted_data_terminal(data: dict, categories: list):
    """Print extracted data to terminal based on selected categories.
    
    Args:
        data: Dictionary of extracted data by category
        categories: List of categories to print (or ['all'] for everything)
    """
    extract_all = 'all' in categories
    
    # Map category names to print functions and data keys
    category_handlers = {
        'history': (print_history_terminal, ['History', 'browsing_history', 'recent_24h']),
        'cookies': (print_cookies_terminal, ['Cookies', 'all_cookies', 'cookies_by_domain']),
        'downloads': (print_downloads_terminal, ['Downloads', 'all_downloads', 'downloads']),
        'bookmarks': (print_bookmarks_terminal, ['Bookmarks', 'bookmarks']),
        'autofill': (print_autofill_terminal, ['Autofill', 'all_autofill', 'all_form_history', 'formhistory']),
        'forms': (print_autofill_terminal, ['Forms', 'all_form_history', 'formhistory']),
        'extensions': (print_extensions_terminal, ['Extensions', 'extensions']),
        'search': (print_search_queries_terminal, ['SearchQueries', 'search_queries']),
        'permissions': (print_permissions_terminal, ['Permissions', 'all_permissions', 'granted_permissions']),
    }
    
    printed_any = False
    
    for cat_name, (print_func, data_keys) in category_handlers.items():
        if extract_all or cat_name in categories:
            # Find matching data
            for key in data_keys:
                if key in data:
                    rows = data[key]
                    if isinstance(rows, dict):
                        # Nested structure - flatten
                        for sub_key, sub_rows in rows.items():
                            if isinstance(sub_rows, list) and sub_rows:
                                print_func(sub_rows)
                                printed_any = True
                                break
                    elif isinstance(rows, list) and rows:
                        print_func(rows)
                        printed_any = True
                        break
    
    if not printed_any:
        print(f"\n{colorize('[*] No data found for selected categories.', Colors.YELLOW)}")


def print_credentials_summary(credentials: list):
    """Print highlighted credentials to terminal."""
    if not credentials:
        print(f"\n{colorize('[*] No credentials found in this profile.', Colors.YELLOW)}")
        return
    
    print(f"\n{colorize('=' * 70, Colors.RED)}")
    print(f"{colorize('[!] CREDENTIALS & SENSITIVE DATA FOUND', Colors.BOLD + Colors.RED)}")
    print(f"{colorize('=' * 70, Colors.RED)}")
    
    for i, cred in enumerate(credentials, 1):
        print(f"\n{colorize(f'[{i}]', Colors.YELLOW)} {colorize(cred.get('type', 'Unknown'), Colors.MAGENTA)}")
        print(f"    {colorize('Source:', Colors.CYAN)} {cred.get('source', 'Unknown')}")
        print(f"    {colorize('Field:', Colors.CYAN)} {colorize(cred.get('field', 'Unknown'), Colors.YELLOW)}")
        print(f"    {colorize('Value:', Colors.CYAN)} {colorize(str(cred.get('value', '')), Colors.GREEN + Colors.BOLD)}")
        
        extra = cred.get('extra', {})
        if extra:
            for k, v in extra.items():
                print(f"    {colorize(f'{k}:', Colors.CYAN)} {v}")
    
    print(f"\n{colorize('═' * 70, Colors.RED)}")
    print(f"{colorize(f'Total: {len(credentials)} credential(s) found', Colors.BOLD + Colors.RED)}")
    print(f"{colorize('═' * 70, Colors.RED)}\n")


def print_decrypted_passwords(passwords: list):
    """Print decrypted Firefox passwords to terminal."""
    if not passwords:
        print(f"\n{colorize('[*] No saved passwords found in this profile.', Colors.YELLOW)}")
        return
    
    print(f"\n{colorize('=' * 70, Colors.RED)}")
    print(f"{colorize('[!] DECRYPTED SAVED PASSWORDS', Colors.BOLD + Colors.RED)}")
    print(f"{colorize('=' * 70, Colors.RED)}")
    
    for i, pwd in enumerate(passwords, 1):
        print(f"\n{colorize(f'[{i}]', Colors.YELLOW)} {colorize(pwd.hostname, Colors.MAGENTA)}")
        print(f"    {colorize('Username:', Colors.CYAN)} {colorize(pwd.username, Colors.GREEN + Colors.BOLD)}")
        print(f"    {colorize('Password:', Colors.CYAN)} {colorize(pwd.password, Colors.RED + Colors.BOLD)}")
        if pwd.times_used:
            print(f"    {colorize('Times Used:', Colors.CYAN)} {pwd.times_used}")
        if pwd.form_submit_url:
            print(f"    {colorize('Submit URL:', Colors.CYAN)} {pwd.form_submit_url}")
    
    print(f"\n{colorize('═' * 70, Colors.RED)}")
    print(f"{colorize(f'Total: {len(passwords)} saved password(s) decrypted', Colors.BOLD + Colors.RED)}")
    print(f"{colorize('═' * 70, Colors.RED)}\n")


def prompt_master_password() -> str:
    """Prompt user for Firefox master password."""
    import getpass
    print(f"\n{colorize('[*] This profile has a master password set.', Colors.YELLOW)}")
    try:
        password = getpass.getpass(f"{colorize('?', Colors.GREEN)} Enter master password: ")
        return password
    except (KeyboardInterrupt, EOFError):
        print()
        return ""


def print_goodbye():
    """Print goodbye message."""
    print(f"\n{colorize('=' * 70, Colors.CYAN)}")
    print(f"{colorize('Thank you for using Browser Forensics Tool!', Colors.BOLD + Colors.CYAN)}")
    print(f"{colorize('   Goodbye!', Colors.CYAN)}")
    print(f"{colorize('=' * 70, Colors.CYAN)}\n")


def prompt_yes_no(question: str, default: bool = True) -> bool:
    """Prompt user for yes/no answer."""
    default_str = "Y/n" if default else "y/N"
    prompt = f"{colorize('?', Colors.GREEN)} {question} [{default_str}]: "
    
    while True:
        try:
            response = input(prompt).strip().lower()
            if not response:
                return default
            if response in ['y', 'yes']:
                return True
            if response in ['n', 'no']:
                return False
            print(f"  {colorize('Please enter y or n', Colors.YELLOW)}")
        except (KeyboardInterrupt, EOFError):
            print()
            return False


def prompt_output_exists(output_dir: Path) -> str:
    """Prompt user when output directory already has forensic files.
    
    Args:
        output_dir: Path to output directory
    
    Returns:
        'overwrite' to overwrite existing files
        'increment' to create incremental output directory
        'cancel' to cancel operation
        None if no existing files found
    """
    # Check for existing forensic output files
    existing_files = []
    check_patterns = ['forensics_report.*', 'report.html', 'report.json', 'summary.txt', 'master_report.md']
    
    for pattern in check_patterns:
        existing_files.extend(list(output_dir.glob(pattern)))
    
    if not existing_files:
        return None  # No existing files, proceed normally
    
    print(f"\n{colorize('[!] Output directory contains existing forensic files:', Colors.YELLOW)}")
    for f in existing_files[:5]:  # Show max 5 files
        print(f"    - {f.name}")
    if len(existing_files) > 5:
        print(f"    ... and {len(existing_files) - 5} more")
    
    print(f"\n{colorize('Choose an option:', Colors.CYAN)}")
    print(f"  {colorize('[1]', Colors.YELLOW)} Overwrite existing files")
    print(f"  {colorize('[2]', Colors.YELLOW)} Create new incremental directory (e.g., output_2, output_3)")
    print(f"  {colorize('[0]', Colors.RED)} Cancel operation")
    
    prompt = f"{colorize('?', Colors.GREEN)} Select option [1]: "
    
    while True:
        try:
            response = input(prompt).strip()
            
            if not response or response == '1':
                confirm = prompt_yes_no("Are you sure you want to overwrite existing files?", default=False)
                if confirm:
                    return 'overwrite'
                continue
            
            if response == '2':
                return 'increment'
            
            if response == '0':
                return 'cancel'
            
            print(f"  {colorize('Please enter 1, 2, or 0', Colors.YELLOW)}")
            
        except (KeyboardInterrupt, EOFError):
            print()
            return 'cancel'


def get_incremental_output_dir(base_dir: Path) -> Path:
    """Generate an incremental output directory name.
    
    Args:
        base_dir: Base directory path
    
    Returns:
        New path with incremental suffix (e.g., output_2, output_3)
    """
    base_name = base_dir.name
    parent = base_dir.parent
    
    # Check if name already has a numeric suffix
    import re
    match = re.match(r'^(.+)_(\d+)$', base_name)
    if match:
        base_name = match.group(1)
        start_num = int(match.group(2)) + 1
    else:
        start_num = 2
    
    # Find next available number
    counter = start_num
    while True:
        new_dir = parent / f"{base_name}_{counter}"
        if not new_dir.exists():
            return new_dir
        counter += 1
        if counter > 1000:  # Safety limit
            raise ValueError("Could not find available directory name")


def prompt_path(question: str, default: str = None) -> Path:
    """Prompt user for a directory path.
    
    Returns:
        Path object or None if user wants to exit (entered 0).
    """
    default_display = f" [{default}]" if default else ""
    prompt = f"{colorize('?', Colors.GREEN)} {question}{default_display} (enter {colorize('0', Colors.YELLOW)} to exit): "
    
    while True:
        try:
            response = input(prompt).strip()
            
            # Check for exit
            if response == '0':
                return None
            
            if not response and default:
                response = default
            
            if not response:
                print(f"  {colorize('Please enter a path or 0 to exit', Colors.YELLOW)}")
                continue
            
            # Expand ~ and environment variables
            expanded = os.path.expanduser(os.path.expandvars(response))
            path = Path(expanded)
            
            # Check if directory exists
            if path.exists():
                if path.is_dir():
                    return path
                else:
                    print(f"  {colorize(f'{path} exists but is not a directory', Colors.RED)}")
                    continue
            
            # Directory doesn't exist - ask permission to create
            print(f"  {colorize(f'Directory does not exist:', Colors.YELLOW)} {path}")
            create = prompt_yes_no(f"Create directory '{path}'?")
            
            if create:
                try:
                    path.mkdir(parents=True, exist_ok=True)
                    print(f"  {colorize('[+]', Colors.GREEN)} Directory created: {path}")
                    return path
                except Exception as e:
                    print(f"  {colorize(f'Cannot create directory: {e}', Colors.RED)}")
                    # Ask for another path
                    continue
            else:
                # User doesn't want to create - ask for another path
                print(f"  {colorize('Please enter a different path or 0 to exit', Colors.YELLOW)}")
                continue
                
        except (KeyboardInterrupt, EOFError):
            print()
            return None


def get_firefox_profiles() -> list:
    """Read Firefox profiles.ini and return list of profiles.
    
    Works on both Windows and Linux.
    
    Returns:
        List of dicts with profile info: {'name': str, 'path': str, 'is_default': bool, 'full_path': Path}
    """
    import configparser
    
    # Determine Firefox directory based on platform
    if sys.platform == 'win32':
        appdata = os.environ.get('APPDATA', '')
        if appdata:
            firefox_dir = Path(appdata) / "Mozilla" / "Firefox"
        else:
            firefox_dir = Path.home() / "AppData" / "Roaming" / "Mozilla" / "Firefox"
    else:
        firefox_dir = Path.home() / ".mozilla" / "firefox"
    
    profiles_ini = firefox_dir / "profiles.ini"
    
    if not profiles_ini.exists():
        return []
    
    profiles = []
    default_path = None
    
    try:
        config = configparser.ConfigParser()
        config.read(profiles_ini)
        
        # First pass: find the default path from Install sections
        for section in config.sections():
            if section.startswith('Install'):
                if config.has_option(section, 'Default'):
                    default_path = config.get(section, 'Default')
                    break
        
        # Second pass: collect all profiles
        for section in config.sections():
            if section.startswith('Profile'):
                name = config.get(section, 'Name', fallback='Unknown')
                path = config.get(section, 'Path', fallback='')
                is_relative = config.getboolean(section, 'IsRelative', fallback=True)
                
                if is_relative:
                    full_path = firefox_dir / path
                else:
                    full_path = Path(path)
                
                # Check if this is the default profile
                is_default = (path == default_path) if default_path else False
                
                if full_path.exists():
                    profiles.append({
                        'name': name,
                        'path': path,
                        'is_default': is_default,
                        'full_path': full_path
                    })
    except Exception:
        return []
    
    return profiles


def prompt_profile_selection() -> Path:
    """Prompt user to select a Firefox profile.
    
    Returns:
        Path to selected profile or None if cancelled.
    """
    profiles = get_firefox_profiles()
    
    if not profiles:
        if sys.platform == 'win32':
            print(f"{colorize('No Firefox profiles found in %APPDATA%\\Mozilla\\Firefox\\', Colors.RED)}")
        else:
            print(f"{colorize('No Firefox profiles found in ~/.mozilla/firefox/', Colors.RED)}")
        return None
    
    print(f"\n{colorize('Available Firefox Profiles:', Colors.CYAN)}")
    print(f"{colorize('─' * 50, Colors.CYAN)}")
    
    for i, profile in enumerate(profiles, 1):
        default_marker = colorize(' (default)', Colors.GREEN + Colors.BOLD) if profile['is_default'] else ''
        print(f"  {colorize(f'[{i}]', Colors.YELLOW)} {profile['name']}{default_marker}")
        print(f"      {colorize('Path:', Colors.CYAN)} {profile['path']}")
    
    print(f"  {colorize('[0]', Colors.RED)} Exit")
    print()
    
    # Find default profile index
    default_idx = next((i for i, p in enumerate(profiles, 1) if p['is_default']), 1)
    
    prompt = f"{colorize('?', Colors.GREEN)} Select profile [{default_idx}]: "
    
    while True:
        try:
            response = input(prompt).strip()
            
            if not response:
                # Use default
                return profiles[default_idx - 1]['full_path']
            
            if response == '0':
                return None
            
            try:
                choice = int(response)
                if 1 <= choice <= len(profiles):
                    selected = profiles[choice - 1]
                    print(f"  {colorize('[+]', Colors.GREEN)} Selected: {selected['name']}")
                    return selected['full_path']
                else:
                    print(f"  {colorize(f'Please enter a number between 1 and {len(profiles)}, or 0 to exit', Colors.YELLOW)}")
            except ValueError:
                print(f"  {colorize('Please enter a valid number', Colors.YELLOW)}")
                
        except (KeyboardInterrupt, EOFError):
            print()
            return None


def prompt_formats() -> list:
    """Prompt user for output formats."""
    print(f"\n{colorize('Select output formats:', Colors.CYAN)}")
    print(f"  {colorize('[1]', Colors.YELLOW)} HTML  - Interactive web report with styling")
    print(f"  {colorize('[2]', Colors.YELLOW)} CSV   - Spreadsheet-compatible data files")
    print(f"  {colorize('[3]', Colors.YELLOW)} MD    - Markdown documentation")
    print(f"  {colorize('[A]', Colors.GREEN)} All formats (recommended)")
    
    prompt = f"{colorize('?', Colors.GREEN)} Enter choices (e.g., 1,2,3 or A) [A]: "
    
    while True:
        try:
            response = input(prompt).strip().upper()
            if not response or response == 'A':
                return ['html', 'csv', 'md']
            
            formats = []
            for choice in response.replace(' ', '').split(','):
                if choice == '1':
                    formats.append('html')
                elif choice == '2':
                    formats.append('csv')
                elif choice == '3':
                    formats.append('md')
                elif choice == 'A':
                    return ['html', 'csv', 'md']
            
            if formats:
                return list(set(formats))  # Remove duplicates
            
            print(f"  {colorize('Invalid choice. Enter 1, 2, 3, or A', Colors.YELLOW)}")
            
        except (KeyboardInterrupt, EOFError):
            print()
            return ['html', 'csv', 'md']


def extract_databases(
    extractor: FirefoxDatabaseExtractor,
    output_dir: Path,
    logger: logging.Logger,
) -> tuple:
    """Extract all SQLite databases from profile.
    
    Returns:
        Tuple of (results list, queries dict)
    """
    results = []
    all_queries = {}    # {query_name: [rows]} - Only store query results, not raw tables
    
    db_paths = extractor.find_databases()
    total_tables = 0
    total_rows = 0

    logger.info(f"Found {len(db_paths)} SQLite databases")

    for db_path in db_paths:
        db_name = db_path.stem
        logger.info(f"Processing {db_path.name}...")

        # Get tables
        tables = extractor.get_tables(db_path)
        logger.info(f"  Found {len(tables)} tables")
        total_tables += len(tables)

        # Run forensic queries for this database (this is what we really need)
        query_results = {}
        if db_path.name in QUERY_REGISTRY:
            queries = QUERY_REGISTRY[db_path.name]
            for query_name, query_sql in queries.items():
                try:
                    rows, row_count = extractor.run_forensic_query(db_path, query_sql)
                    if rows:
                        all_queries[query_name] = rows
                        query_results[query_name] = row_count
                        total_rows += row_count
                        logger.debug(f"    Query '{query_name}': {row_count} rows")
                except Exception as e:
                    logger.error(f"    Error executing query '{query_name}': {e}")

        results.append(
            ExtractionResult(
                success=True,
                database=db_path.name,
                rows_extracted=sum(query_results.values()) if query_results else 0,
                output_path=output_dir,
            )
        )

    return results, all_queries, total_tables, total_rows


def extract_json_artifacts(
    extractor: FirefoxDatabaseExtractor,
    output_dir: Path,
    logger: logging.Logger,
) -> dict:
    """Extract and process JSON files from profile.
    
    Returns:
        Dictionary of JSON data.
    """
    json_data = {}
    json_paths = extractor.find_json_files()

    if not json_paths:
        logger.info("No JSON files found in profile")
        return json_data

    logger.info(f"Found {len(json_paths)} JSON files")
    artifacts_dir = output_dir / "artifacts"
    artifacts_dir.mkdir(exist_ok=True)

    for json_path in json_paths:
        logger.info(f"Processing {json_path.name}...")

        # Parse JSON based on filename
        if json_path.name in ["extensions.json", "addons.json"]:
            summary = FirefoxJSONExtractor.parse_extensions(json_path)
        elif json_path.name == "search.json":
            summary = FirefoxJSONExtractor.parse_search_engines(json_path)
        else:
            summary = FirefoxJSONExtractor.parse_json_file(json_path)

        json_data[json_path.name] = summary

        # Save processed JSON
        output_path = artifacts_dir / json_path.name
        FirefoxJSONExtractor.save_json_report(summary, output_path)
        logger.debug(f"  Saved processed JSON to {output_path.name}")

    return json_data


def extract_profile(
    profile_path: Path,
    output_dir: Path,
    logger: logging.Logger,
    formats: list = None,
    interactive: bool = True,
    format_provided: bool = False,
    output_provided: bool = False,
) -> bool:
    """Main orchestration function for profile extraction.
    
    Args:
        profile_path: Path to Firefox profile.
        output_dir: Output directory path.
        logger: Logger instance.
        formats: List of output formats ['html', 'csv', 'md']
        interactive: Whether to prompt for user input.
        format_provided: Whether -f flag was provided (skip format prompt).
        output_provided: Whether -o flag was provided (skip output prompt).
    
    Returns:
        True if extraction completed successfully.
    """
    if formats is None:
        formats = ['html', 'csv', 'md']
    
    print_banner()

    # Validate profile
    logger.info(f"Validating profile at {profile_path}...")
    if not validate_profile_path(profile_path):
        logger.error(f"Invalid Firefox profile: {profile_path}")
        return False

    # Get profile info
    profile_info = get_profile_info(profile_path)
    
    print(f"{colorize('Profile:', Colors.CYAN)} {profile_info['name']}")
    print(f"{colorize('Path:', Colors.CYAN)} {profile_path}")
    print(f"{colorize('Size:', Colors.CYAN)} {profile_info.get('total_size_formatted', 'unknown')}")
    print(f"{colorize('Files:', Colors.CYAN)} {profile_info.get('file_count', 'unknown')}")
    print()

    # Interactive prompts
    if interactive:
        # Only prompt for formats if -f flag was not provided
        if not format_provided:
            formats = prompt_formats()
        
        # Always save to disk, but ask for path if -o was not provided
        if not output_provided:
            output_dir = prompt_path(
                "Enter output directory",
                default=str(output_dir)
            )
            if output_dir is None:
                # User entered 0 to exit
                print_goodbye()
                return False

    # Convert to Path object
    output_dir = Path(output_dir) if not isinstance(output_dir, Path) else output_dir
    
    # Check for existing output files if directory exists
    if interactive and output_dir.exists():
        action = prompt_output_exists(output_dir)
        
        if action == 'cancel':
            print(f"\n{colorize('Operation cancelled by user.', Colors.YELLOW)}")
            print_goodbye()
            return False
        elif action == 'increment':
            output_dir = get_incremental_output_dir(output_dir)
            print(f"\n{colorize('[+]', Colors.GREEN)} Using new directory: {output_dir}")
        elif action == 'overwrite':
            print(f"\n{colorize('[+]', Colors.GREEN)} Will overwrite existing files in: {output_dir}")
        # If action is None, no existing files, proceed normally

    # Create output directories
    print(f"\n{colorize('Creating output directory:', Colors.CYAN)} {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Initialize extractor
    try:
        extractor = FirefoxDatabaseExtractor(profile_path)
    except Exception as e:
        logger.error(f"Failed to initialize extractor: {e}")
        return False

    # Extract databases
    print(f"\n{colorize('=' * 70, Colors.BLUE)}")
    print(f"{colorize('[*] Extracting SQLite Databases', Colors.BOLD + Colors.BLUE)}")
    print(f"{colorize('=' * 70, Colors.BLUE)}")
    db_results, all_queries, total_tables, total_rows = extract_databases(extractor, output_dir, logger)

    # Extract JSON artifacts
    print(f"\n{colorize('=' * 70, Colors.BLUE)}")
    print(f"{colorize('[*] Extracting JSON Artifacts', Colors.BOLD + Colors.BLUE)}")
    print(f"{colorize('=' * 70, Colors.BLUE)}")
    json_data = extract_json_artifacts(extractor, output_dir, logger)

    # Extract credentials from all data
    print(f"\n{colorize('=' * 70, Colors.MAGENTA)}")
    print(f"{colorize('[*] Analyzing for Credentials', Colors.BOLD + Colors.MAGENTA)}")
    print(f"{colorize('=' * 70, Colors.MAGENTA)}")
    
    credentials = extract_credentials_from_data({}, all_queries, json_data)
    
    # Print credentials to terminal (highlighted)
    print_credentials_summary(credentials)

    # Decrypt saved passwords
    print(f"\n{colorize('=' * 70, Colors.RED)}")
    print(f"{colorize('[*] Decrypting Saved Passwords', Colors.BOLD + Colors.RED)}")
    print(f"{colorize('=' * 70, Colors.RED)}")
    
    decrypted_passwords = []
    
    # Check environment before attempting decryption
    try:
        validate_environment(profile_path)
    except UnsupportedEnvironment as e:
        print(f"  {colorize('[!] UNSUPPORTED ENVIRONMENT', Colors.RED)}")
        print(f"  {colorize(str(e), Colors.YELLOW)}")
        error = str(e)
        passwords = []
    except NSSLibraryMissing as e:
        print(f"  {colorize('[!] MISSING LIBRARY', Colors.RED)}")
        print(f"  {colorize(str(e), Colors.YELLOW)}")
        error = str(e)
        passwords = []
    except OSKeyringLocked as e:
        print(f"  {colorize('[!] OS KEYRING LOCKED', Colors.RED)}")
        print(f"  {colorize(str(e), Colors.YELLOW)}")
        error = str(e)
        passwords = []
    else:
        # Environment OK - proceed with decryption
        # First try without master password
        passwords, error = decrypt_firefox_passwords(profile_path, "")
        
        if error and "master password" in error.lower():
            # Master password is required
            if interactive:
                master_password = prompt_master_password()
                if master_password:
                    passwords, error = decrypt_firefox_passwords(profile_path, master_password)
                else:
                    print(f"  {colorize('[*] Skipping password decryption (no master password provided)', Colors.YELLOW)}")
                    error = None  # User chose to skip
            else:
                print(f"  {colorize('[*] Master password required but running non-interactively', Colors.YELLOW)}")
        
        if error:
            print(f"  {colorize(f'[*] Password decryption failed: {error}', Colors.YELLOW)}")
        elif passwords:
            decrypted_passwords = passwords
            print_decrypted_passwords(passwords)
            
            # Add decrypted passwords to credentials list
            for pwd in passwords:
                credentials.append({
                    'type': 'Saved Password',
                    'source': 'logins.json (decrypted)',
                    'field': 'password',
                    'value': pwd.password,
                    'extra': {
                        'URL': pwd.hostname,
                        'Username': pwd.username,
                        'Times Used': pwd.times_used or 0,
                    }
                })

    # Calculate summary stats (use values from extract_databases)
    summary = {
        'databases': len(db_results),
        'tables': total_tables,
        'total_rows': total_rows,
        'json_files': len(json_data),
        'credentials': len(credentials),
        'decrypted_passwords': len(decrypted_passwords)
    }

    # Create ForensicData object
    forensic_data = ForensicData(
        profile_path=str(profile_path),
        profile_name=profile_info['name'],
        extraction_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        databases={},  # We don't store raw database tables anymore
        queries=all_queries,
        json_artifacts=json_data,
        credentials=credentials,
        summary=summary
    )

    # Generate reports in requested formats
    print(f"\n{colorize('=' * 70, Colors.GREEN)}")
    print(f"{colorize('[*] Generating Reports', Colors.BOLD + Colors.GREEN)}")
    print(f"{colorize('=' * 70, Colors.GREEN)}")
    
    report_gen = ReportGenerator(forensic_data)
    
    if 'html' in formats:
        html_path = output_dir / f"forensics_report.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(report_gen.html_formatter.generate())
        print(f"  {colorize('[+]', Colors.GREEN)} HTML Report: {html_path}")
    
    if 'md' in formats:
        md_path = output_dir / f"forensics_report.md"
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(report_gen.md_formatter.generate())
        print(f"  {colorize('[+]', Colors.GREEN)} Markdown Report: {md_path}")
    
    if 'csv' in formats:
        csv_dir = output_dir / "csv_export"
        csv_files = report_gen.csv_formatter.save_all(csv_dir)
        print(f"  {colorize('[+]', Colors.GREEN)} CSV Files: {len(csv_files)} files in {csv_dir}")
    
    # Generate master report (legacy format)
    master_report = ForensicReportGenerator.generate_master_report(
        profile_path, db_results, json_data, output_dir
    )
    master_report_path = output_dir / "master_report.md"
    master_report_path.write_text(master_report, encoding='utf-8')

    # Summary
    print(f"\n{colorize('=' * 70, Colors.GREEN)}")
    print(f"{colorize('[+] EXTRACTION COMPLETE', Colors.BOLD + Colors.GREEN)}")
    print(f"{colorize('=' * 70, Colors.GREEN)}")
    
    print(f"\n{colorize('Summary:', Colors.CYAN)}")
    print(f"  - Databases processed: {colorize(str(summary['databases']), Colors.YELLOW)}")
    print(f"  - Tables extracted: {colorize(str(summary['tables']), Colors.YELLOW)}")
    total_rows_str = f"{summary['total_rows']:,}"
    print(f"  - Total rows: {colorize(total_rows_str, Colors.YELLOW)}")
    print(f"  - JSON artifacts: {colorize(str(summary['json_files']), Colors.YELLOW)}")
    print(f"  - Credentials found: {colorize(str(summary['credentials']), Colors.RED + Colors.BOLD)}")
    print(f"  - Passwords decrypted: {colorize(str(summary.get('decrypted_passwords', 0)), Colors.RED + Colors.BOLD)}")
    
    print(f"\n{colorize('Output saved to:', Colors.CYAN)} {output_dir}")
    print(f"\n{colorize('Files created:', Colors.CYAN)}")
    for subdir in ["databases", "forensics", "reports", "artifacts", "csv_export"]:
        subpath = output_dir / subdir
        if subpath.exists():
            file_count = len(list(subpath.rglob("*.*")))
            print(f"  [DIR] {subdir}/: {file_count} files")
    
    # List main reports
    for report_file in output_dir.glob("forensics_report.*"):
        print(f"  [FILE] {report_file.name}")

    print_goodbye()
    return True


def extract_profile_forensic(
    profile_path: Path,
    output_dir: Path,
    logger: logging.Logger,
    interactive: bool = True,
    copy_artifacts: bool = False,
    output_provided: bool = False,
) -> bool:
    """DFIR-compliant forensic extraction with full evidence integrity.
    
    This function generates forensic-grade reports following DFIR best practices:
    - report.html: Human-readable forensic report
    - report.json: Machine-readable structured data
    - summary.txt: Executive summary
    - artifacts/: Copied read-only browser databases (optional)
    
    Args:
        profile_path: Path to Firefox profile.
        output_dir: Output directory path.
        logger: Logger instance.
        interactive: Whether to prompt for user input.
        copy_artifacts: Whether to copy source files as read-only artifacts.
        output_provided: Whether output path was provided via command line.
    
    Returns:
        True if extraction completed successfully.
    """
    print_banner()
    
    # Validate profile
    logger.info(f"Validating profile at {profile_path}...")
    if not validate_profile_path(profile_path):
        logger.error(f"Invalid Firefox profile: {profile_path}")
        return False
    
    # Get profile info for display
    profile_info = get_profile_info(profile_path)
    
    print(f"{colorize('Profile:', Colors.CYAN)} {profile_info['name']}")
    print(f"{colorize('Path:', Colors.CYAN)} {profile_path}")
    print(f"{colorize('Size:', Colors.CYAN)} {profile_info.get('total_size_formatted', 'unknown')}")
    print(f"{colorize('Files:', Colors.CYAN)} {profile_info.get('file_count', 'unknown')}")
    print()
    
    # Interactive output path selection
    if interactive and not output_provided:
        output_dir = prompt_path(
            "Enter output directory",
            default=str(output_dir)
        )
        if output_dir is None:
            print_goodbye()
            return False
    
    # Convert to Path object
    output_dir = Path(output_dir)
    
    # Check for existing output files if directory exists
    if interactive and output_dir.exists():
        action = prompt_output_exists(output_dir)
        
        if action == 'cancel':
            print(f"\n{colorize('Operation cancelled by user.', Colors.YELLOW)}")
            print_goodbye()
            return False
        elif action == 'increment':
            output_dir = get_incremental_output_dir(output_dir)
            print(f"\n{colorize('[+]', Colors.GREEN)} Using new directory: {output_dir}")
        elif action == 'overwrite':
            print(f"\n{colorize('[+]', Colors.GREEN)} Will overwrite existing files in: {output_dir}")
        # If action is None, no existing files, proceed normally
    
    # Create output directory
    print(f"\n{colorize('Creating output directory:', Colors.CYAN)} {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize forensic report builder
    print(f"\n{colorize('=' * 70, Colors.BLUE)}")
    print(f"{colorize('[*] Building Forensic Report', Colors.BOLD + Colors.BLUE)}")
    print(f"{colorize('=' * 70, Colors.BLUE)}")
    
    execution_args = sys.argv[1:] if len(sys.argv) > 1 else []
    
    try:
        builder = ForensicReportBuilder(
            profile_path=profile_path,
            output_dir=output_dir,
            copy_artifacts=copy_artifacts,
            execution_args=execution_args
        )
        
        # Collect evidence files
        print(f"  {colorize('-', Colors.CYAN)} Collecting evidence integrity data...")
        evidence_files = builder.evidence_manager.collect_evidence_files(copy_artifacts)
        print(f"    {colorize('[+]', Colors.GREEN)} {len(evidence_files)} files catalogued")
        
        # Extract databases
        print(f"  {colorize('-', Colors.CYAN)} Extracting SQLite databases...")
        builder._extract_all_databases()
        db_count = len([f for f in builder.findings.keys() if not f.startswith('logins')])
        print(f"    {colorize('[+]', Colors.GREEN)} {db_count} data categories extracted")
        
        # Extract JSON artifacts
        print(f"  {colorize('-', Colors.CYAN)} Processing JSON artifacts...")
        builder._extract_json_artifacts()
        
        # Attempt password decryption
        print(f"\n{colorize('=' * 70, Colors.RED)}")
        print(f"{colorize('[*] Attempting Password Decryption', Colors.BOLD + Colors.RED)}")
        print(f"{colorize('=' * 70, Colors.RED)}")
        
        decrypted_passwords = []
        
        try:
            validate_environment(profile_path)
            
            # Try without master password first
            passwords, error = decrypt_firefox_passwords(profile_path, "")
            
            if error and "master password" in error.lower():
                if interactive:
                    master_password = prompt_master_password()
                    if master_password:
                        passwords, error = decrypt_firefox_passwords(profile_path, master_password)
                        if passwords:
                            builder.set_decrypted_passwords(passwords, master_password_used=True)
                            decrypted_passwords = passwords
                            print_decrypted_passwords(passwords)
                    else:
                        print(f"  {colorize('[*] Skipping password decryption', Colors.YELLOW)}")
                        builder.decryption_context.master_password_status = "set"
                        builder.decryption_context.decryption_status = ProcessingStatus.PARTIAL
                        builder.decryption_context.failure_reason = "Master password required but not provided"
                else:
                    print(f"  {colorize('[*] Master password required but running non-interactively', Colors.YELLOW)}")
                    builder.decryption_context.master_password_status = "set"
                    builder.decryption_context.decryption_status = ProcessingStatus.PARTIAL
            elif error:
                print(f"  {colorize(f'[*] Decryption failed: {error}', Colors.YELLOW)}")
                builder.decryption_context.decryption_status = ProcessingStatus.FAILED
                builder.decryption_context.failure_reason = error
            elif passwords:
                builder.set_decrypted_passwords(passwords)
                decrypted_passwords = passwords
                print_decrypted_passwords(passwords)
            else:
                print(f"  {colorize('[*] No saved passwords found', Colors.YELLOW)}")
                builder.decryption_context.decryption_status = ProcessingStatus.SUCCESS
                
        except UnsupportedEnvironment as e:
            print(f"  {colorize('[!] UNSUPPORTED ENVIRONMENT', Colors.RED)}")
            print(f"  {colorize(str(e), Colors.YELLOW)}")
            builder.decryption_context.decryption_status = ProcessingStatus.FAILED
            builder.decryption_context.failure_reason = str(e)
        except NSSLibraryMissing as e:
            print(f"  {colorize('[!] MISSING LIBRARY', Colors.RED)}")
            print(f"  {colorize(str(e), Colors.YELLOW)}")
            builder.decryption_context.decryption_status = ProcessingStatus.FAILED
            builder.decryption_context.failure_reason = str(e)
        except OSKeyringLocked as e:
            print(f"  {colorize('[!] OS KEYRING LOCKED', Colors.RED)}")
            print(f"  {colorize(str(e), Colors.YELLOW)}")
            builder.decryption_context.decryption_status = ProcessingStatus.FAILED
            builder.decryption_context.failure_reason = str(e)
        
        # Build final report
        print(f"\n{colorize('=' * 70, Colors.GREEN)}")
        print(f"{colorize('[*] Generating Forensic Reports', Colors.BOLD + Colors.GREEN)}")
        print(f"{colorize('=' * 70, Colors.GREEN)}")
        
        # Build report object
        report = builder.build()
        
        # Generate all output files
        output_manager = ReportOutputManager(report, output_dir)
        outputs = output_manager.generate_all()
        
        # Report generated files
        for fmt, path in outputs.items():
            print(f"  {colorize('[+]', Colors.GREEN)} {fmt.upper()}: {path}")
        
        # Copy artifacts if requested
        if copy_artifacts:
            artifacts_dir = output_dir / "artifacts"
            if artifacts_dir.exists():
                artifact_count = len(list(artifacts_dir.glob('*')))
                print(f"  {colorize('[+]', Colors.GREEN)} Artifacts: {artifact_count} files copied to {artifacts_dir}")
        
        # Summary
        print(f"\n{colorize('=' * 70, Colors.GREEN)}")
        print(f"{colorize('[+] FORENSIC EXTRACTION COMPLETE', Colors.BOLD + Colors.GREEN)}")
        print(f"{colorize('=' * 70, Colors.GREEN)}")
        
        # Statistics
        total_items = sum(cat.total_count for cat in report.findings.values())
        errors = len([e for e in report.errors_and_warnings if e.status == ProcessingStatus.FAILED])
        warnings = len([e for e in report.errors_and_warnings if e.status == ProcessingStatus.PARTIAL])
        
        print(f"\n{colorize('Statistics:', Colors.CYAN)}")
        print(f"  - Evidence files catalogued: {colorize(str(len(evidence_files)), Colors.YELLOW)}")
        print(f"  - Data categories extracted: {colorize(str(len(report.findings)), Colors.YELLOW)}")
        print(f"  - Total items extracted: {colorize(f'{total_items:,}', Colors.YELLOW)}")
        print(f"  - Passwords decrypted: {colorize(str(len(decrypted_passwords)), Colors.RED + Colors.BOLD)}")
        print(f"  - Errors: {colorize(str(errors), Colors.RED if errors else Colors.GREEN)}")
        print(f"  - Warnings: {colorize(str(warnings), Colors.YELLOW if warnings else Colors.GREEN)}")
        
        print(f"\n{colorize('Output Directory:', Colors.CYAN)} {output_dir}")
        print(f"\n{colorize('Generated Files:', Colors.CYAN)}")
        print(f"  [FILE] report.html    - Human-readable forensic report")
        print(f"  [FILE] report.json    - Machine-readable structured data")
        print(f"  [FILE] summary.txt    - Executive summary")
        if copy_artifacts and artifacts_dir.exists():
            print(f"  [DIR]  artifacts/     - Copied read-only source files")
        
        print_goodbye()
        return True
        
    except Exception as e:
        logger.exception(f"Forensic extraction failed: {e}")
        print(f"\n{colorize(f'[!] Extraction failed: {e}', Colors.RED)}")
        print_goodbye()
        return False


def main():
    """Main entry point with CLI argument parsing."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "profile",
        nargs="?",
        help="Path to browser profile directory (optional - will auto-detect if not provided)",
    )

    parser.add_argument(
        "--browser", "-b",
        choices=["firefox", "chrome", "chromium", "edge", "brave", "opera", "vivaldi", "auto"],
        default="auto",
        help="Browser to extract from (default: auto-detect all browsers)",
    )

    parser.add_argument(
        "--list-browsers",
        action="store_true",
        help="List all detected browsers and their profiles",
    )

    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output directory name (default: ~/Downloads/<browser>_forensics_output)",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=['html', 'csv', 'md', 'all', 'forensic'],
        default='forensic',
        help="Output format: 'forensic' for DFIR-compliant reports (default), or legacy formats",
    )

    parser.add_argument(
        "--copy-artifacts",
        "-c",
        action="store_true",
        help="Copy source database files as read-only artifacts (forensic mode)",
    )

    parser.add_argument(
        "--extract", "-e",
        nargs="+",
        choices=["history", "cookies", "passwords", "downloads", "bookmarks", 
                 "autofill", "extensions", "forms", "permissions", "search", "all"],
        default=["all"],
        help="Data categories to extract (default: all). Can specify multiple: -e history cookies",
    )

    parser.add_argument(
        "--print-only",
        action="store_true",
        help="Print extracted data to terminal only (no file output)",
    )

    parser.add_argument(
        "--no-passwords",
        action="store_true",
        help="Skip password decryption",
    )

    parser.add_argument(
        "--no-interactive",
        "-n",
        action="store_true",
        help="Disable interactive prompts (use defaults)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging (DEBUG level)",
    )

    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress non-critical output",
    )

    parser.add_argument(
        "--list-queries",
        action="store_true",
        help="List all available forensic queries and exit",
    )

    parser.add_argument(
        "--check-env",
        action="store_true",
        help="Check environment compatibility for password decryption and exit",
    )

    parser.add_argument(
        "--legacy",
        action="store_true",
        help="Use legacy report format instead of new DFIR-compliant format",
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
        profile = Path(args.profile) if args.profile else None
        run_environment_check(profile)
        return 0

    # Handle --list-queries
    if args.list_queries:
        print(f"{colorize('Available Forensic Queries:', Colors.CYAN)}\n")
        print(f"\n{colorize('Firefox Queries:', Colors.YELLOW)}")
        for db_name, queries in QUERY_REGISTRY.items():
            print(f"  {colorize(db_name, Colors.WHITE)}:")
            for query_name in queries:
                print(f"    - {query_name}")
        
        print(f"\n{colorize('Chromium Queries:', Colors.YELLOW)}")
        from chromium_queries import CHROMIUM_QUERY_REGISTRY
        for category, config in CHROMIUM_QUERY_REGISTRY.items():
            print(f"  {colorize(category, Colors.WHITE)} ({config['database']}):")
            for query_name in config['queries']:
                print(f"    - {query_name}")
        return 0

    # Determine browser filter
    browser_filter = args.browser if args.browser != "auto" else None
    
    # Handle profile path - auto-detect if not provided
    if args.profile:
        # User provided profile path directly
        profile_path = Path(args.profile).expanduser().resolve()
        if not profile_path.exists():
            logger.error(f"Profile path does not exist: {profile_path}")
            return 1
        
        # Try to detect browser type from path
        detected = detect_browser_from_path(str(profile_path))
        if detected:
            browser_type = detected.browser_type
            browser_family = detected.family
            profile_display = detected.display_name
        else:
            # Fallback: try to determine from directory structure
            if (profile_path / "places.sqlite").exists():
                browser_family = BrowserFamily.GECKO
                browser_type = BrowserType.FIREFOX
                profile_display = profile_path.name
            elif (profile_path / "History").exists() or (profile_path / "Cookies").exists():
                browser_family = BrowserFamily.CHROMIUM
                browser_type = BrowserType.CHROMIUM
                profile_display = profile_path.name
            else:
                logger.error("Could not determine browser type from profile path")
                return 1
        
        selected_profile = BrowserProfile(
            path=profile_path,
            name=profile_path.name,
            display_name=profile_display,
            browser_type=browser_type,
            family=browser_family,
        )
    else:
        # Auto-detect: show browser selection
        selected_profile = prompt_browser_selection(filter_browser=browser_filter)
        if selected_profile is None:
            print_goodbye()
            return 0

    # Track if user specified output path
    output_provided = args.output is not None
    browser_name = selected_profile.browser_type.value.lower().replace(" ", "_")
    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = Path.home() / "Downloads" / f"{browser_name}_forensics_output"

    # Determine which extraction mode to use
    use_forensic_mode = (args.format == 'forensic' or args.format == 'all') and not args.legacy
    profile_path = selected_profile.profile_path
    
    # Get extraction categories
    extract_categories = args.extract if hasattr(args, 'extract') else ['all']
    print_only = args.print_only if hasattr(args, 'print_only') else False

    # Run extraction based on browser family
    try:
        interactive = not args.no_interactive
        skip_passwords = args.no_passwords
        
        # Check if passwords should be included based on extract categories
        if 'passwords' not in extract_categories and 'all' not in extract_categories:
            skip_passwords = True
        
        if selected_profile.browser_family == BrowserFamily.CHROMIUM:
            # Chromium-based browser extraction
            success = extract_chromium_forensics(
                selected_profile,
                output_dir,
                logger,
                interactive=interactive,
                copy_artifacts=args.copy_artifacts,
                output_provided=output_provided,
                skip_passwords=skip_passwords,
                extract_categories=extract_categories,
                print_only=print_only,
            )
        elif selected_profile.browser_family == BrowserFamily.GECKO:
            # Firefox/Gecko browser extraction
            if print_only or extract_categories != ['all']:
                # Use quick extraction for print-only or specific categories
                success = extract_firefox_quick(
                    profile_path,
                    output_dir,
                    logger,
                    extract_categories=extract_categories,
                    print_only=print_only,
                    skip_passwords=skip_passwords,
                )
            elif use_forensic_mode:
                # Use new DFIR-compliant forensic extraction
                success = extract_profile_forensic(
                    profile_path,
                    output_dir,
                    logger,
                    interactive=interactive,
                    copy_artifacts=args.copy_artifacts,
                    output_provided=output_provided,
                )
            else:
                # Use legacy extraction mode
                format_provided = args.format != 'all'
                if args.format == 'all':
                    formats = ['html', 'csv', 'md']
                elif args.format == 'forensic':
                    formats = ['html', 'csv', 'md']
                else:
                    formats = [args.format]
                
                success = extract_profile(
                    profile_path,
                    output_dir,
                    logger,
                    formats=formats,
                    interactive=interactive,
                    format_provided=format_provided,
                    output_provided=output_provided,
                )
        else:
            logger.error(f"Unsupported browser family: {selected_profile.browser_family}")
            return 1
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print(f"\n{colorize('Extraction interrupted by user', Colors.YELLOW)}")
        print_goodbye()
        return 130
    except Exception as e:
        logger.exception(f"Unexpected error during extraction: {e}")
        print_goodbye()
        return 1


def extract_chromium_forensics(
    profile: BrowserProfile,
    output_dir: Path,
    logger: logging.Logger,
    interactive: bool = True,
    copy_artifacts: bool = False,
    output_provided: bool = False,
    skip_passwords: bool = False,
    extract_categories: list = None,
    print_only: bool = False,
) -> bool:
    """Extract forensic data from a Chromium-based browser profile."""
    from chromium_extractor import ChromiumDatabaseExtractor, ChromiumJSONExtractor
    from chromium_queries import CHROMIUM_QUERY_REGISTRY
    from chromium_decrypt import decrypt_chromium_passwords, check_decryption_requirements
    
    if extract_categories is None:
        extract_categories = ['all']
    
    extract_all = 'all' in extract_categories
    
    # Map categories to Chromium query categories
    category_map = {
        'history': ['History'],
        'cookies': ['Cookies'],
        'downloads': ['Downloads'],
        'autofill': ['Autofill'],
        'forms': ['Autofill'],
        'search': ['SearchEngines'],
        'bookmarks': ['Bookmarks'],
        'extensions': ['Extensions'],
        'passwords': ['Logins'],
    }
    
    profile_path = profile.profile_path
    browser_name = profile.browser_type.value
    profile_name = profile.display_name.split(" - ", 1)[1] if " - " in profile.display_name else profile.profile_name
    
    print(f"\n{colorize('=' * 60, Colors.CYAN)}")
    print(f"{colorize(f'Extracting from {browser_name}', Colors.CYAN)}")
    print(f"{colorize(f'Profile: {profile_name}', Colors.WHITE)}")
    print(f"{colorize(f'Path: {profile_path}', Colors.WHITE)}")
    if not extract_all:
        print(f"{colorize(f'Categories: {", ".join(extract_categories)}', Colors.YELLOW)}")
    print(f"{colorize('=' * 60, Colors.CYAN)}\n")
    
    # Confirm extraction
    if interactive and not print_only:
        confirm = input(f"{colorize('Proceed with extraction? [Y/n]: ', Colors.YELLOW)}").strip().lower()
        if confirm == 'n':
            print(f"{colorize('Extraction cancelled.', Colors.YELLOW)}")
            return False
    
    # Create output directory (only if not print_only)
    if not print_only:
        if not output_provided:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = output_dir.parent / f"{output_dir.name}_{timestamp}"
        
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n{colorize('[*] Output directory:', Colors.CYAN)} {output_dir}")
    
    all_data = {}
    
    # Determine which categories to extract from database
    db_categories_to_extract = set()
    if extract_all:
        db_categories_to_extract = set(CHROMIUM_QUERY_REGISTRY.keys())
    else:
        for cat in extract_categories:
            if cat in category_map:
                db_categories_to_extract.update(category_map[cat])
    
    # Extract database data
    print(f"\n{colorize('[*] Extracting database artifacts...', Colors.CYAN)}")
    
    with ChromiumDatabaseExtractor(profile) as extractor:
        for category, config in CHROMIUM_QUERY_REGISTRY.items():
            # Skip if not in requested categories
            if category not in db_categories_to_extract:
                continue
                
            db_name = config['database']
            print(f"  {colorize('•', Colors.WHITE)} {category} ({db_name})...", end=" ")
            
            category_data = {}
            for query_name, query_info in config['queries'].items():
                try:
                    # query_info is a dict with 'name', 'query', 'description'
                    query_sql = query_info['query'] if isinstance(query_info, dict) else query_info
                    rows, count = extractor.run_query(db_name, query_sql)
                    if rows:
                        category_data[query_name] = rows
                except Exception as e:
                    logger.debug(f"Query {query_name} failed: {e}")
            
            if category_data:
                all_data[category] = category_data
                total_rows = sum(len(v) for v in category_data.values())
                print(f"{colorize(f'{total_rows} records', Colors.GREEN)}")
            else:
                print(f"{colorize('no data', Colors.YELLOW)}")
    
    # Extract JSON data (bookmarks, extensions) if requested
    if extract_all or 'bookmarks' in extract_categories or 'extensions' in extract_categories:
        print(f"\n{colorize('[*] Extracting JSON artifacts...', Colors.CYAN)}")
        
        json_extractor = ChromiumJSONExtractor(profile)
        
        # Bookmarks
        if extract_all or 'bookmarks' in extract_categories:
            print(f"  {colorize('•', Colors.WHITE)} Bookmarks...", end=" ")
            bookmarks = json_extractor.flatten_bookmarks()
            if bookmarks:
                all_data['Bookmarks'] = {'bookmarks': bookmarks}
                print(f"{colorize(f'{len(bookmarks)} bookmarks', Colors.GREEN)}")
            else:
                print(f"{colorize('no data', Colors.YELLOW)}")
        
        # Extensions
        if extract_all or 'extensions' in extract_categories:
            print(f"  {colorize('•', Colors.WHITE)} Extensions...", end=" ")
            extensions = json_extractor.get_extensions()
            if extensions:
                all_data['Extensions'] = {'extensions': extensions}
                print(f"{colorize(f'{len(extensions)} extensions', Colors.GREEN)}")
            else:
                print(f"{colorize('no data', Colors.YELLOW)}")
    
    # Password decryption
    if not skip_passwords and (extract_all or 'passwords' in extract_categories):
        print(f"\n{colorize('[*] Attempting password decryption...', Colors.CYAN)}")
        reqs_met, missing = check_decryption_requirements()
        
        if reqs_met:
            credentials = decrypt_chromium_passwords(profile_path)
            if credentials:
                all_data['Credentials'] = {'passwords': credentials}
                print(f"  {colorize('✓', Colors.GREEN)} Decrypted {len(credentials)} credentials")
                
                # Display credentials
                print_credentials_chromium(credentials)
            else:
                print(f"  {colorize('•', Colors.YELLOW)} No saved passwords found")
        else:
            print(f"  {colorize('✗', Colors.RED)} Missing requirements: {', '.join(missing)}")
    elif skip_passwords and (extract_all or 'passwords' in extract_categories):
        print(f"\n{colorize('[*] Password decryption skipped (--no-passwords)', Colors.YELLOW)}")
    
    # Print data to terminal if requested
    if print_only or not extract_all:
        # Flatten all_data for terminal printing
        flat_data = {}
        for category, queries in all_data.items():
            for query_name, rows in queries.items():
                flat_data[query_name] = rows
                flat_data[category] = rows  # Also add by category name
        
        print_extracted_data_terminal(flat_data, extract_categories)
    
    # If print_only, skip file generation
    if print_only:
        print(f"\n{colorize('=' * 60, Colors.GREEN)}")
        print(f"{colorize('Data printed to terminal (--print-only mode)', Colors.GREEN)}")
        print(f"{colorize('=' * 60, Colors.GREEN)}")
        print_goodbye()
        return True
    
    # Copy artifacts if requested
    if copy_artifacts:
        print(f"\n{colorize('[*] Copying source artifacts...', Colors.CYAN)}")
        artifacts_dir = output_dir / "artifacts"
        artifacts_dir.mkdir(exist_ok=True)
        
        artifact_files = [
            "History", "Cookies", "Login Data", "Web Data",
            "Bookmarks", "Preferences", "Secure Preferences",
            "Local State", "Extensions"
        ]
        
        for artifact in artifact_files:
            src = profile_path / artifact
            if src.exists():
                dst = artifacts_dir / artifact
                try:
                    if src.is_file():
                        shutil.copy2(src, dst)
                        os.chmod(dst, 0o444)  # Read-only
                        print(f"  {colorize('✓', Colors.GREEN)} {artifact}")
                    elif src.is_dir():
                        shutil.copytree(src, dst)
                        print(f"  {colorize('✓', Colors.GREEN)} {artifact}/ (directory)")
                except Exception as e:
                    print(f"  {colorize('✗', Colors.RED)} {artifact}: {e}")
    
    # Generate reports
    print(f"\n{colorize('[*] Generating forensic reports...', Colors.CYAN)}")
    
    # Generate CSV reports
    csv_dir = output_dir / "csv"
    csv_dir.mkdir(exist_ok=True)
    
    for category, queries in all_data.items():
        for query_name, rows in queries.items():
            if rows and isinstance(rows, list) and len(rows) > 0:
                csv_path = csv_dir / f"{category}_{query_name}.csv"
                try:
                    if isinstance(rows[0], dict):
                        import csv
                        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                            writer.writeheader()
                            writer.writerows(rows)
                        print(f"  {colorize('✓', Colors.GREEN)} {csv_path.name}")
                except Exception as e:
                    logger.debug(f"CSV export failed for {category}/{query_name}: {e}")
    
    # Generate summary report
    summary_path = output_dir / "extraction_summary.txt"
    with open(summary_path, 'w') as f:
        f.write(f"Browser Forensics Extraction Summary\n")
        f.write(f"{'=' * 50}\n\n")
        f.write(f"Browser: {browser_name}\n")
        f.write(f"Profile: {profile_name}\n")
        f.write(f"Profile Path: {profile_path}\n")
        f.write(f"Extraction Time: {datetime.now().isoformat()}\n")
        f.write(f"Output Directory: {output_dir}\n")
        f.write(f"Categories Extracted: {', '.join(extract_categories)}\n\n")
        
        f.write(f"Extracted Data Summary:\n")
        f.write(f"{'-' * 30}\n")
        for category, queries in all_data.items():
            total = sum(len(v) if isinstance(v, list) else 1 for v in queries.values())
            f.write(f"  {category}: {total} records\n")
    
    print(f"  {colorize('✓', Colors.GREEN)} extraction_summary.txt")
    
    print(f"\n{colorize('=' * 60, Colors.GREEN)}")
    print(f"{colorize('Extraction Complete!', Colors.GREEN)}")
    print(f"{colorize(f'Output: {output_dir}', Colors.WHITE)}")
    print(f"{colorize('=' * 60, Colors.GREEN)}")
    
    print_goodbye()
    return True


def extract_firefox_quick(
    profile_path: Path,
    output_dir: Path,
    logger: logging.Logger,
    extract_categories: list = None,
    print_only: bool = False,
    skip_passwords: bool = False,
) -> bool:
    """Quick extraction for Firefox with specific categories and terminal print support."""
    from extractor import FirefoxDatabaseExtractor
    from queries import QUERY_REGISTRY
    
    if extract_categories is None:
        extract_categories = ['all']
    
    extract_all = 'all' in extract_categories
    
    # Map categories to Firefox database/query mappings
    category_map = {
        'history': [('places.sqlite', ['browsing_history', 'recent_24h', 'top_sites'])],
        'cookies': [('cookies.sqlite', ['all_cookies', 'auth_tokens', 'persistent_sessions'])],
        'downloads': [('places.sqlite', ['downloads'])],
        'bookmarks': [('places.sqlite', ['bookmarks'])],
        'forms': [('formhistory.sqlite', ['all_form_history', 'sensitive_fields'])],
        'autofill': [('formhistory.sqlite', ['all_form_history', 'email_addresses', 'usernames'])],
        'search': [('formhistory.sqlite', ['search_queries']), ('places.sqlite', ['search_queries'])],
        'permissions': [('permissions.sqlite', ['all_permissions', 'granted_permissions'])],
    }
    
    print(f"\n{colorize('=' * 60, Colors.CYAN)}")
    print(f"{colorize('Extracting from Firefox', Colors.CYAN)}")
    print(f"{colorize(f'Profile: {profile_path.name}', Colors.WHITE)}")
    print(f"{colorize(f'Path: {profile_path}', Colors.WHITE)}")
    if not extract_all:
        print(f"{colorize(f'Categories: {", ".join(extract_categories)}', Colors.YELLOW)}")
    print(f"{colorize('=' * 60, Colors.CYAN)}\n")
    
    all_data = {}
    
    # Determine which queries to run
    queries_to_run = {}  # db_name -> [query_names]
    
    if extract_all:
        for db_name, queries in QUERY_REGISTRY.items():
            queries_to_run[db_name] = list(queries.keys())
    else:
        for cat in extract_categories:
            if cat in category_map:
                for db_name, query_names in category_map[cat]:
                    if db_name not in queries_to_run:
                        queries_to_run[db_name] = []
                    queries_to_run[db_name].extend(query_names)
    
    # Extract data
    print(f"{colorize('[*] Extracting database artifacts...', Colors.CYAN)}")
    
    extractor = FirefoxDatabaseExtractor(profile_path)
    
    for db_name, query_names in queries_to_run.items():
        if db_name not in QUERY_REGISTRY:
            continue
        
        db_path = profile_path / db_name
        if not db_path.exists():
            continue
            
        print(f"  {colorize('•', Colors.WHITE)} {db_name}...", end=" ")
        
        db_data = {}
        for query_name in set(query_names):  # Deduplicate
            if query_name in QUERY_REGISTRY.get(db_name, {}):
                try:
                    query_sql = QUERY_REGISTRY[db_name][query_name]
                    rows, count = extractor.run_forensic_query(db_path, query_sql)
                    if rows:
                        db_data[query_name] = rows
                except Exception as e:
                    logger.debug(f"Query {query_name} failed: {e}")
        
        if db_data:
            all_data[db_name] = db_data
            total_rows = sum(len(v) for v in db_data.values())
            print(f"{colorize(f'{total_rows} records', Colors.GREEN)}")
        else:
            print(f"{colorize('no data', Colors.YELLOW)}")
    
    # Password decryption
    if not skip_passwords and (extract_all or 'passwords' in extract_categories):
        print(f"\n{colorize('[*] Attempting password decryption...', Colors.CYAN)}")
        try:
            from nss_decrypt import decrypt_firefox_passwords, check_master_password_required
            
            if check_master_password_required(profile_path):
                password = prompt_master_password()
                if not password:
                    print(f"  {colorize('•', Colors.YELLOW)} Password decryption cancelled")
                else:
                    passwords = decrypt_firefox_passwords(profile_path, master_password=password)
                    if passwords:
                        all_data['passwords'] = {'decrypted': passwords}
                        print(f"  {colorize('✓', Colors.GREEN)} Decrypted {len(passwords)} passwords")
                        print_decrypted_passwords(passwords)
            else:
                passwords = decrypt_firefox_passwords(profile_path)
                if passwords:
                    all_data['passwords'] = {'decrypted': passwords}
                    print(f"  {colorize('✓', Colors.GREEN)} Decrypted {len(passwords)} passwords")
                    print_decrypted_passwords(passwords)
                else:
                    print(f"  {colorize('•', Colors.YELLOW)} No saved passwords found")
        except Exception as e:
            logger.debug(f"Password decryption failed: {e}")
            print(f"  {colorize('✗', Colors.RED)} Password decryption failed: {e}")
    
    # Flatten data for terminal printing
    flat_data = {}
    for db_name, queries in all_data.items():
        if isinstance(queries, dict):
            for query_name, rows in queries.items():
                flat_data[query_name] = rows
    
    # Print to terminal
    print_extracted_data_terminal(flat_data, extract_categories)
    
    if print_only:
        print(f"\n{colorize('=' * 60, Colors.GREEN)}")
        print(f"{colorize('Data printed to terminal (--print-only mode)', Colors.GREEN)}")
        print(f"{colorize('=' * 60, Colors.GREEN)}")
        print_goodbye()
        return True
    
    # Save to files
    if not output_dir.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = output_dir.parent / f"{output_dir.name}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{colorize('[*] Saving to files...', Colors.CYAN)}")
    print(f"  {colorize('Output:', Colors.WHITE)} {output_dir}")
    
    # Save CSV files
    csv_dir = output_dir / "csv"
    csv_dir.mkdir(exist_ok=True)
    
    import csv as csv_module
    for query_name, rows in flat_data.items():
        if rows and isinstance(rows, list) and len(rows) > 0 and isinstance(rows[0], dict):
            csv_path = csv_dir / f"{query_name}.csv"
            try:
                with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv_module.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)
                print(f"  {colorize('✓', Colors.GREEN)} {csv_path.name}")
            except Exception as e:
                logger.debug(f"CSV export failed: {e}")
    
    print(f"\n{colorize('=' * 60, Colors.GREEN)}")
    print(f"{colorize('Extraction Complete!', Colors.GREEN)}")
    print(f"{colorize(f'Output: {output_dir}', Colors.WHITE)}")
    print(f"{colorize('=' * 60, Colors.GREEN)}")
    
    print_goodbye()
    return True


if __name__ == "__main__":
    sys.exit(main())
