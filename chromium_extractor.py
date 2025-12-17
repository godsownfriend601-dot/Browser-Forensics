#!/usr/bin/env python3
"""Chromium Browser Forensic Extractor.

Extracts and analyzes forensic artifacts from Chromium-based browsers:
- Google Chrome
- Microsoft Edge
- Brave Browser
- Opera
- Vivaldi
- Chromium

Database files handled:
- History: browsing history, downloads, keyword searches
- Cookies: session and persistent cookies
- Login Data: saved passwords (encrypted)
- Web Data: autofill, credit cards, addresses
- Bookmarks: JSON file with bookmark tree
- Preferences: JSON browser settings
"""

import csv
import json
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from browser_profiles import BrowserProfile, BrowserType, BrowserFamily
from chromium_queries import CHROMIUM_QUERY_REGISTRY, webkit_to_unix


@dataclass
class ChromiumExtractionResult:
    """Result of a Chromium extraction operation."""
    success: bool
    database: str
    query_name: str
    rows_extracted: int
    error: Optional[str] = None
    output_path: Optional[Path] = None
    data: Optional[List[Dict[str, Any]]] = None


class ChromiumDatabaseExtractor:
    """Extract data from Chromium SQLite databases.
    
    Chromium databases are often locked while the browser is running.
    This extractor creates temporary copies for safe access.
    """
    
    def __init__(self, profile: BrowserProfile):
        """Initialize extractor with a browser profile.
        
        Args:
            profile: BrowserProfile object with paths
        """
        if profile.browser_family != BrowserFamily.CHROMIUM:
            raise ValueError(f"Expected Chromium browser, got {profile.browser_family}")
        
        self.profile = profile
        self.profile_path = profile.profile_path
        self.user_data_dir = profile.user_data_dir
        self._temp_dir: Optional[Path] = None
        self._db_copies: Dict[str, Path] = {}
    
    def __enter__(self):
        """Context manager entry - create temp directory."""
        self._temp_dir = Path(tempfile.mkdtemp(prefix="chromium_forensics_"))
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup temp files."""
        self.cleanup()
    
    def cleanup(self):
        """Remove temporary database copies."""
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
        self._db_copies.clear()
    
    def _get_db_copy(self, db_name: str) -> Optional[Path]:
        """Get a safe copy of a database file.
        
        Chromium locks database files while running. We copy them
        to a temp location for safe read access.
        
        Args:
            db_name: Name of database file (e.g., "History", "Cookies")
        
        Returns:
            Path to temporary copy, or None if database doesn't exist
        """
        if db_name in self._db_copies:
            return self._db_copies[db_name]
        
        original_path = self.profile_path / db_name
        if not original_path.exists():
            return None
        
        if self._temp_dir is None:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="chromium_forensics_"))
        
        temp_path = self._temp_dir / db_name
        
        try:
            shutil.copy2(original_path, temp_path)
            
            # Also copy WAL and SHM files if they exist (for integrity)
            for suffix in ["-wal", "-shm", "-journal"]:
                wal_path = original_path.parent / f"{db_name}{suffix}"
                if wal_path.exists():
                    shutil.copy2(wal_path, self._temp_dir / f"{db_name}{suffix}")
            
            self._db_copies[db_name] = temp_path
            return temp_path
        except (IOError, OSError) as e:
            print(f"Error copying database {db_name}: {e}")
            return None
    
    def find_databases(self) -> List[str]:
        """Find all known Chromium database files in the profile.
        
        Returns:
            List of database names that exist
        """
        known_dbs = ["History", "Cookies", "Login Data", "Web Data", 
                     "Shortcuts", "Favicons", "Top Sites", "Network Action Predictor"]
        
        found = []
        for db_name in known_dbs:
            if (self.profile_path / db_name).exists():
                found.append(db_name)
        return found
    
    def find_json_files(self) -> List[Path]:
        """Find important JSON files in the profile.
        
        Returns:
            List of Path objects for JSON files
        """
        json_files = []
        important_json = ["Bookmarks", "Preferences", "Secure Preferences", 
                         "History Provider Cache", "TransportSecurity"]
        
        for name in important_json:
            path = self.profile_path / name
            if path.exists():
                json_files.append(path)
        
        # Local State is in parent directory
        local_state = self.user_data_dir / "Local State"
        if local_state.exists():
            json_files.append(local_state)
        
        return json_files
    
    def get_tables(self, db_name: str) -> List[str]:
        """Get list of tables in a database.
        
        Args:
            db_name: Database file name
        
        Returns:
            List of table names
        """
        db_path = self._get_db_copy(db_name)
        if not db_path:
            return []
        
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()
            return tables
        except sqlite3.Error as e:
            print(f"Error reading tables from {db_name}: {e}")
            return []
    
    def run_query(
        self, 
        db_name: str, 
        query: str
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Execute a SQL query against a database.
        
        Args:
            db_name: Database file name
            query: SQL query string
        
        Returns:
            Tuple of (result_rows, row_count)
        """
        db_path = self._get_db_copy(db_name)
        if not db_path:
            return [], 0
        
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            result = [dict(row) for row in rows]
            conn.close()
            return result, len(result)
        except sqlite3.Error as e:
            print(f"Error executing query on {db_name}: {e}")
            return [], 0
    
    def export_query_to_csv(
        self,
        db_name: str,
        query: str,
        output_path: Path,
        query_name: str = "query"
    ) -> ChromiumExtractionResult:
        """Export query results to CSV file.
        
        Args:
            db_name: Database file name
            query: SQL query string
            output_path: Path to write CSV file
            query_name: Name for logging
        
        Returns:
            ChromiumExtractionResult with status
        """
        rows, count = self.run_query(db_name, query)
        
        if not rows:
            return ChromiumExtractionResult(
                success=True,
                database=db_name,
                query_name=query_name,
                rows_extracted=0,
                output_path=output_path
            )
        
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            
            return ChromiumExtractionResult(
                success=True,
                database=db_name,
                query_name=query_name,
                rows_extracted=count,
                output_path=output_path,
                data=rows
            )
        except IOError as e:
            return ChromiumExtractionResult(
                success=False,
                database=db_name,
                query_name=query_name,
                rows_extracted=0,
                error=str(e)
            )
    
    def extract_all_forensic_data(
        self, 
        output_dir: Path
    ) -> Dict[str, List[ChromiumExtractionResult]]:
        """Extract all forensic data using registered queries.
        
        Args:
            output_dir: Directory to write output files
        
        Returns:
            Dictionary mapping categories to extraction results
        """
        results: Dict[str, List[ChromiumExtractionResult]] = {}
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for category, config in CHROMIUM_QUERY_REGISTRY.items():
            db_name = config["database"]
            queries = config["queries"]
            
            category_results = []
            
            for query_key, query_info in queries.items():
                query_name = query_info["name"]
                query = query_info["query"]
                
                output_file = output_dir / f"{category.lower()}_{query_key}.csv"
                
                result = self.export_query_to_csv(
                    db_name=db_name,
                    query=query,
                    output_path=output_file,
                    query_name=query_name
                )
                category_results.append(result)
            
            results[category] = category_results
        
        return results
    
    def get_browsing_history(self) -> List[Dict[str, Any]]:
        """Get complete browsing history.
        
        Returns:
            List of history entries
        """
        query = CHROMIUM_QUERY_REGISTRY["History"]["queries"]["browsing_history"]["query"]
        rows, _ = self.run_query("History", query)
        return rows
    
    def get_downloads(self) -> List[Dict[str, Any]]:
        """Get download history.
        
        Returns:
            List of download entries
        """
        query = CHROMIUM_QUERY_REGISTRY["Downloads"]["queries"]["all_downloads"]["query"]
        rows, _ = self.run_query("History", query)
        return rows
    
    def get_cookies(self) -> List[Dict[str, Any]]:
        """Get all cookies.
        
        Returns:
            List of cookie entries
        """
        query = CHROMIUM_QUERY_REGISTRY["Cookies"]["queries"]["all_cookies"]["query"]
        rows, _ = self.run_query("Cookies", query)
        return rows
    
    def get_logins(self) -> List[Dict[str, Any]]:
        """Get saved login data (passwords encrypted).
        
        Returns:
            List of login entries
        """
        query = CHROMIUM_QUERY_REGISTRY["Logins"]["queries"]["all_logins"]["query"]
        rows, _ = self.run_query("Login Data", query)
        return rows
    
    def get_autofill(self) -> List[Dict[str, Any]]:
        """Get autofill form data.
        
        Returns:
            List of autofill entries
        """
        query = CHROMIUM_QUERY_REGISTRY["Autofill"]["queries"]["all_autofill"]["query"]
        rows, _ = self.run_query("Web Data", query)
        return rows


class ChromiumJSONExtractor:
    """Extract data from Chromium JSON files."""
    
    def __init__(self, profile: BrowserProfile):
        """Initialize extractor.
        
        Args:
            profile: BrowserProfile object
        """
        self.profile = profile
        self.profile_path = profile.profile_path
        self.user_data_dir = profile.user_data_dir
    
    def extract_bookmarks(self) -> Optional[Dict[str, Any]]:
        """Extract bookmarks from JSON file.
        
        Returns:
            Bookmarks data structure or None
        """
        bookmarks_path = self.profile_path / "Bookmarks"
        if not bookmarks_path.exists():
            return None
        
        try:
            with open(bookmarks_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
    
    def flatten_bookmarks(self) -> List[Dict[str, Any]]:
        """Flatten bookmark tree into a list.
        
        Returns:
            List of bookmark entries with path info
        """
        data = self.extract_bookmarks()
        if not data:
            return []
        
        bookmarks = []
        
        def traverse(node: Dict, path: str = ""):
            if node.get("type") == "url":
                bookmarks.append({
                    "name": node.get("name", ""),
                    "url": node.get("url", ""),
                    "path": path,
                    "date_added": self._chrome_time_to_iso(node.get("date_added", "0")),
                    "date_modified": self._chrome_time_to_iso(node.get("date_modified", "0")),
                    "guid": node.get("guid", ""),
                })
            elif node.get("type") == "folder":
                new_path = f"{path}/{node.get('name', '')}" if path else node.get("name", "")
                for child in node.get("children", []):
                    traverse(child, new_path)
        
        roots = data.get("roots", {})
        for root_name, root_node in roots.items():
            if isinstance(root_node, dict):
                traverse(root_node, root_name)
        
        return bookmarks
    
    def _chrome_time_to_iso(self, chrome_time: str) -> str:
        """Convert Chrome timestamp string to ISO format.
        
        Chrome stores timestamps as strings of WebKit time.
        """
        try:
            ts = int(chrome_time)
            if ts == 0:
                return ""
            unix_ts = webkit_to_unix(ts)
            dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
            return dt.isoformat()
        except (ValueError, OSError):
            return ""
    
    def extract_preferences(self) -> Optional[Dict[str, Any]]:
        """Extract browser preferences.
        
        Returns:
            Preferences dict or None
        """
        prefs_path = self.profile_path / "Preferences"
        if not prefs_path.exists():
            return None
        
        try:
            with open(prefs_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
    
    def get_extensions(self) -> List[Dict[str, Any]]:
        """Get list of installed extensions from preferences.
        
        Returns:
            List of extension info dicts
        """
        prefs = self.extract_preferences()
        if not prefs:
            return []
        
        extensions = []
        ext_settings = prefs.get("extensions", {}).get("settings", {})
        
        for ext_id, ext_data in ext_settings.items():
            if isinstance(ext_data, dict):
                extensions.append({
                    "id": ext_id,
                    "name": ext_data.get("manifest", {}).get("name", "Unknown"),
                    "version": ext_data.get("manifest", {}).get("version", ""),
                    "description": ext_data.get("manifest", {}).get("description", ""),
                    "enabled": ext_data.get("state", 0) == 1,
                    "install_time": self._chrome_time_to_iso(
                        str(ext_data.get("install_time", "0"))
                    ),
                    "from_webstore": ext_data.get("from_webstore", False),
                    "path": ext_data.get("path", ""),
                })
        
        return extensions
    
    def extract_local_state(self) -> Optional[Dict[str, Any]]:
        """Extract Local State file (contains encryption key).
        
        Returns:
            Local State dict or None
        """
        local_state_path = self.user_data_dir / "Local State"
        if not local_state_path.exists():
            return None
        
        try:
            with open(local_state_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
    
    def get_encrypted_key(self) -> Optional[bytes]:
        """Get the encrypted key from Local State.
        
        This key is used to decrypt passwords on Windows (DPAPI)
        and Linux (PBKDF2 + AES).
        
        Returns:
            Base64-decoded encrypted key or None
        """
        import base64
        
        local_state = self.extract_local_state()
        if not local_state:
            return None
        
        encrypted_key_b64 = local_state.get("os_crypt", {}).get("encrypted_key")
        if not encrypted_key_b64:
            return None
        
        try:
            # Key is base64 encoded, prefixed with "DPAPI" on Windows
            encrypted_key = base64.b64decode(encrypted_key_b64)
            return encrypted_key
        except Exception:
            return None
    
    def export_bookmarks_to_csv(self, output_path: Path) -> bool:
        """Export flattened bookmarks to CSV.
        
        Args:
            output_path: Path to write CSV file
        
        Returns:
            True if successful
        """
        bookmarks = self.flatten_bookmarks()
        if not bookmarks:
            return False
        
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=bookmarks[0].keys())
                writer.writeheader()
                writer.writerows(bookmarks)
            return True
        except IOError:
            return False
    
    def export_extensions_to_csv(self, output_path: Path) -> bool:
        """Export extension list to CSV.
        
        Args:
            output_path: Path to write CSV file
        
        Returns:
            True if successful
        """
        extensions = self.get_extensions()
        if not extensions:
            return False
        
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=extensions[0].keys())
                writer.writeheader()
                writer.writerows(extensions)
            return True
        except IOError:
            return False


def extract_chromium_profile(
    profile: BrowserProfile,
    output_dir: Path,
    include_passwords: bool = False
) -> Dict[str, Any]:
    """High-level function to extract all data from a Chromium profile.
    
    Args:
        profile: BrowserProfile to extract from
        output_dir: Directory to write output files
        include_passwords: Whether to attempt password decryption
    
    Returns:
        Dictionary with extraction summary
    """
    summary = {
        "browser": profile.browser_type.value,
        "profile": profile.profile_name,
        "profile_path": str(profile.profile_path),
        "extraction_time": datetime.now(timezone.utc).isoformat(),
        "results": {},
        "errors": []
    }
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Extract SQLite data
    try:
        with ChromiumDatabaseExtractor(profile) as db_extractor:
            db_results = db_extractor.extract_all_forensic_data(output_dir)
            
            for category, results in db_results.items():
                summary["results"][category] = {
                    "files": [],
                    "total_rows": 0
                }
                for result in results:
                    if result.success and result.output_path:
                        summary["results"][category]["files"].append(
                            str(result.output_path.name)
                        )
                        summary["results"][category]["total_rows"] += result.rows_extracted
                    elif result.error:
                        summary["errors"].append(f"{category}/{result.query_name}: {result.error}")
    except Exception as e:
        summary["errors"].append(f"Database extraction failed: {e}")
    
    # Extract JSON data
    try:
        json_extractor = ChromiumJSONExtractor(profile)
        
        # Bookmarks
        bookmarks_path = output_dir / "bookmarks.csv"
        if json_extractor.export_bookmarks_to_csv(bookmarks_path):
            summary["results"]["Bookmarks"] = {"files": ["bookmarks.csv"]}
        
        # Extensions
        extensions_path = output_dir / "extensions.csv"
        if json_extractor.export_extensions_to_csv(extensions_path):
            summary["results"]["Extensions"] = {"files": ["extensions.csv"]}
        
    except Exception as e:
        summary["errors"].append(f"JSON extraction failed: {e}")
    
    # Save summary
    summary_path = output_dir / "extraction_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    
    return summary


# =============================================================================
# CLI for testing
# =============================================================================

if __name__ == "__main__":
    import sys
    from browser_profiles import detect_all_browsers, print_detected_browsers
    
    print_detected_browsers()
    
    # Find first Chromium browser for testing
    installations = detect_all_browsers()
    chromium_profile = None
    
    for inst in installations:
        if inst.browser_family == BrowserFamily.CHROMIUM and inst.profiles:
            chromium_profile = inst.profiles[0]
            break
    
    if chromium_profile:
        print(f"\nExtracting from: {chromium_profile.display_name}")
        print(f"Path: {chromium_profile.profile_path}")
        
        output = Path("./chromium_output")
        summary = extract_chromium_profile(chromium_profile, output)
        
        print(f"\nExtraction complete!")
        print(f"Output directory: {output}")
        print(f"Results: {json.dumps(summary['results'], indent=2)}")
        if summary["errors"]:
            print(f"Errors: {summary['errors']}")
    else:
        print("\nNo Chromium browsers found!")
