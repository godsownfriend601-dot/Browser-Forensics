#!/usr/bin/env python3
"""Chromium Password Decryption Module.

Decrypts saved passwords from Chromium-based browsers (Chrome, Edge, Brave, etc.).

Encryption methods by platform:
- Windows: DPAPI (Data Protection API) + AES-256-GCM (v10 format)
- Linux: PBKDF2 + AES-128-CBC with system keyring or 'peanuts' key
- macOS: PBKDF2 + AES-128-CBC with Keychain stored key

Password format versions:
- v10: AES-256-GCM with DPAPI-protected key (Windows)
- v11: AES-256-GCM with Keychain key (macOS)  
- v10/v11: AES-128-CBC with GNOME Keyring/libsecret (Linux)
- Legacy: Direct DPAPI encryption (older Chrome)

Requirements:
- Windows: No additional dependencies (uses ctypes for DPAPI)
- Linux: pycryptodome for AES (pip install pycryptodome)
- Linux with GNOME: secretstorage for keyring access
"""

import base64
import json
import os
import sqlite3
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any

# Platform-specific imports
if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes


@dataclass
class DecryptedCredential:
    """Represents a decrypted browser credential."""
    url: str
    username: str
    password: str
    signon_realm: str
    date_created: Optional[str] = None
    date_last_used: Optional[str] = None
    times_used: int = 0


class ChromiumDecryptionError(Exception):
    """Base exception for Chromium decryption errors."""
    pass


class EncryptionKeyNotFound(ChromiumDecryptionError):
    """Encryption key could not be found or extracted."""
    pass


class DecryptionFailed(ChromiumDecryptionError):
    """Password decryption failed."""
    pass


class UnsupportedPlatform(ChromiumDecryptionError):
    """Platform is not supported for decryption."""
    pass


class DependencyMissing(ChromiumDecryptionError):
    """Required dependency is not installed."""
    pass


# =============================================================================
# Windows DPAPI Functions
# =============================================================================

if sys.platform == "win32":
    
    class DATA_BLOB(ctypes.Structure):
        """Windows DATA_BLOB structure for DPAPI."""
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]
    
    def _win_dpapi_decrypt(encrypted_data: bytes) -> bytes:
        """Decrypt data using Windows DPAPI.
        
        Args:
            encrypted_data: DPAPI-encrypted bytes
        
        Returns:
            Decrypted bytes
        
        Raises:
            DecryptionFailed: If DPAPI decryption fails
        """
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        
        # Input blob
        input_blob = DATA_BLOB()
        input_blob.cbData = len(encrypted_data)
        input_blob.pbData = ctypes.cast(
            ctypes.create_string_buffer(encrypted_data, len(encrypted_data)),
            ctypes.POINTER(ctypes.c_char)
        )
        
        # Output blob
        output_blob = DATA_BLOB()
        
        # Call CryptUnprotectData
        result = crypt32.CryptUnprotectData(
            ctypes.byref(input_blob),
            None,  # description
            None,  # optional entropy
            None,  # reserved
            None,  # prompt struct
            0,     # flags
            ctypes.byref(output_blob)
        )
        
        if not result:
            raise DecryptionFailed(f"DPAPI decryption failed: {ctypes.GetLastError()}")
        
        # Extract decrypted data
        decrypted = ctypes.string_at(output_blob.pbData, output_blob.cbData)
        
        # Free the output buffer
        kernel32.LocalFree(output_blob.pbData)
        
        return decrypted


# =============================================================================
# AES Decryption Functions
# =============================================================================

def _aes_gcm_decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM encrypted data.
    
    Format: nonce (12 bytes) + ciphertext + tag (16 bytes)
    
    Args:
        encrypted_data: Encrypted bytes (nonce + ciphertext + tag)
        key: 32-byte AES key
    
    Returns:
        Decrypted bytes
    """
    try:
        from Crypto.Cipher import AES
    except ImportError:
        raise DependencyMissing(
            "pycryptodome is required for AES decryption. "
            "Install with: pip install pycryptodome"
        )
    
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:-16]
    tag = encrypted_data[-16:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def _aes_cbc_decrypt(encrypted_data: bytes, key: bytes, iv: bytes = None) -> bytes:
    """Decrypt AES-128-CBC encrypted data (Linux).
    
    Args:
        encrypted_data: Encrypted bytes
        key: 16-byte AES key
        iv: Initialization vector (default: 16 bytes of space)
    
    Returns:
        Decrypted bytes (PKCS7 padding removed)
    """
    try:
        from Crypto.Cipher import AES
    except ImportError:
        raise DependencyMissing(
            "pycryptodome is required for AES decryption. "
            "Install with: pip install pycryptodome"
        )
    
    if iv is None:
        iv = b" " * 16  # Chromium uses spaces as IV on Linux
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_data)
    
    # Remove PKCS7 padding
    padding_len = decrypted[-1]
    if padding_len < 16:
        decrypted = decrypted[:-padding_len]
    
    return decrypted


# =============================================================================
# Key Extraction Functions
# =============================================================================

def get_encryption_key_windows(user_data_dir: Path) -> bytes:
    """Extract and decrypt the AES key on Windows.
    
    The key is stored in Local State, encrypted with DPAPI.
    Format: "DPAPI" prefix (5 bytes) + DPAPI blob
    
    Args:
        user_data_dir: Path to browser's User Data directory
    
    Returns:
        32-byte AES decryption key
    """
    local_state_path = user_data_dir / "Local State"
    if not local_state_path.exists():
        raise EncryptionKeyNotFound(f"Local State not found: {local_state_path}")
    
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    
    encrypted_key_b64 = local_state.get("os_crypt", {}).get("encrypted_key")
    if not encrypted_key_b64:
        raise EncryptionKeyNotFound("encrypted_key not found in Local State")
    
    encrypted_key = base64.b64decode(encrypted_key_b64)
    
    # Remove "DPAPI" prefix
    if encrypted_key[:5] != b"DPAPI":
        raise EncryptionKeyNotFound("Invalid key format (missing DPAPI prefix)")
    
    encrypted_key = encrypted_key[5:]
    
    # Decrypt with DPAPI
    return _win_dpapi_decrypt(encrypted_key)


def get_encryption_key_linux(user_data_dir: Path) -> bytes:
    """Extract the AES key on Linux.
    
    Linux Chrome uses PBKDF2 to derive a key from:
    - GNOME Keyring stored password (if available)
    - Or the hardcoded password "peanuts"
    
    Args:
        user_data_dir: Path to browser's user data directory
    
    Returns:
        16-byte AES decryption key
    """
    try:
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Hash import SHA1
    except ImportError:
        raise DependencyMissing(
            "pycryptodome is required. Install with: pip install pycryptodome"
        )
    
    # Try to get password from GNOME Keyring
    password = None
    
    try:
        import secretstorage
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
        
        # Search for Chrome/Chromium password
        for item in collection.get_all_items():
            label = item.get_label().lower()
            if "chrome" in label or "chromium" in label:
                password = item.get_secret()
                break
        bus.close()
    except Exception:
        # secretstorage not available or keyring locked
        pass
    
    # Fall back to hardcoded password
    if password is None:
        password = b"peanuts"
    elif isinstance(password, str):
        password = password.encode("utf-8")
    
    # Derive key using PBKDF2
    # Chrome uses 1 iteration with SHA1
    key = PBKDF2(
        password,
        b"saltysalt",  # Fixed salt used by Chrome
        dkLen=16,
        count=1,
        hmac_hash_module=SHA1
    )
    
    return key


def get_encryption_key_macos(user_data_dir: Path) -> bytes:
    """Extract the AES key on macOS.
    
    macOS Chrome stores the key in Keychain.
    
    Args:
        user_data_dir: Path to browser's user data directory
    
    Returns:
        16-byte AES decryption key
    """
    try:
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Hash import SHA1
    except ImportError:
        raise DependencyMissing(
            "pycryptodome is required. Install with: pip install pycryptodome"
        )
    
    # Try to get password from Keychain using security command
    import subprocess
    
    # Different browsers use different service names
    service_names = [
        "Chrome Safe Storage",
        "Chromium Safe Storage", 
        "Microsoft Edge Safe Storage",
        "Brave Safe Storage",
        "Opera Safe Storage",
        "Vivaldi Safe Storage",
    ]
    
    password = None
    for service in service_names:
        try:
            result = subprocess.run(
                ["security", "find-generic-password", "-s", service, "-w"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                password = result.stdout.strip().encode("utf-8")
                break
        except Exception:
            continue
    
    if password is None:
        raise EncryptionKeyNotFound(
            "Could not retrieve password from macOS Keychain. "
            "You may need to unlock Keychain or grant access."
        )
    
    # Derive key using PBKDF2
    key = PBKDF2(
        password,
        b"saltysalt",
        dkLen=16,
        count=1003,  # macOS uses 1003 iterations
        hmac_hash_module=SHA1
    )
    
    return key


def get_encryption_key(user_data_dir: Path) -> bytes:
    """Get the encryption key for the current platform.
    
    Args:
        user_data_dir: Path to browser's User Data directory
    
    Returns:
        AES decryption key
    """
    if sys.platform == "win32":
        return get_encryption_key_windows(user_data_dir)
    elif sys.platform == "darwin":
        return get_encryption_key_macos(user_data_dir)
    else:  # Linux and others
        return get_encryption_key_linux(user_data_dir)


# =============================================================================
# Password Decryption Functions
# =============================================================================

def decrypt_password_windows(encrypted_password: bytes, key: bytes) -> str:
    """Decrypt a Chromium password on Windows.
    
    Handles both v10 (AES-GCM) and legacy (DPAPI) formats.
    
    Args:
        encrypted_password: Encrypted password bytes
        key: AES decryption key
    
    Returns:
        Decrypted password string
    """
    if not encrypted_password:
        return ""
    
    # v10 format: "v10" + nonce + ciphertext + tag
    if encrypted_password[:3] == b"v10":
        try:
            return _aes_gcm_decrypt(encrypted_password[3:], key).decode("utf-8")
        except Exception as e:
            raise DecryptionFailed(f"AES-GCM decryption failed: {e}")
    
    # Legacy format: Direct DPAPI
    try:
        return _win_dpapi_decrypt(encrypted_password).decode("utf-8")
    except Exception as e:
        raise DecryptionFailed(f"DPAPI decryption failed: {e}")


def decrypt_password_linux(encrypted_password: bytes, key: bytes) -> str:
    """Decrypt a Chromium password on Linux.
    
    Format: "v10" or "v11" prefix + encrypted data
    
    Args:
        encrypted_password: Encrypted password bytes
        key: AES decryption key (16 bytes)
    
    Returns:
        Decrypted password string
    """
    if not encrypted_password:
        return ""
    
    # v10/v11 format
    if encrypted_password[:3] in (b"v10", b"v11"):
        try:
            return _aes_cbc_decrypt(encrypted_password[3:], key).decode("utf-8")
        except Exception as e:
            raise DecryptionFailed(f"AES-CBC decryption failed: {e}")
    
    # Unencrypted (very old Chrome)
    return encrypted_password.decode("utf-8", errors="ignore")


def decrypt_password_macos(encrypted_password: bytes, key: bytes) -> str:
    """Decrypt a Chromium password on macOS.
    
    Args:
        encrypted_password: Encrypted password bytes
        key: AES decryption key (16 bytes)
    
    Returns:
        Decrypted password string
    """
    if not encrypted_password:
        return ""
    
    # v10 format
    if encrypted_password[:3] == b"v10":
        try:
            return _aes_cbc_decrypt(encrypted_password[3:], key).decode("utf-8")
        except Exception as e:
            raise DecryptionFailed(f"AES-CBC decryption failed: {e}")
    
    return encrypted_password.decode("utf-8", errors="ignore")


def decrypt_password(encrypted_password: bytes, key: bytes) -> str:
    """Decrypt a password using the appropriate method for this platform.
    
    Args:
        encrypted_password: Encrypted password bytes from database
        key: Decryption key
    
    Returns:
        Decrypted password string
    """
    if sys.platform == "win32":
        return decrypt_password_windows(encrypted_password, key)
    elif sys.platform == "darwin":
        return decrypt_password_macos(encrypted_password, key)
    else:
        return decrypt_password_linux(encrypted_password, key)


# =============================================================================
# Main Decryption Function
# =============================================================================

def decrypt_chromium_passwords(
    profile_path: Path,
    user_data_dir: Path,
    master_password: Optional[str] = None
) -> Tuple[List[DecryptedCredential], List[str]]:
    """Decrypt all saved passwords from a Chromium profile.
    
    Args:
        profile_path: Path to browser profile directory
        user_data_dir: Path to User Data directory (contains Local State)
        master_password: Not used for Chromium (kept for API compatibility)
    
    Returns:
        Tuple of (list of DecryptedCredential, list of error messages)
    """
    credentials: List[DecryptedCredential] = []
    errors: List[str] = []
    
    login_data_path = profile_path / "Login Data"
    if not login_data_path.exists():
        errors.append(f"Login Data not found: {login_data_path}")
        return credentials, errors
    
    # Get decryption key
    try:
        key = get_encryption_key(user_data_dir)
    except (EncryptionKeyNotFound, DependencyMissing) as e:
        errors.append(str(e))
        return credentials, errors
    
    # Copy database to temp location (it may be locked)
    temp_dir = Path(tempfile.mkdtemp(prefix="chromium_passwords_"))
    temp_db = temp_dir / "Login Data"
    
    try:
        shutil.copy2(login_data_path, temp_db)
        
        # Also copy WAL file if exists
        wal_path = login_data_path.parent / "Login Data-wal"
        if wal_path.exists():
            shutil.copy2(wal_path, temp_dir / "Login Data-wal")
        
        # Connect and extract
        conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
        cursor = conn.cursor()
        
        # Query for logins
        cursor.execute("""
            SELECT 
                origin_url,
                action_url,
                username_value,
                password_value,
                signon_realm,
                date_created,
                date_last_used,
                times_used
            FROM logins
            WHERE blacklisted_by_user = 0
        """)
        
        for row in cursor.fetchall():
            origin_url = row[0] or ""
            action_url = row[1] or ""
            username = row[2] or ""
            encrypted_password = row[3]
            signon_realm = row[4] or ""
            date_created = row[5]
            date_last_used = row[6]
            times_used = row[7] or 0
            
            # Decrypt password
            try:
                password = decrypt_password(encrypted_password, key) if encrypted_password else ""
            except DecryptionFailed as e:
                errors.append(f"Failed to decrypt password for {origin_url}: {e}")
                password = "[DECRYPTION FAILED]"
            
            # Convert timestamps
            from sql_queries import webkit_to_unix
            from datetime import datetime, timezone
            
            created_str = ""
            if date_created:
                try:
                    unix_ts = webkit_to_unix(date_created)
                    if unix_ts > 0:
                        created_str = datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
                except (ValueError, OSError):
                    pass
            
            last_used_str = ""
            if date_last_used:
                try:
                    unix_ts = webkit_to_unix(date_last_used)
                    if unix_ts > 0:
                        last_used_str = datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
                except (ValueError, OSError):
                    pass
            
            credentials.append(DecryptedCredential(
                url=action_url or origin_url,
                username=username,
                password=password,
                signon_realm=signon_realm,
                date_created=created_str,
                date_last_used=last_used_str,
                times_used=times_used
            ))
        
        conn.close()
        
    except sqlite3.Error as e:
        errors.append(f"Database error: {e}")
    except Exception as e:
        errors.append(f"Unexpected error: {e}")
    finally:
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    return credentials, errors


def check_decryption_requirements() -> Tuple[bool, List[str]]:
    """Check if all requirements for password decryption are met.
    
    Returns:
        Tuple of (requirements_met, list of missing items)
    """
    missing = []
    
    # Check for pycryptodome
    try:
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
    except ImportError:
        missing.append("pycryptodome (pip install pycryptodome)")
    
    # Linux-specific checks
    if sys.platform == "linux":
        try:
            import secretstorage
        except ImportError:
            missing.append("secretstorage (pip install secretstorage) - optional, for GNOME keyring")
    
    return len(missing) == 0, missing


# =============================================================================
# CLI for testing
# =============================================================================

if __name__ == "__main__":
    from browser_profiles import detect_all_browsers, BrowserFamily
    
    print("Chromium Password Decryption Test")
    print("=" * 50)
    
    # Check requirements
    reqs_met, missing = check_decryption_requirements()
    if not reqs_met:
        print(f"Missing requirements: {missing}")
        print("Some features may not work.")
    
    # Find a Chromium browser
    installations = detect_all_browsers()
    
    for inst in installations:
        if inst.browser_family == BrowserFamily.CHROMIUM and inst.profiles:
            profile = inst.profiles[0]
            print(f"\nTesting with: {profile.display_name}")
            print(f"Profile path: {profile.profile_path}")
            print(f"User data dir: {profile.user_data_dir}")
            
            try:
                credentials, errors = decrypt_chromium_passwords(
                    profile.profile_path,
                    profile.user_data_dir
                )
                
                print(f"\nDecrypted {len(credentials)} credentials")
                
                for cred in credentials[:5]:  # Show first 5
                    print(f"  - {cred.signon_realm}")
                    print(f"    User: {cred.username}")
                    print(f"    Pass: {'*' * len(cred.password) if cred.password else '[empty]'}")
                
                if len(credentials) > 5:
                    print(f"  ... and {len(credentials) - 5} more")
                
                if errors:
                    print(f"\nErrors: {errors}")
                    
            except Exception as e:
                print(f"Error: {e}")
            
            break
    else:
        print("No Chromium browsers found!")
