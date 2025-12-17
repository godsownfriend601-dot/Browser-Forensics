"""Forensic SQL queries for Chromium-based browser profile extraction.

Chromium browsers (Chrome, Edge, Brave, Opera, Vivaldi) use WebKit timestamps:
- Microseconds since January 1, 1601 (Windows FILETIME epoch)
- To convert to Unix timestamp: (webkit_ts / 1000000) - 11644473600

Database files:
- History: browsing history, downloads, keywords
- Cookies: session and persistent cookies
- Login Data: encrypted saved passwords
- Web Data: autofill, credit cards, addresses
"""

# =============================================================================
# WebKit Timestamp Conversion
# =============================================================================
# Chromium uses WebKit timestamps (microseconds since 1601-01-01)
# Unix epoch is 1970-01-01
# Difference: 11644473600 seconds

WEBKIT_TO_UNIX = 11644473600

# =============================================================================
# History Database Queries
# =============================================================================

CHROMIUM_HISTORY_ALL = """
SELECT 
    u.id,
    u.url,
    u.title,
    datetime((v.visit_time / 1000000) - 11644473600, 'unixepoch') as visit_time_utc,
    v.visit_time as visit_time_raw,
    CASE v.transition & 0xFF
        WHEN 0 THEN 'link'
        WHEN 1 THEN 'typed'
        WHEN 2 THEN 'auto_bookmark'
        WHEN 3 THEN 'auto_subframe'
        WHEN 4 THEN 'manual_subframe'
        WHEN 5 THEN 'generated'
        WHEN 6 THEN 'auto_toplevel'
        WHEN 7 THEN 'form_submit'
        WHEN 8 THEN 'reload'
        WHEN 9 THEN 'keyword'
        WHEN 10 THEN 'keyword_generated'
        ELSE 'other'
    END as transition_type,
    CASE 
        WHEN v.transition & 0x10000000 THEN 'blocked'
        WHEN v.transition & 0x20000000 THEN 'forward_back'
        WHEN v.transition & 0x40000000 THEN 'from_address_bar'
        WHEN v.transition & 0x80000000 THEN 'home_page'
        ELSE ''
    END as transition_qualifier,
    u.visit_count,
    u.typed_count,
    datetime((u.last_visit_time / 1000000) - 11644473600, 'unixepoch') as last_visit_utc,
    u.hidden
FROM visits v
JOIN urls u ON v.url = u.id
ORDER BY v.visit_time DESC
"""

CHROMIUM_HISTORY_RECENT_24H = """
SELECT 
    u.url,
    u.title,
    datetime((v.visit_time / 1000000) - 11644473600, 'unixepoch') as visit_time_utc,
    CASE v.transition & 0xFF
        WHEN 1 THEN 'User Typed'
        WHEN 0 THEN 'Link Clicked'
        WHEN 7 THEN 'Form Submit'
        ELSE 'Other'
    END as user_action
FROM visits v
JOIN urls u ON v.url = u.id
WHERE v.visit_time > ((strftime('%s', 'now') + 11644473600) * 1000000 - 86400000000)
ORDER BY v.visit_time DESC
"""

CHROMIUM_TOP_SITES = """
SELECT 
    url,
    title,
    visit_count,
    typed_count,
    datetime((last_visit_time / 1000000) - 11644473600, 'unixepoch') as last_visit_utc,
    hidden
FROM urls
WHERE url NOT LIKE 'chrome://%'
    AND url NOT LIKE 'chrome-extension://%'
    AND url NOT LIKE 'edge://%'
    AND url NOT LIKE 'brave://%'
ORDER BY visit_count DESC
LIMIT 200
"""

CHROMIUM_TYPED_URLS = """
SELECT 
    url,
    title,
    typed_count,
    visit_count,
    datetime((last_visit_time / 1000000) - 11644473600, 'unixepoch') as last_visit_utc
FROM urls
WHERE typed_count > 0
ORDER BY typed_count DESC, last_visit_time DESC
"""

CHROMIUM_SEARCH_QUERIES = """
SELECT DISTINCT
    u.url,
    u.title,
    u.visit_count,
    datetime((u.last_visit_time / 1000000) - 11644473600, 'unixepoch') as last_visit_utc
FROM urls u
WHERE u.url LIKE '%google.com/search%'
    OR u.url LIKE '%bing.com/search%'
    OR u.url LIKE '%duckduckgo.com/%'
    OR u.url LIKE '%search.yahoo.com%'
    OR u.url LIKE '%ecosia.org/search%'
    OR u.url LIKE '%startpage.com%'
    OR u.url LIKE '%searx%'
ORDER BY u.last_visit_time DESC
"""

# =============================================================================
# Downloads Queries
# =============================================================================

CHROMIUM_DOWNLOADS_ALL = """
SELECT 
    d.id,
    d.target_path,
    d.start_time,
    datetime((d.start_time / 1000000) - 11644473600, 'unixepoch') as start_time_utc,
    datetime((d.end_time / 1000000) - 11644473600, 'unixepoch') as end_time_utc,
    d.received_bytes,
    d.total_bytes,
    CASE d.state
        WHEN 0 THEN 'in_progress'
        WHEN 1 THEN 'complete'
        WHEN 2 THEN 'cancelled'
        WHEN 3 THEN 'interrupted'
        ELSE 'unknown'
    END as state,
    CASE d.danger_type
        WHEN 0 THEN 'not_dangerous'
        WHEN 1 THEN 'dangerous_file'
        WHEN 2 THEN 'dangerous_url'
        WHEN 3 THEN 'dangerous_content'
        WHEN 4 THEN 'maybe_dangerous'
        WHEN 5 THEN 'uncommon_content'
        WHEN 6 THEN 'user_validated'
        WHEN 7 THEN 'dangerous_host'
        WHEN 8 THEN 'potentially_unwanted'
        WHEN 9 THEN 'allowlisted_by_policy'
        ELSE 'unknown'
    END as danger_type,
    d.opened,
    d.last_access_time,
    d.mime_type,
    d.original_mime_type,
    dc.url as download_url
FROM downloads d
LEFT JOIN downloads_url_chains dc ON d.id = dc.id AND dc.chain_index = 0
ORDER BY d.start_time DESC
"""

CHROMIUM_DOWNLOADS_DANGEROUS = """
SELECT 
    d.target_path,
    datetime((d.start_time / 1000000) - 11644473600, 'unixepoch') as download_time,
    d.total_bytes,
    CASE d.danger_type
        WHEN 1 THEN 'dangerous_file'
        WHEN 2 THEN 'dangerous_url'
        WHEN 3 THEN 'dangerous_content'
        WHEN 7 THEN 'dangerous_host'
        WHEN 8 THEN 'potentially_unwanted'
        ELSE 'other_danger'
    END as danger_type,
    dc.url as download_url
FROM downloads d
LEFT JOIN downloads_url_chains dc ON d.id = dc.id AND dc.chain_index = 0
WHERE d.danger_type > 0
ORDER BY d.start_time DESC
"""

# =============================================================================
# Cookies Database Queries
# =============================================================================

CHROMIUM_COOKIES_ALL = """
SELECT 
    host_key,
    name,
    path,
    datetime((creation_utc / 1000000) - 11644473600, 'unixepoch') as created_utc,
    datetime((expires_utc / 1000000) - 11644473600, 'unixepoch') as expires_utc,
    datetime((last_access_utc / 1000000) - 11644473600, 'unixepoch') as last_access_utc,
    is_secure,
    is_httponly,
    CASE samesite
        WHEN 0 THEN 'no_restriction'
        WHEN 1 THEN 'lax'
        WHEN 2 THEN 'strict'
        ELSE 'unknown'
    END as samesite,
    is_persistent,
    priority,
    source_scheme
FROM cookies
ORDER BY last_access_utc DESC
"""

CHROMIUM_COOKIES_SESSION = """
SELECT 
    host_key,
    name,
    path,
    datetime((creation_utc / 1000000) - 11644473600, 'unixepoch') as created_utc,
    datetime((last_access_utc / 1000000) - 11644473600, 'unixepoch') as last_access_utc,
    is_secure,
    is_httponly
FROM cookies
WHERE is_persistent = 0 OR expires_utc = 0
ORDER BY last_access_utc DESC
"""

CHROMIUM_COOKIES_BY_DOMAIN = """
SELECT 
    host_key,
    COUNT(*) as cookie_count,
    MAX(datetime((last_access_utc / 1000000) - 11644473600, 'unixepoch')) as last_access,
    SUM(is_secure) as secure_count,
    SUM(is_httponly) as httponly_count
FROM cookies
GROUP BY host_key
ORDER BY cookie_count DESC
LIMIT 100
"""

# =============================================================================
# Login Data (Passwords) Queries
# Note: password_value is encrypted and needs DPAPI/AES decryption
# =============================================================================

CHROMIUM_LOGINS_ALL = """
SELECT 
    origin_url,
    action_url,
    username_element,
    username_value,
    password_element,
    password_value,
    signon_realm,
    datetime((date_created / 1000000) - 11644473600, 'unixepoch') as created_utc,
    datetime((date_last_used / 1000000) - 11644473600, 'unixepoch') as last_used_utc,
    datetime((date_password_modified / 1000000) - 11644473600, 'unixepoch') as password_modified_utc,
    times_used,
    blacklisted_by_user,
    scheme
FROM logins
ORDER BY date_last_used DESC
"""

CHROMIUM_LOGINS_SUMMARY = """
SELECT 
    signon_realm,
    origin_url,
    username_value,
    datetime((date_created / 1000000) - 11644473600, 'unixepoch') as created_utc,
    datetime((date_last_used / 1000000) - 11644473600, 'unixepoch') as last_used_utc,
    times_used
FROM logins
WHERE blacklisted_by_user = 0
ORDER BY times_used DESC, date_last_used DESC
"""

CHROMIUM_BLACKLISTED_SITES = """
SELECT 
    origin_url,
    signon_realm,
    datetime((date_created / 1000000) - 11644473600, 'unixepoch') as blacklisted_date
FROM logins
WHERE blacklisted_by_user = 1
ORDER BY date_created DESC
"""

# =============================================================================
# Web Data (Autofill) Queries
# =============================================================================

CHROMIUM_AUTOFILL_ALL = """
SELECT 
    name,
    value,
    count,
    datetime((date_created / 1000000) - 11644473600, 'unixepoch') as first_used_utc,
    datetime((date_last_used / 1000000) - 11644473600, 'unixepoch') as last_used_utc
FROM autofill
ORDER BY count DESC, date_last_used DESC
"""

CHROMIUM_AUTOFILL_EMAILS = """
SELECT DISTINCT
    value as email,
    count as times_used,
    datetime((date_last_used / 1000000) - 11644473600, 'unixepoch') as last_used_utc
FROM autofill
WHERE name LIKE '%email%' 
    OR name LIKE '%mail%'
    OR value LIKE '%@%.%'
ORDER BY count DESC
"""

CHROMIUM_AUTOFILL_NAMES = """
SELECT DISTINCT
    name as field_name,
    value,
    count as times_used
FROM autofill
WHERE name LIKE '%name%'
    OR name LIKE '%first%'
    OR name LIKE '%last%'
    OR name LIKE '%full%'
ORDER BY count DESC
"""

CHROMIUM_AUTOFILL_PROFILE = """
SELECT 
    guid,
    company_name,
    street_address,
    city,
    state,
    zipcode,
    country_code,
    datetime((date_modified / 1000000) - 11644473600, 'unixepoch') as modified_utc,
    use_count,
    datetime((use_date / 1000000) - 11644473600, 'unixepoch') as last_used_utc
FROM autofill_profiles
ORDER BY use_count DESC
"""

CHROMIUM_CREDIT_CARDS = """
SELECT 
    guid,
    name_on_card,
    expiration_month,
    expiration_year,
    datetime((date_modified / 1000000) - 11644473600, 'unixepoch') as modified_utc,
    origin,
    use_count,
    datetime((use_date / 1000000) - 11644473600, 'unixepoch') as last_used_utc,
    billing_address_id
FROM credit_cards
ORDER BY use_count DESC
"""

# Note: card_number_encrypted needs decryption - similar to passwords

# =============================================================================
# Keywords (Search Engines) Queries
# =============================================================================

CHROMIUM_SEARCH_ENGINES = """
SELECT 
    short_name,
    keyword,
    url,
    favicon_url,
    datetime((date_created / 1000000) - 11644473600, 'unixepoch') as created_utc,
    datetime((last_modified / 1000000) - 11644473600, 'unixepoch') as modified_utc,
    usage_count,
    is_active
FROM keywords
WHERE url != ''
ORDER BY usage_count DESC
"""

CHROMIUM_DEFAULT_SEARCH = """
SELECT 
    short_name,
    keyword,
    url,
    usage_count
FROM keywords
WHERE is_active = 1
ORDER BY usage_count DESC
LIMIT 1
"""

# =============================================================================
# Segment Usage (Visit Patterns) Queries
# =============================================================================

CHROMIUM_SEGMENT_USAGE = """
SELECT 
    s.name as segment_name,
    su.visit_count,
    datetime((su.time_slot / 1000000) - 11644473600, 'unixepoch') as time_slot_utc,
    u.url
FROM segments s
JOIN segment_usage su ON s.id = su.segment_id
LEFT JOIN urls u ON s.url_id = u.id
ORDER BY su.visit_count DESC
LIMIT 500
"""

# =============================================================================
# Query Registry for Chromium browsers
# =============================================================================

CHROMIUM_QUERY_REGISTRY = {
    "History": {
        "database": "History",
        "queries": {
            "browsing_history": {
                "name": "Complete Browsing History",
                "query": CHROMIUM_HISTORY_ALL,
                "description": "All visited URLs with timestamps and transition types"
            },
            "recent_24h": {
                "name": "Recent Activity (24h)",
                "query": CHROMIUM_HISTORY_RECENT_24H,
                "description": "Browsing activity in the last 24 hours"
            },
            "top_sites": {
                "name": "Most Visited Sites",
                "query": CHROMIUM_TOP_SITES,
                "description": "Top 200 most frequently visited URLs"
            },
            "typed_urls": {
                "name": "Typed URLs",
                "query": CHROMIUM_TYPED_URLS,
                "description": "URLs manually typed in address bar"
            },
            "search_queries": {
                "name": "Search Queries",
                "query": CHROMIUM_SEARCH_QUERIES,
                "description": "Search engine queries"
            },
        }
    },
    "Downloads": {
        "database": "History",
        "queries": {
            "all_downloads": {
                "name": "All Downloads",
                "query": CHROMIUM_DOWNLOADS_ALL,
                "description": "Complete download history with status"
            },
            "dangerous_downloads": {
                "name": "Dangerous Downloads",
                "query": CHROMIUM_DOWNLOADS_DANGEROUS,
                "description": "Downloads flagged as potentially dangerous"
            },
        }
    },
    "Cookies": {
        "database": "Cookies",
        "queries": {
            "all_cookies": {
                "name": "All Cookies",
                "query": CHROMIUM_COOKIES_ALL,
                "description": "Complete cookie data"
            },
            "session_cookies": {
                "name": "Session Cookies",
                "query": CHROMIUM_COOKIES_SESSION,
                "description": "Non-persistent session cookies"
            },
            "cookies_by_domain": {
                "name": "Cookies by Domain",
                "query": CHROMIUM_COOKIES_BY_DOMAIN,
                "description": "Cookie count per domain"
            },
        }
    },
    "Logins": {
        "database": "Login Data",
        "queries": {
            "all_logins": {
                "name": "Saved Logins",
                "query": CHROMIUM_LOGINS_ALL,
                "description": "All saved login credentials (encrypted)"
            },
            "login_summary": {
                "name": "Login Summary",
                "query": CHROMIUM_LOGINS_SUMMARY,
                "description": "Summary of saved login sites"
            },
            "blacklisted_sites": {
                "name": "Never Save Sites",
                "query": CHROMIUM_BLACKLISTED_SITES,
                "description": "Sites where password saving was declined"
            },
        }
    },
    "Autofill": {
        "database": "Web Data",
        "queries": {
            "all_autofill": {
                "name": "All Autofill Data",
                "query": CHROMIUM_AUTOFILL_ALL,
                "description": "All form autofill entries"
            },
            "autofill_emails": {
                "name": "Autofill Emails",
                "query": CHROMIUM_AUTOFILL_EMAILS,
                "description": "Email addresses from autofill"
            },
            "autofill_names": {
                "name": "Autofill Names",
                "query": CHROMIUM_AUTOFILL_NAMES,
                "description": "Names from autofill data"
            },
            "autofill_profiles": {
                "name": "Address Profiles",
                "query": CHROMIUM_AUTOFILL_PROFILE,
                "description": "Saved address profiles"
            },
            "credit_cards": {
                "name": "Credit Cards",
                "query": CHROMIUM_CREDIT_CARDS,
                "description": "Saved credit card info (number encrypted)"
            },
        }
    },
    "SearchEngines": {
        "database": "Web Data",
        "queries": {
            "search_engines": {
                "name": "Search Engines",
                "query": CHROMIUM_SEARCH_ENGINES,
                "description": "Configured search engines"
            },
            "default_search": {
                "name": "Default Search Engine",
                "query": CHROMIUM_DEFAULT_SEARCH,
                "description": "Currently active default search"
            },
        }
    },
}


def get_webkit_timestamp_now() -> int:
    """Get current time as WebKit timestamp."""
    import time
    return int((time.time() + WEBKIT_TO_UNIX) * 1000000)


def webkit_to_unix(webkit_ts: int) -> float:
    """Convert WebKit timestamp to Unix timestamp."""
    return (webkit_ts / 1000000) - WEBKIT_TO_UNIX


def unix_to_webkit(unix_ts: float) -> int:
    """Convert Unix timestamp to WebKit timestamp."""
    return int((unix_ts + WEBKIT_TO_UNIX) * 1000000)
