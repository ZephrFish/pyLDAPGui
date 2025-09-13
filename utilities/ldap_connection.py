import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE
from typing import Optional, List, Dict, Any, Tuple, Set
import ssl
import socket
import time
import hashlib
import json
from collections import defaultdict
import logging
from datetime import datetime
import random  # for opsec randomization

# Check if SOCKS proxy support is available
try:
    import python_socks.sync as socks_sync
    from python_socks import ProxyType
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False


class SOCKSSocket:
    """Custom socket wrapper for SOCKS proxy support"""
    def __init__(self, proxy_type: str, proxy_host: str, proxy_port: int, 
                 proxy_username: Optional[str] = None, proxy_password: Optional[str] = None):
        self.proxy_type = proxy_type
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self._socket = None
        
    def connect(self, address: Tuple[str, int]):
        """Connect through SOCKS proxy"""
        if not HAS_SOCKS:
            raise ImportError("python-socks library required for SOCKS proxy support. Install with: pip install python-socks[asyncio]")
            
        # Map proxy type
        proxy_type_map = {
            'SOCKS4': ProxyType.SOCKS4,
            'SOCKS5': ProxyType.SOCKS5,
            'HTTP': ProxyType.HTTP
        }
        
        proxy_type_enum = proxy_type_map.get(self.proxy_type.upper(), ProxyType.SOCKS5)
        
        # Create connection through proxy
        self._socket = socks_sync.Proxy.create(
            proxy_type=proxy_type_enum,
            host=self.proxy_host,
            port=self.proxy_port,
            username=self.proxy_username,
            password=self.proxy_password
        )
        
        # Connect to target through proxy
        self._socket.connect(dest_host=address[0], dest_port=address[1])
        
    def __getattr__(self, name):
        """Delegate all other methods to the underlying socket"""
        if self._socket is None:
            raise RuntimeError("Socket not connected")
        return getattr(self._socket, name)


class LDAPConnection:
    def __init__(self):
        self.connection: Optional[Connection] = None
        self.server: Optional[Server] = None
        self.base_dn: Optional[str] = None
        self._cache = {}  # Simple cache for queries
        self._cache_ttl = 1800  # bumped to 30min, helps with large exports
        self._last_cache_clear = time.time()
        self._page_size = 1000  # Default page size for paged searches
        self._max_retries = 3  # Max retries for failed queries
        self._batch_cache = defaultdict(list)  # Cache for batch queries
        
        # OpSec settings - on by default for safety
        self._opsec_enabled = True  # randomise queries to avoid detection
        self._min_query_delay = 0.5  # min delay between queries 
        self._max_query_delay = 2.0  # max delay - adjust based on your needs
        
        # Throttling settings for stealth/performance
        self._throttle_enabled = True  # pace queries to look human
        self._queries_per_minute = 30  # max 30 queries/min when throttled
        self._query_timestamps = []  # track query times for throttling
        self._burst_size = 5  # allow small bursts before throttling
        
        # Enhanced caching for large domains
        self._cache_size_mb = 100  # max cache size in MB
        self._cache_stats = {'hits': 0, 'misses': 0, 'evictions': 0}
        self._persistent_cache_enabled = False  # can enable disk caching
        self._cache_file = ".ldap_cache.db"  # persistent cache file
        
        # Debug logging setup
        self.debug_mode = False
        self.query_log = []  # Store query history
        self.logger = logging.getLogger('LDAPConnection')
        self.logger.setLevel(logging.DEBUG)
        
    @staticmethod
    def has_socks_support() -> bool:
        """Check if SOCKS proxy support is available"""
        return HAS_SOCKS
        
    def connect(self, host: str, username: str, password: str, use_ssl: bool = False, 
                port: Optional[int] = None, proxy_settings: Optional[Dict[str, Any]] = None) -> bool:
        """
        Establish connection to LDAP server
        
        Args:
            host: LDAP server hostname or IP
            username: Authentication username
            password: Authentication password
            use_ssl: Whether to use SSL/TLS
            port: Custom port (defaults to 389/636)
            proxy_settings: Dict with proxy configuration:
                {
                    'enabled': bool,
                    'type': 'SOCKS4' | 'SOCKS5' | 'HTTP',
                    'host': str,
                    'port': int,
                    'username': str (optional),
                    'password': str (optional)
                }
        """
        try:
            if port is None:
                port = 636 if use_ssl else 389
                
            tls = ldap3.Tls(validate=ssl.CERT_NONE) if use_ssl else None
            
            # Check if we need to use proxy
            if proxy_settings and proxy_settings.get('enabled'):
                if not HAS_SOCKS:
                    raise ImportError("SOCKS proxy support requires python-socks library. Install with: pip install python-socks[asyncio]")
                
                # Create custom socket factory for proxy
                def socket_factory(address):
                    sock = SOCKSSocket(
                        proxy_type=proxy_settings.get('type', 'SOCKS5'),
                        proxy_host=proxy_settings['host'],
                        proxy_port=proxy_settings['port'],
                        proxy_username=proxy_settings.get('username'),
                        proxy_password=proxy_settings.get('password')
                    )
                    sock.connect((address[0], address[1]))
                    return sock._socket
                
                # Create server with custom socket
                self.server = Server(
                    host,
                    port=port,
                    use_ssl=use_ssl,
                    tls=tls,
                    get_info=ALL,
                    connect_timeout=30  # Increase timeout for proxy connections
                )
                
                # Create connection with custom socket
                self.connection = Connection(
                    self.server,
                    user=username,
                    password=password,
                    auto_bind=True,
                    authentication=ldap3.SIMPLE,
                    socket=socket_factory
                )
            else:
                # Standard connection without proxy
                self.server = Server(
                    host,
                    port=port,
                    use_ssl=use_ssl,
                    tls=tls,
                    get_info=ALL
                )
                
                self.connection = Connection(
                    self.server,
                    user=username,
                    password=password,
                    auto_bind=True,
                    authentication=ldap3.SIMPLE
                )
            
            # Auto-discover base DN
            self.base_dn = self._discover_base_dn()
            
            return True
            
        except Exception as e:
            print(f"Connection error: {str(e)}")
            return False
    
    def _discover_base_dn(self) -> Optional[str]:
        """
        Auto-discover the base DN from the root DSE
        """
        if not self.connection:
            return None
            
        try:
            if self.server.info.naming_contexts:
                return str(self.server.info.naming_contexts[0])
        except:
            pass
            
        return None
    
    def get_server_info(self) -> Dict[str, Any]:
        """
        Get server information and capabilities
        """
        if not self.server:
            return {}
            
        info = {
            'server': str(self.server),
            'naming_contexts': list(self.server.info.naming_contexts) if self.server.info.naming_contexts else [],
            'supported_controls': list(self.server.info.supported_controls) if self.server.info.supported_controls else [],
            'supported_extensions': list(self.server.info.supported_extensions) if self.server.info.supported_extensions else [],
            'supported_features': list(self.server.info.supported_features) if self.server.info.supported_features else [],
            'supported_ldap_versions': list(self.server.info.supported_ldap_versions) if self.server.info.supported_ldap_versions else [],
            'supported_sasl_mechanisms': list(self.server.info.supported_sasl_mechanisms) if self.server.info.supported_sasl_mechanisms else []
        }
        
        return info
    
    def _get_cache_key(self, base_dn: str, search_filter: str, attributes: List[str], scope: str) -> str:
        """Generate cache key for a search query"""
        attrs_str = ','.join(sorted(attributes)) if attributes else ''
        key_parts = [base_dn, search_filter, attrs_str, str(scope)]
        return hashlib.md5('|'.join(key_parts).encode()).hexdigest()
    
    def _clean_cache(self):
        """Remove expired cache entries and handle size limits"""
        current_time = time.time()
        
        # Remove expired entries
        if current_time - self._last_cache_clear > self._cache_ttl:
            expired_keys = []
            for key, (timestamp, _) in self._cache.items():
                if current_time - timestamp > self._cache_ttl:
                    expired_keys.append(key)
                    self._cache_stats['evictions'] += 1
            for key in expired_keys:
                del self._cache[key]
            self._last_cache_clear = current_time
        
        # Check cache size limit (rough estimate)
        cache_size_estimate = sum(len(str(v)) for v in self._cache.values()) / (1024 * 1024)
        if cache_size_estimate > self._cache_size_mb:
            # Remove oldest entries until under limit
            sorted_entries = sorted(self._cache.items(), key=lambda x: x[1][0])
            while cache_size_estimate > self._cache_size_mb * 0.8 and sorted_entries:  # 80% threshold
                oldest_key, _ = sorted_entries.pop(0)
                del self._cache[oldest_key]
                self._cache_stats['evictions'] += 1
                cache_size_estimate = sum(len(str(v)) for v in self._cache.values()) / (1024 * 1024)
    
    def _apply_throttle(self):
        """Apply query throttling to avoid detection
        
        Implements a token bucket algorithm with burst capability
        """
        current_time = time.time()
        
        # Clean old timestamps (older than 1 minute)
        self._query_timestamps = [t for t in self._query_timestamps if current_time - t < 60]
        
        # Check if we're exceeding rate limit
        if len(self._query_timestamps) >= self._queries_per_minute:
            # Calculate how long to wait
            oldest_in_window = self._query_timestamps[0]
            wait_time = 60 - (current_time - oldest_in_window)
            
            if wait_time > 0:
                # Add some jitter to look more human
                jitter = random.uniform(0, 0.5)
                actual_wait = wait_time + jitter
                
                if self.debug_mode:
                    self.logger.info(f"Throttling: waiting {actual_wait:.2f}s to stay under {self._queries_per_minute} queries/min")
                
                time.sleep(actual_wait)
                current_time = time.time()
        
        # Check burst limit
        recent_queries = [t for t in self._query_timestamps if current_time - t < 10]  # last 10 seconds
        if len(recent_queries) >= self._burst_size:
            # Small delay to prevent bursts
            burst_delay = random.uniform(1.0, 2.0)
            if self.debug_mode:
                self.logger.info(f"Burst limit reached, waiting {burst_delay:.2f}s")
            time.sleep(burst_delay)
        
        # Record this query
        self._query_timestamps.append(time.time())
    
    def clear_cache(self):
        """Clear all cached results"""
        self._cache.clear()
        self._batch_cache.clear()
        self._last_cache_clear = time.time()
        self._cache_stats = {'hits': 0, 'misses': 0, 'evictions': 0}
    
    def set_debug_mode(self, enabled: bool):
        """Enable or disable debug mode for query logging"""
        self.debug_mode = enabled
        if enabled:
            self.logger.info("LDAP debug mode enabled")
        else:
            self.logger.info("LDAP debug mode disabled")
    
    def get_query_log(self) -> List[Dict[str, Any]]:
        """Get the query log entries"""
        return self.query_log.copy()
    
    def clear_query_log(self):
        """Clear the query log"""
        self.query_log.clear()
        self.logger.info("Query log cleared")
    
    def _log_query(self, query_type: str, params: Dict[str, Any], result_count: int, 
                   duration: float, cache_hit: bool = False):
        """Log a query for debugging purposes"""
        if not self.debug_mode:
            return
            
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': query_type,
            'params': params,
            'result_count': result_count,
            'duration_ms': round(duration * 1000, 2),
            'cache_hit': cache_hit
        }
        
        self.query_log.append(log_entry)
        
        # Also log to logger
        self.logger.debug(f"LDAP Query: {query_type} | "
                         f"Filter: {params.get('filter', 'N/A')} | "
                         f"Base: {params.get('base_dn', 'N/A')} | "
                         f"Results: {result_count} | "
                         f"Duration: {log_entry['duration_ms']}ms | "
                         f"Cache: {'HIT' if cache_hit else 'MISS'}")
    
    def search(self, base_dn: str = None, search_filter: str = '(objectClass=*)', 
               attributes: List[str] = None, scope: str = SUBTREE, size_limit: int = 1000,
               use_cache: bool = True, paged_search: bool = True) -> List[Dict[str, Any]]:
        """
        Perform LDAP search with caching and paged search support
        
        Args:
            base_dn: Base DN for search
            search_filter: LDAP search filter
            attributes: List of attributes to retrieve
            scope: Search scope (SUBTREE, LEVEL, BASE)
            size_limit: Maximum number of entries to return
            use_cache: Whether to use caching
            paged_search: Whether to use paged searches for large result sets
        """
        if not self.connection:
            return []
            
        if base_dn is None:
            base_dn = self.base_dn
            
        if attributes is None:
            attributes = ['*', '+']  # All user and operational attributes
        
        # Clean expired cache entries
        self._clean_cache()
        
        # Apply throttling if enabled
        if self._throttle_enabled:
            self._apply_throttle()
        
        # Start timing for debug
        start_time = time.time()
        
        # Check cache if enabled
        if use_cache:
            cache_key = self._get_cache_key(base_dn, search_filter, attributes, scope)
            if cache_key in self._cache:
                timestamp, results = self._cache[cache_key]
                if time.time() - timestamp < self._cache_ttl:
                    # Cache hit!
                    self._cache_stats['hits'] += 1
                    
                    # Log cache hit
                    self._log_query('search', {
                        'base_dn': base_dn,
                        'filter': search_filter,
                        'attributes': attributes,
                        'scope': str(scope),
                        'size_limit': size_limit
                    }, len(results), time.time() - start_time, cache_hit=True)
                    return results
        
        # Cache miss
        self._cache_stats['misses'] += 1
        
        try:
            results = []
            
            # Use paged search for large result sets - helps avoid timeouts on big directories
            if paged_search and size_limit > self._page_size:
                # Perform paged search
                cookie = True
                total_entries = 0
                
                while cookie and total_entries < size_limit:
                    # Determine page size for this iteration
                    current_page_size = min(self._page_size, size_limit - total_entries)
                    
                    # Use paged controls if server supports it - this OID is for Simple Paged Results
                    if self.server and self.server.info and '1.2.840.113556.1.4.319' in self.server.info.supported_controls:
                        from ldap3 import SIMPLE_PAGED_RESULTS_CONTROL
                        paged_control = SIMPLE_PAGED_RESULTS_CONTROL(True, size=current_page_size, cookie=cookie if isinstance(cookie, bytes) else b'')
                        
                        self.connection.search(
                            search_base=base_dn,
                            search_filter=search_filter,
                            search_scope=scope,
                            attributes=attributes,
                            controls=[paged_control]
                        )
                        
                        # Extract cookie for next page
                        cookie = None
                        for control in self.connection.response.get('controls', []):
                            if control.get('type') == '1.2.840.113556.1.4.319':
                                cookie = control.get('value', {}).get('cookie')
                                break
                    else:
                        # Fallback to regular search with size limit
                        self.connection.search(
                            search_base=base_dn,
                            search_filter=search_filter,
                            search_scope=scope,
                            attributes=attributes,
                            size_limit=current_page_size,
                            time_limit=30
                        )
                        cookie = False  # No paging support, stop after first batch
                    
                    # Process entries from this page
                    for entry in self.connection.entries:
                        if total_entries >= size_limit:
                            break
                            
                        entry_dict = {
                            'dn': entry.entry_dn,
                            'attributes': {}
                        }
                        
                        for attr_name in entry.entry_attributes:
                            attr = entry[attr_name]
                            if attr.values:
                                if len(attr.values) == 1:
                                    entry_dict['attributes'][attr_name] = attr.values[0]
                                else:
                                    entry_dict['attributes'][attr_name] = list(attr.values)
                                    
                        results.append(entry_dict)
                        total_entries += 1
                    
                    if not cookie:
                        break
            else:
                # Regular search for smaller result sets
                self.connection.search(
                    search_base=base_dn,
                    search_filter=search_filter,
                    search_scope=scope,
                    attributes=attributes,
                    size_limit=size_limit,
                    time_limit=30
                )
                
                for entry in self.connection.entries:
                    entry_dict = {
                        'dn': entry.entry_dn,
                        'attributes': {}
                    }
                    
                    for attr_name in entry.entry_attributes:
                        attr = entry[attr_name]
                        if attr.values:
                            if len(attr.values) == 1:
                                entry_dict['attributes'][attr_name] = attr.values[0]
                            else:
                                entry_dict['attributes'][attr_name] = list(attr.values)
                                
                    results.append(entry_dict)
            
            # Cache results if enabled
            if use_cache:
                self._cache[cache_key] = (time.time(), results)
            
            # Log successful query
            self._log_query('search', {
                'base_dn': base_dn,
                'filter': search_filter,
                'attributes': attributes,
                'scope': str(scope),
                'size_limit': size_limit,
                'paged': paged_search and size_limit > self._page_size
            }, len(results), time.time() - start_time, cache_hit=False)
                
            return results
            
        except Exception as e:
            # Log error
            self._log_query('search_error', {
                'base_dn': base_dn,
                'filter': search_filter,
                'error': str(e)
            }, 0, time.time() - start_time, cache_hit=False)
            
            print(f"Search error: {str(e)}")
            return []
    
    def get_children(self, dn: str) -> List[Dict[str, Any]]:
        """
        Get immediate children of a DN
        """
        return self.search(base_dn=dn, scope=ldap3.LEVEL, attributes=['objectClass', 'cn', 'ou', 'name'])
    
    def get_entry(self, dn: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific entry by DN
        """
        results = self.search(base_dn=dn, scope=ldap3.BASE)
        return results[0] if results else None
    
    def batch_search(self, queries: List[Dict[str, Any]], optimize: bool = True) -> Dict[str, List[Dict[str, Any]]]:
        """
        Perform multiple LDAP searches efficiently by optimizing queries
        
        Args:
            queries: List of search parameters, each containing:
                     {
                         'key': str,  # Unique identifier for this query
                         'base_dn': str,
                         'search_filter': str,
                         'attributes': List[str],
                         'scope': str,
                         'size_limit': int
                     }
            optimize: Whether to optimize by combining similar queries
            
        Returns:
            Dictionary mapping query keys to their results
        """
        results = {}
        
        if not self.connection:
            return results
            
        # Group queries by similar parameters for optimization
        if optimize:
            query_groups = defaultdict(list)
            
            for query in queries:
                # Group by base_dn and scope
                group_key = (query.get('base_dn', self.base_dn), query.get('scope', SUBTREE))
                query_groups[group_key].append(query)
            
            # Process each group
            for (base_dn, scope), group_queries in query_groups.items():
                # Combine filters and attributes for the group
                combined_filters = []
                combined_attributes = set()
                query_map = {}
                
                for query in group_queries:
                    filter_str = query.get('search_filter', '(objectClass=*)')
                    combined_filters.append(filter_str)
                    
                    attrs = query.get('attributes', ['*', '+'])
                    combined_attributes.update(attrs)
                    
                    query_map[query['key']] = filter_str
                
                # Create combined filter using OR
                if len(combined_filters) > 1:
                    combined_filter = f"(|{''.join(combined_filters)})"
                else:
                    combined_filter = combined_filters[0]
                
                # OpSec: add random delay between query groups
                if self._opsec_enabled and query_groups:
                    time.sleep(random.uniform(self._min_query_delay, self._max_query_delay))
                
                # Perform single search for the group
                group_results = self.search(
                    base_dn=base_dn,
                    search_filter=combined_filter,
                    attributes=list(combined_attributes),
                    scope=scope,
                    size_limit=sum(q.get('size_limit', 1000) for q in group_queries),
                    use_cache=True,
                    paged_search=True
                )
                
                # Distribute results to individual queries
                for query in group_queries:
                    query_filter = query_map[query['key']]
                    query_results = []
                    
                    # Filter results for this specific query
                    for entry in group_results:
                        # Check if entry matches this query's filter
                        # This is a simplified check - in production, you'd use proper LDAP filter matching
                        if self._entry_matches_filter(entry, query_filter):
                            # Filter attributes to only those requested
                            filtered_entry = {
                                'dn': entry['dn'],
                                'attributes': {}
                            }
                            
                            requested_attrs = set(query.get('attributes', ['*', '+']))
                            for attr_name, attr_value in entry['attributes'].items():
                                if '*' in requested_attrs or attr_name in requested_attrs:
                                    filtered_entry['attributes'][attr_name] = attr_value
                            
                            query_results.append(filtered_entry)
                    
                    results[query['key']] = query_results[:query.get('size_limit', 1000)]
        else:
            # Process queries individually without optimisation
            for i, query in enumerate(queries):
                # OpSec: add delay between individual queries
                if self._opsec_enabled and i > 0:
                    time.sleep(random.uniform(self._min_query_delay, self._max_query_delay))
                    
                query_results = self.search(
                    base_dn=query.get('base_dn'),
                    search_filter=query.get('search_filter', '(objectClass=*)'),
                    attributes=query.get('attributes'),
                    scope=query.get('scope', SUBTREE),
                    size_limit=query.get('size_limit', 1000),
                    use_cache=True,
                    paged_search=True
                )
                results[query['key']] = query_results
        
        return results
    
    def _entry_matches_filter(self, entry: Dict[str, Any], ldap_filter: str) -> bool:
        """
        Simple LDAP filter matching (for basic filters only)
        This is a simplified implementation for optimization purposes
        """
        # Handle basic equality filters like (attribute=value)
        if ldap_filter.startswith('(') and ldap_filter.endswith(')'):
            filter_content = ldap_filter[1:-1]
            
            # Simple equality check
            if '=' in filter_content and not any(op in filter_content for op in ['>=', '<=', '~=']):
                attr_name, value = filter_content.split('=', 1)
                
                # Handle objectClass=*
                if value == '*':
                    return attr_name in entry.get('attributes', {})
                
                # Check attribute value
                attr_value = entry.get('attributes', {}).get(attr_name)
                if attr_value is not None:
                    if isinstance(attr_value, list):
                        return value in attr_value
                    else:
                        return str(attr_value).lower() == value.lower()
        
        # For complex filters, return True and let the results be filtered later
        # In production, you'd implement proper LDAP filter parsing
        return True
    
    def get_bloodhound_data(self, use_cache: bool = True) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all data needed for BloodHound export with optimized queries
        Now with randomisation to avoid detection patterns
        """
        # Define the queries needed for BloodHound
        queries = [
            {
                'key': 'users',
                'base_dn': self.base_dn,
                'search_filter': '(&(objectClass=user)(!(objectClass=computer)))',
                'attributes': ['*', '+'],
                'scope': SUBTREE,
                'size_limit': 50000
            },
            {
                'key': 'computers',
                'base_dn': self.base_dn,
                'search_filter': '(objectClass=computer)',
                'attributes': ['*', '+'],
                'scope': SUBTREE,
                'size_limit': 50000
            },
            {
                'key': 'groups',
                'base_dn': self.base_dn,
                'search_filter': '(objectClass=group)',
                'attributes': ['*', '+'],
                'scope': SUBTREE,
                'size_limit': 50000
            },
            {
                'key': 'ous',
                'base_dn': self.base_dn,
                'search_filter': '(objectClass=organizationalUnit)',
                'attributes': ['*', '+'],
                'scope': SUBTREE,
                'size_limit': 10000
            },
            {
                'key': 'domains',
                'base_dn': self.base_dn,
                'search_filter': '(objectClass=domain)',
                'attributes': ['*', '+'],
                'scope': SUBTREE,
                'size_limit': 100
            },
            {
                'key': 'trusts',
                'base_dn': f"CN=System,{self.base_dn}",
                'search_filter': '(objectClass=trustedDomain)',
                'attributes': ['*', '+'],
                'scope': SUBTREE,
                'size_limit': 1000
            }
        ]
        
        # OpSec: randomise query order to avoid **common** detection patterns
        if self._opsec_enabled:
            random.shuffle(queries)
            # add a small random delay before starting
            time.sleep(random.uniform(0.2, 0.5))
        
        # Use batch search for efficiency
        return self.batch_search(queries, optimize=True)
    
    def set_opsec_mode(self, enabled: bool = True, min_delay: float = 0.5, max_delay: float = 2.0):
        """
        Configure OpSec mode settings
        
        Args:
            enabled: Enable/disable OpSec randomisation
            min_delay: Minimum delay between queries in seconds
            max_delay: Maximum delay between queries in seconds
        """
        self._opsec_enabled = enabled
        self._min_query_delay = max(0.1, min_delay)  # at least 100ms
        self._max_query_delay = max(self._min_query_delay, max_delay)
        
        if enabled:
            print(f"OpSec mode enabled: queries randomised with {min_delay}-{max_delay}s delays")
        else:
            print("OpSec mode disabled - queries will run at full speed")
    
    def set_throttle_settings(self, enabled: bool = True, queries_per_minute: int = 30, 
                             burst_size: int = 5):
        """
        Configure throttle settings for stealth operations
        
        Args:
            enabled: Enable/disable throttling
            queries_per_minute: Maximum queries allowed per minute
            burst_size: Maximum burst queries allowed
        """
        self._throttle_enabled = enabled
        self._queries_per_minute = max(1, queries_per_minute)  # at least 1 query/min
        self._burst_size = max(1, burst_size)
        
        if enabled:
            print(f"Throttling enabled: {queries_per_minute} queries/min, burst of {burst_size}")
        else:
            print("Throttling disabled - queries will run at full speed")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics and performance metrics
        
        Returns:
            Dictionary with cache stats including hits, misses, hit rate, etc.
        """
        total_requests = self._cache_stats['hits'] + self._cache_stats['misses']
        hit_rate = (self._cache_stats['hits'] / total_requests * 100) if total_requests > 0 else 0
        
        # Estimate cache size
        cache_size_bytes = sum(len(str(k)) + len(str(v)) for k, v in self._cache.items())
        cache_size_mb = cache_size_bytes / (1024 * 1024)
        
        return {
            'hits': self._cache_stats['hits'],
            'misses': self._cache_stats['misses'],
            'evictions': self._cache_stats['evictions'],
            'hit_rate': round(hit_rate, 2),
            'total_requests': total_requests,
            'cache_entries': len(self._cache),
            'cache_size_mb': round(cache_size_mb, 2),
            'cache_limit_mb': self._cache_size_mb,
            'cache_ttl_seconds': self._cache_ttl,
            'throttle_enabled': self._throttle_enabled,
            'queries_per_minute': self._queries_per_minute if self._throttle_enabled else 'unlimited',
            'burst_size': self._burst_size if self._throttle_enabled else 'N/A'
        }
    
    def set_cache_settings(self, size_mb: int = 100, ttl_seconds: int = 1800):
        """
        Configure cache settings
        
        Args:
            size_mb: Maximum cache size in megabytes
            ttl_seconds: Time to live for cache entries in seconds
        """
        self._cache_size_mb = max(1, size_mb)  # at least 1MB
        self._cache_ttl = max(60, ttl_seconds)  # at least 1 minute
        
        print(f"Cache settings updated: {size_mb}MB limit, {ttl_seconds}s TTL")
        
        # Clean cache with new settings
        self._clean_cache()
    
    def get_bloodhound_opengraph_data(self, use_cache: bool = True) -> Dict[str, Any]:
        """
        Future implementation for BloodHound OpenGraph schema support
        https://bloodhound.specterops.io/opengraph/schema
        
        TODO: Attempt to implement OpenGraph for BloodHound CE
        - Uses graph-based queries instead of flat LDAP searches
        - Better relationship mapping
        - More efficient for complex permission chains
        """
        raise NotImplementedError("OpenGraph support coming in future release - feel free to submit a pull req pls")
    
    def disconnect(self):
        """
        Close LDAP connection
        """
        if self.connection:
            self.connection.unbind()
            self.connection = None
            self.server = None
            self.base_dn = None
            self.clear_cache()