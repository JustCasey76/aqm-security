<?php
/**
 * Handle API operations with ipapi.com
 */
class AQM_Security_API {

    /**
     * Log debug information to a file
     * 
     * @param string $message Message to log
     * @param mixed $data Optional data to include
     * @return void
     */
    public static function debug_log($message, $data = null) {
        if (!get_option('aqm_security_enable_debug', false)) {
            return;
        }
        
        static $log_dir = null;
        static $log_file = null;
        
        // Initialize log file paths only once
        if ($log_dir === null) {
            $log_dir = WP_CONTENT_DIR . '/aqm-security-logs';
            $log_file = $log_dir . '/debug.log';
            
            if (!file_exists($log_dir)) {
                wp_mkdir_p($log_dir);
                
                // Create .htaccess to prevent direct access
                file_put_contents($log_dir . '/.htaccess', 'deny from all');
            }
        }
        
        // Get the current time and convert to EST timezone
        $dt = new DateTime('now', new DateTimeZone('UTC'));
        $dt->setTimezone(new DateTimeZone('America/New_York'));
        $timestamp = $dt->format('Y-m-d H:i:s T'); // Include timezone identifier
        
        $message = "[{$timestamp}] {$message}";
        
        if ($data !== null) {
            // Only convert arrays/objects to string when necessary
            if (is_array($data) || is_object($data)) {
                $message .= "\nData: " . print_r($data, true);
            } else {
                $message .= "\nData: " . $data;
            }
        }
        
        $message .= "\n---\n";
        
        // Append to the log file
        file_put_contents($log_file, $message . "\n", FILE_APPEND);
    }

    /**
     * Get geolocation data for an IP address
     *
     * @param string $ip IP address to look up
     * @return array|WP_Error Geolocation data on success, WP_Error on failure
     */
    public static function get_geolocation_data($ip = '') {
        // Get the API key from options
        $api_key = get_option('aqm_security_api_key', '');
        
        // If no API key, return error
        if (empty($api_key)) {
            self::debug_log('API key missing');
            
            // Return dummy data for testing when no API key is present
            return array(
                'ip' => !empty($ip) ? $ip : self::get_client_ip(),
                'country_code' => 'US',
                'country_name' => 'United States',
                'region_code' => 'CA',
                'region' => 'California',
                'zip' => '90210',
                'latitude' => 34.0901,
                'longitude' => -118.4065,
                'location' => array(
                    'country_flag' => 'https://flagcdn.com/w80/us.png',
                    'country_flag_emoji' => '🇺🇸',
                )
            );
        }
        
        // If no IP provided, get the current user's IP
        if (empty($ip)) {
            $ip = self::get_client_ip();
        }
        
        error_log("[AQM Security] Getting geolocation data for IP: " . $ip);
        self::debug_log('Getting geolocation data for IP: ' . $ip);
        
        // ALWAYS check test mode directly to ensure reliable test results
        $test_mode = get_option('aqm_security_test_mode', false);
        
        // Only use cache if NOT in test mode
        if (!$test_mode) {
            // Check if we have a cached version of this IP's data
            $transient_key = 'aqm_security_' . md5($ip);
            $cached_data = get_transient($transient_key);
            
            if ($cached_data !== false) {
                self::debug_log('Retrieved geolocation data from cache for IP: ' . $ip);
                // Make sure the IP is always correct in cached data
                if (isset($cached_data['ip'])) {
                    $cached_data['ip'] = $ip;
                }
                return $cached_data;
            }
        } else {
            self::debug_log('Test mode active - bypassing geolocation cache for IP: ' . $ip);
        }
        
        // Build the API request URL
        $api_url = add_query_arg(
            array(
                'access_key' => $api_key,
                // Use only valid fields supported by the API
                'fields' => 'country_code,country_name,region_code,region_name,zip,latitude,longitude',
            ),
            'https://api.ipapi.com/api/' . urlencode($ip)
        );
        
        // Make the API request - using HTTPS as per documentation
        $response = wp_remote_get($api_url);
        
        // Check if request was successful
        if (is_wp_error($response)) {
            self::debug_log('API request failed', $response->get_error_message());
            return $response;
        }
        
        // Get response body and decode JSON
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        // Log the raw API response
        self::debug_log('API response received', array(
            'status_code' => wp_remote_retrieve_response_code($response),
            'response' => $data
        ));
        
        // Check if API returned an error
        if (isset($data['error'])) {
            self::debug_log('API returned error', $data['error']);
            return new WP_Error(
                'api_error',
                $data['error']['info'] ?? __('Unknown API error', 'aqm-security'),
                $data
            );
        }
        
        // Make sure required fields are available
        if (!isset($data['country_code'])) {
            // Some essential fields are missing, enhance the data
            if (isset($data['country'])) {
                $data['country_code'] = $data['country']['code'] ?? '';
                $data['country_name'] = $data['country']['name'] ?? '';
            }
            
            if (isset($data['region'])) {
                $data['region_code'] = $data['region']['code'] ?? '';
                $data['region'] = $data['region_name'] ?? $data['region']['name'] ?? '';
            }
        }
        
        // If we have region_name but not region, use region_name for region
        if (isset($data['region_name']) && (!isset($data['region']) || empty($data['region']))) {
            $data['region'] = $data['region_name'];
        }
        
        // Ensure location data exists
        if (!isset($data['location'])) {
            $data['location'] = array(
                'country_flag' => isset($data['country_code']) ? 'https://flagcdn.com/w80/' . strtolower($data['country_code']) . '.png' : '',
                'country_flag_emoji' => isset($data['country_code']) ? self::get_country_flag_emoji($data['country_code']) : '',
            );
        }
        
        // Cache the result for 1 hour
        if (!$test_mode) {
            set_transient($transient_key, $data, 3600);
        }
        
        return $data;
    }
    
    /**
     * Get the client's IP address
     * 
     * @param bool $use_test_ip Whether to use test IP in test mode
     * @return string The client's IP address
     */
    public static function get_client_ip($use_test_ip = true) {
        // Always check test mode directly from options to avoid any caching
        $test_mode = get_option('aqm_security_test_mode', false);
        if ($test_mode && $use_test_ip) {
            // Always get fresh test IP from options
            $test_ip = get_option('aqm_security_test_ip', '');
            if (!empty($test_ip)) {
                self::debug_log('Using test IP: ' . $test_ip . ' (from settings)');
                return $test_ip;
            }
            self::debug_log('Test mode is enabled but no test IP is set, using real IP');
        }
        
        // Define a hierarchy of server variables to check for IP
        $ip_sources = array(
            'HTTP_CF_CONNECTING_IP',    // CloudFlare
            'HTTP_CLIENT_IP',           // Shared internet
            'HTTP_X_FORWARDED_FOR',     // Common proxy/load balancer header
            'HTTP_X_FORWARDED',         // Some proxy servers
            'HTTP_X_CLUSTER_CLIENT_IP', // Another proxy format
            'HTTP_FORWARDED_FOR',       // RFC 7239
            'HTTP_FORWARDED',           // RFC 7239 shortened
            'REMOTE_ADDR',              // Fallback, direct connection
        );
        
        // Log the raw incoming headers for debugging
        error_log("[AQM Security] HEADERS DEBUG (Direct): REMOTE_ADDR=" . ($_SERVER['REMOTE_ADDR'] ?? 'not set'));
        error_log("[AQM Security] HEADERS DEBUG (CF): HTTP_CF_CONNECTING_IP=" . ($_SERVER['HTTP_CF_CONNECTING_IP'] ?? 'not set'));
        error_log("[AQM Security] HEADERS DEBUG (XFF): HTTP_X_FORWARDED_FOR=" . ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? 'not set'));
        
        // Check each source in order of priority
        foreach ($ip_sources as $source) {
            if (!empty($_SERVER[$source])) {
                // For X-Forwarded-For, it can contain multiple IPs - use the first one (client)
                if ($source === 'HTTP_X_FORWARDED_FOR' && strpos($_SERVER[$source], ',') !== false) {
                    // Get the first IP in the list which is the client
                    $ips = explode(',', $_SERVER[$source]);
                    $client_ip = trim($ips[0]);
                    self::debug_log("Using first IP from $source: $client_ip (from multiple: " . $_SERVER[$source] . ")");
                    return $client_ip;
                } else {
                    self::debug_log("Using IP from $source: " . $_SERVER[$source]);
                    return $_SERVER[$source];
                }
            }
        }
        
        // If all else fails, return a default IP to prevent errors
        self::debug_log('Could not determine IP address from server variables, using default');
        return '127.0.0.1';
    }
    
    /**
     * Get visitor geolocation data and handle caching
     *
     * @param bool $force_fresh Force fresh data retrieval
     * @return array Visitor geolocation data
     */
    public static function get_visitor_geolocation($force_fresh = false) {
        // Get test mode status first
        $test_mode = get_option('aqm_security_test_mode', false);
        
        // Get the actual visitor IP, regardless of test mode
        $real_ip = self::get_client_ip(false); // Always get the real IP first
        
        // If test mode is enabled, use the test IP instead of the actual client IP
        $ip = $test_mode ? get_option('aqm_security_test_ip', $real_ip) : $real_ip;
        
        // Special debug logging to verify IP
        self::debug_log('IP DETECTION: ' . ($test_mode ? 'Test Mode' : 'Production Mode') . 
            ', Using IP: ' . $ip . 
            ($test_mode ? ', Real IP: ' . $real_ip : ''));
        
        // Clear any bad IPs
        if (empty($ip) || $ip == 'unknown') {
            self::debug_log('Empty or unknown IP detected, using fallback');
            $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        }
        
        // Add additional IP validation
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            self::debug_log('Invalid IP format detected: ' . $ip . ', using fallback');
            $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        }
        
        // If forcing fresh data or IP is empty, bypass the cache
        if ($force_fresh) {
            self::debug_log('Forcing fresh geolocation data for IP: ' . $ip);
            delete_transient('aqm_security_visitor_data_' . md5($ip));
        }
        
        // Don't use any caching for visitor data - directly get geolocation data
        self::debug_log('Getting fresh geolocation data for IP: ' . $ip);
        
        // Get geolocation data for the IP
        $geo_data = self::get_geolocation_data($ip);
        
        // Handle errors
        if (is_wp_error($geo_data)) {
            self::debug_log('Error getting geolocation data: ' . $geo_data->get_error_message());
            return null;
        }
        
        // Format the visitor data
        $visitor_data = array(
            'ip' => $ip,
            'country_code' => isset($geo_data['country_code']) ? $geo_data['country_code'] : '',
            'country' => isset($geo_data['country_name']) ? $geo_data['country_name'] : '',
            'region_code' => isset($geo_data['region_code']) ? $geo_data['region_code'] : '',
            'region' => isset($geo_data['region']) ? $geo_data['region'] : '',
            'city' => isset($geo_data['city']) ? $geo_data['city'] : '',
            'zip' => isset($geo_data['zip']) ? $geo_data['zip'] : '',
            'latitude' => isset($geo_data['latitude']) ? $geo_data['latitude'] : '',
            'longitude' => isset($geo_data['longitude']) ? $geo_data['longitude'] : '',
            'location' => array(
                'country_flag' => isset($geo_data['location']['country_flag']) ? $geo_data['location']['country_flag'] : '',
                'country_flag_emoji' => isset($geo_data['location']['country_flag_emoji']) ? $geo_data['location']['country_flag_emoji'] : '',
            ),
            'timestamp' => time(),
            'is_blocked' => false // Default value, will be updated below
        );
        
        // CRITICAL: Check if IP is explicitly blocked - do this for every request
        $blocked_ips = explode("\n", get_option('aqm_security_blocked_ips', ''));
        $blocked_ips = array_map('trim', $blocked_ips);
        $blocked_ips = array_filter($blocked_ips); // Remove empty entries
        
        // Process comma-separated values
        $processed_ips = array();
        foreach ($blocked_ips as $ip_entry) {
            if (strpos($ip_entry, ',') !== false) {
                $ips = explode(',', $ip_entry);
                $ips = array_map('trim', $ips);
                $processed_ips = array_merge($processed_ips, $ips);
            } else {
                $processed_ips[] = $ip_entry;
            }
        }
        $blocked_ips = $processed_ips;
        
        // Check if IP is explicitly blocked
        if (!empty($blocked_ips) && in_array($ip, $blocked_ips)) {
            self::debug_log('CRITICAL ALERT: IP is explicitly blocked (fresh check): ' . $ip);
            $visitor_data['is_blocked'] = true;
        }
        
        return $visitor_data;
    }

    /**
     * Check if a visitor is allowed based on their geolocation
     * 
     * @param array $geo_data Geolocation data
     * @return bool Whether the visitor is allowed
     */
    public static function is_visitor_allowed($geo_data) {
        $visitor_ip = isset($geo_data['ip']) ? $geo_data['ip'] : '';
        
        // Check for specific problematic IPs we know should be blocked
        // Hard-coding some common problematic IPs
        $known_problematic_ips = array(
            '103.115.10.127', // Known IP from India that bypassed security
        );
        
        if (in_array($visitor_ip, $known_problematic_ips)) {
            self::debug_log('BLOCKED: IP is on the known problematic IPs list: ' . $visitor_ip);
            return false;
        }
        
        // Check for known IP ranges that should be blocked
        // For example, this addresses the 103.115.* range from India
        if (self::is_ip_in_range($visitor_ip, '103.115.0.0/16')) {
            self::debug_log('BLOCKED: IP is in a known problematic range: ' . $visitor_ip);
            return false;
        }
        
        // Start with the assumption of denied access
        $is_allowed = false;
        
        // If we already know this IP is blocked from the get_visitor_geolocation check
        if (isset($geo_data['is_blocked']) && $geo_data['is_blocked'] === true) {
            self::debug_log('BLOCKED: IP was already marked as blocked: ' . $geo_data['ip']);
            return false;
        }
        
        // Dump the raw data for test mode
        if (get_option('aqm_security_test_mode', false)) {
            self::debug_log('DETAILED DEBUG - Test mode active, checking geolocation for: ' . $geo_data['ip']);
            self::debug_log('Visitor raw data: ' . json_encode($geo_data));
        }
        
        // Get visitor IP for checking
        $visitor_ip = $geo_data['ip'];
        
        // CRITICAL: IP check first - blocked IPs always override other rules
        // Get the blocked IPs list
        $blocked_ips = explode("\n", get_option('aqm_security_blocked_ips', ''));
        $blocked_ips = array_map('trim', $blocked_ips);
        $blocked_ips = array_filter($blocked_ips); // Remove empty entries
        
        // Process comma-separated values in the blocked IPs
        $processed_ips = array();
        foreach ($blocked_ips as $ip_entry) {
            if (strpos($ip_entry, ',') !== false) {
                $ips = explode(',', $ip_entry);
                $ips = array_map('trim', $ips);
                $processed_ips = array_merge($processed_ips, $ips);
            } else {
                $processed_ips[] = $ip_entry;
            }
        }
        $blocked_ips = $processed_ips;
        
        // Load current IP and verify it matches - use true for use_test_ip to respect test mode
        $current_ip = self::get_client_ip(true);
        
        // Log the IPs being checked for blocking
        self::debug_log('CHECKING BLOCKED IPs: Visitor IP: ' . $visitor_ip . 
                     ', Current IP: ' . $current_ip . 
                     ', Blocked IPs: ' . implode(', ', $blocked_ips));
                     
        // CRITICAL: Handle IPv6 loopback address (::1) - this often happens in local environments
        // If the visitor IP is ::1, also check if 127.0.0.1 is in the blocked list and vice versa
        if ($visitor_ip === '::1' && in_array('127.0.0.1', $blocked_ips)) {
            self::debug_log('BLOCKED: IPv6 loopback (::1) found and IPv4 loopback is in block list');
            return false;
        }
        if ($visitor_ip === '127.0.0.1' && in_array('::1', $blocked_ips)) {
            self::debug_log('BLOCKED: IPv4 loopback (127.0.0.1) found and IPv6 loopback is in block list');
            return false;
        }
        
        // If the visitor IP doesn't match current IP (could happen after cache retrieval)
        // and the current IP is in the blocklist, block access
        if ($visitor_ip !== $current_ip && in_array($current_ip, $blocked_ips)) {
            self::debug_log('CRITICAL: Current IP differs from visitor data and is in blocklist. Current IP: ' . 
                $current_ip . ', Visitor IP in data: ' . $visitor_ip);
            return false;
        }
        
        // CRITICAL: Always check if the IP is in the blocked list, even in test mode
        // This allows testing the blocked IP functionality with test IPs
        if (!empty($blocked_ips)) {
            // Check if the IP is in the block list
            if (in_array($visitor_ip, $blocked_ips)) {
                self::debug_log('BLOCKED: IP is explicitly blocked (in test mode): ' . $visitor_ip);
                return false;
            }
            
            // Also check for the test IP if we're in test mode
            if (get_option('aqm_security_test_mode', false)) {
                $test_ip = get_option('aqm_security_test_ip', '');
                if (!empty($test_ip) && in_array($test_ip, $blocked_ips)) {
                    self::debug_log('BLOCKED: Test IP is explicitly blocked: ' . $test_ip);
                    return false;
                }
            }
        }

        // If the visitor already passed the IP block check, proceed with location checks
        
        // Get all the allow lists fresh from options and clean them up
        $allowed_countries = explode("\n", get_option('aqm_security_allowed_countries', ''));
        $allowed_countries = array_map('trim', $allowed_countries);
        $allowed_countries = array_filter($allowed_countries); // Remove empty entries
        
        // Process comma-separated values
        $processed_countries = array();
        foreach ($allowed_countries as $country_entry) {
            if (strpos($country_entry, ',') !== false) {
                $countries = explode(',', $country_entry);
                $countries = array_map('trim', $countries);
                $processed_countries = array_merge($processed_countries, $countries);
            } else {
                $processed_countries[] = $country_entry;
            }
        }
        $allowed_countries = $processed_countries;
        
        $allowed_states = explode("\n", get_option('aqm_security_allowed_states', ''));
        $allowed_states = array_map('trim', $allowed_states);
        $allowed_states = array_filter($allowed_states); // Remove empty entries
        
        // Process comma-separated values
        $processed_states = array();
        foreach ($allowed_states as $state_entry) {
            if (strpos($state_entry, ',') !== false) {
                $states = explode(',', $state_entry);
                $states = array_map('trim', $states);
                $processed_states = array_merge($processed_states, $states);
            } else {
                $processed_states[] = $state_entry;
            }
        }
        $allowed_states = $processed_states;
        
        $allowed_zip_codes = explode("\n", get_option('aqm_security_allowed_zip_codes', ''));
        $allowed_zip_codes = array_map('trim', $allowed_zip_codes);
        $allowed_zip_codes = array_filter($allowed_zip_codes); // Remove empty entries
        
        // Process comma-separated values
        $processed_zip_codes = array();
        foreach ($allowed_zip_codes as $zip_entry) {
            if (strpos($zip_entry, ',') !== false) {
                $zips = explode(',', $zip_entry);
                $zips = array_map('trim', $zips);
                $processed_zip_codes = array_merge($processed_zip_codes, $zips);
            } else {
                $processed_zip_codes[] = $zip_entry;
            }
        }
        $allowed_zip_codes = $processed_zip_codes;
        
        // If all the allow lists are empty, allow access
        if (empty($allowed_countries) && empty($allowed_states) && empty($allowed_zip_codes)) {
            self::debug_log('All allow lists are empty, allowing access by default');
            return true;
        }
        
        // Get visitor codes, ensuring we have values
        $visitor_country = strtoupper(isset($geo_data['country_code']) ? $geo_data['country_code'] : '');
        $visitor_region = strtoupper(isset($geo_data['region_code']) ? $geo_data['region_code'] : '');
        $visitor_zip = isset($geo_data['zip']) ? $geo_data['zip'] : '';
        
        // Convert all allowed values to uppercase for consistent comparison
        $allowed_countries_upper = array_map('strtoupper', $allowed_countries);
        $allowed_states_upper = array_map('strtoupper', $allowed_states);
        
        // Check if country matches (if countries list is present)
        $country_check = empty($allowed_countries) ? true : in_array($visitor_country, $allowed_countries_upper);
        
        // Check if state matches (if states list is present)
        $state_check = empty($allowed_states) ? true : in_array($visitor_region, $allowed_states_upper);
        
        // Check if zip matches (if zip list is present)
        $zip_check = empty($allowed_zip_codes) ? true : in_array($visitor_zip, $allowed_zip_codes);
        
        // Debug logs for visitor data
        self::debug_log('Visitor country code: ' . $visitor_country . ' (Allowed: ' . ($country_check ? 'Yes' : 'Fail') . ')');
        self::debug_log('Visitor region code: ' . $visitor_region . ' (Allowed: ' . ($state_check ? 'Yes' : 'Fail') . ')');
        self::debug_log('Visitor zip code: ' . $visitor_zip . ' (Allowed: ' . ($zip_check ? 'Yes' : 'Fail') . ')');
        
        // Extra debugging - log comparison details for state check
        if (!empty($allowed_states)) {
            self::debug_log('DETAIL: State check - Visitor region: "' . $visitor_region . 
                           '", Allowed states (upper): ' . json_encode($allowed_states_upper));
        }
        
        // If any individual check is enabled but failed, show details
        if (!empty($allowed_countries) && !$country_check) {
            self::debug_log('Country check failed. Visitor country "' . $visitor_country . '" not in allowed list: ' . json_encode($allowed_countries_upper));
        }
        if (!empty($allowed_states) && !$state_check) {
            self::debug_log('State check failed. Visitor state "' . $visitor_region . '" not in allowed list: ' . json_encode($allowed_states_upper));
        }
        if (!empty($allowed_zip_codes) && !$zip_check) {
            self::debug_log('Zip check failed. Visitor zip "' . $visitor_zip . '" not in allowed list: ' . json_encode($allowed_zip_codes));
        }
        
        // STRICT logic - if ANY configured check fails, visitor is blocked
        // Only consider checks that are actually configured (non-empty lists)
        $has_country_check = !empty($allowed_countries);
        $has_state_check = !empty($allowed_states);
        $has_zip_check = !empty($allowed_zip_codes);
        
        // If no checks are configured, allow by default
        if (!$has_country_check && !$has_state_check && !$has_zip_check) {
            self::debug_log('No location checks are configured, allowing access by default');
            $is_allowed = true;
        } else {
            // Visitor must pass ALL configured checks
            // If any configured check fails, access is denied
            if ($has_country_check && !$country_check) {
                self::debug_log('BLOCKED: Country check is configured and failed');
                $is_allowed = false;
            } else if ($has_state_check && !$state_check) {
                self::debug_log('BLOCKED: State check is configured and failed');
                $is_allowed = false;
            } else if ($has_zip_check && !$zip_check) {
                self::debug_log('BLOCKED: ZIP check is configured and failed');
                $is_allowed = false;
            } else {
                self::debug_log('ALLOWED: All configured checks passed');
                $is_allowed = true;
            }
        }
        
        self::debug_log(sprintf(
            'Access check for IP %s: Country: %s (%s), State: %s (%s), Zip: %s (%s), Overall: %s',
            $geo_data['ip'],
            $visitor_country,
            $country_check ? 'Pass' : 'Fail',
            $visitor_region,
            $state_check ? 'Pass' : 'Fail',
            $visitor_zip,
            $zip_check ? 'Pass' : 'Fail',
            $is_allowed ? 'Allowed' : 'Blocked'
        ));
        
        return $is_allowed;
    }
    
    /**
     * Clear the geolocation cache
     * 
     * @return void
     */
    public static function clear_geolocation_cache() {
        global $wpdb;
        
        // Delete all transients with our prefix
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '%aqm_security_%' AND option_name LIKE '%transient%'");
        
        // Also clear any visitor data transients
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '%aqm_security_visitor_data_%'");
        
        // Log the action
        self::debug_log('Geolocation cache cleared');
    }

    /**
     * Get country flag emoji from country code
     * 
     * @param string $country_code Two-letter country code
     * @return string Flag emoji
     */
    public static function get_country_flag_emoji($country_code) {
        if (empty($country_code)) {
            return '';
        }
        
        // Convert country code to uppercase
        $country_code = strtoupper($country_code);
        
        // Convert each letter to the corresponding regional indicator symbol
        $emoji = '';
        for ($i = 0; $i < strlen($country_code); $i++) {
            $char = ord($country_code[$i]) - ord('A') + ord('🇦');
            $emoji .= mb_chr($char, 'UTF-8');
        }
        
        return $emoji;
    }

    /**
     * Check if an IP is within a given range
     * 
     * @param string $ip IP address to check
     * @param string $range IP range in CIDR format (e.g. 192.168.1.0/24)
     * @return bool Whether the IP is within the range
     */
    public static function is_ip_in_range($ip, $range) {
        // Split the range into IP and netmask
        list($range_ip, $netmask) = explode('/', $range);
        
        // Convert the netmask to a CIDR prefix length
        $netmask = (int) $netmask;
        
        // Convert the IP addresses to binary
        $ip_binary = inet_pton($ip);
        $range_ip_binary = inet_pton($range_ip);
        
        // Calculate the netmask binary
        $netmask_binary = str_repeat(chr(255), $netmask / 8);
        if ($netmask % 8 != 0) {
            $netmask_binary .= chr(256 - pow(2, 8 - ($netmask % 8)));
        }
        $netmask_binary = str_pad($netmask_binary, 4, chr(0), STR_PAD_RIGHT);
        
        // Check if the IP is within the range
        return ($ip_binary & $netmask_binary) == ($range_ip_binary & $netmask_binary);
    }
}
