<?php
/**
 * Visitor logging functionality
 */
class AQM_Security_Logger {

    // Define table name as a constant for consistency
    const TABLE_NAME = 'aqms_visitor_log';

    /**
     * Log visitor access to the database
     * 
     * @param string $ip Visitor IP address
     * @param string $country Visitor country
     * @param string $region Visitor region
     * @param bool $allowed Whether the visitor is allowed
     * @param string $country_flag URL to the country flag
     * @param bool $force_new Force a new log entry even if recent entry exists
     * @return int|bool Last insert ID or false on failure
     */
    public static function log_visitor($ip, $country, $region, $allowed, $country_flag = '', $force_new = false) {
        global $wpdb;
        
        // Check for session-based logging throttle
        if (!$force_new && self::should_skip_logging($ip)) {
            error_log("[AQM Security] Skipping redundant logging for IP: $ip (session throttle)");
            return true; // Return true to indicate success without actually logging
        }
        
        // Debug log the start of the logging process
        error_log("[AQM Security] Starting visitor logging process...");
        
        // Ensure the table exists before we try to log anything
        self::maybe_create_table();
        
        // Get test mode setting
        $test_mode = get_option('aqm_security_test_mode', false);
        
        // Double-check the IP for test mode
        if ($test_mode) {
            $test_ip = get_option('aqm_security_test_ip', '');
            if (!empty($test_ip) && filter_var($test_ip, FILTER_VALIDATE_IP)) {
                $ip = $test_ip;
                error_log("[AQM Security] Logger forcing test IP: $ip for database entry");
            } else {
                error_log("[AQM Security] Logger could not find valid test IP, using: $ip");
            }
        }
        
        // Sanitize inputs
        $ip = sanitize_text_field($ip);
        $country = sanitize_text_field($country);
        $region = sanitize_text_field($region);
        $zip = ''; // Initialize with empty string as it's not passed as a parameter
        $allowed = $allowed ? 1 : 0;
        $country_flag = esc_url_raw($country_flag);
        
        // Get current time and date key
        $dt = new DateTime('now', new DateTimeZone('UTC'));
        $current_time = $dt->format('Y-m-d H:i:s');
        $date_key = $dt->format('Y-m-d');
        
        // Get the full table name with prefix
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        
        // Debug logging
        error_log("[AQM Security] Logging visitor: IP=$ip, Country=$country, Region=$region, Test Mode=" . ($test_mode ? 'Yes' : 'No'));
        
        // Check for any existing log entry for this IP, ignoring time
        $existing_id = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM $table_name WHERE ip = %s ORDER BY id DESC LIMIT 1",
            $ip
        ));
        
        // Prepare data for database
        $data = array(
            'ip' => $ip,
            'country' => $country,
            'region' => $region,
            'zipcode' => $zip,
            'allowed' => $allowed,
            'flag_url' => $country_flag,
            'timestamp' => $current_time
        );
        
        $format = array(
            '%s', // ip
            '%s', // country
            '%s', // region
            '%s', // zipcode
            '%d', // allowed
            '%s', // flag_url
            '%s'  // timestamp
        );
        
        // If an existing entry is found, update it instead of creating a new one
        if ($existing_id) {
            error_log("[AQM Security] Updating existing log entry for IP: $ip (ID: $existing_id)");
            
            $result = $wpdb->update(
                $table_name,
                $data,
                array('id' => $existing_id),
                $format,
                array('%d') // id format
            );
            
            if ($result === false) {
                error_log("[AQM Security] Failed to update visitor log. Database error: " . $wpdb->last_error);
                return false;
            }
            
            error_log("[AQM Security] Successfully updated log entry for IP: $ip (ID: $existing_id)");
            
            // Mark this IP as logged in this session
            self::set_logging_throttle($ip);
            
            return $existing_id;
        } else {
            // No existing entry, insert a new one
            $result = $wpdb->insert($table_name, $data, $format);
            
            if ($result === false) {
                error_log("[AQM Security] Failed to log visitor. Database error: " . $wpdb->last_error);
                return false;
            }
            
            error_log("[AQM Security] Successfully logged visitor with ID: " . $wpdb->insert_id);
            
            // Mark this IP as logged in this session
            self::set_logging_throttle($ip);
            
            return $wpdb->insert_id;
        }
    }
    
    /**
     * Create the visitor log table if it doesn't exist
     */
    public static function maybe_create_table() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        
        if ($wpdb->get_var("SHOW TABLES LIKE '{$table_name}'") !== $table_name) {
            $charset_collate = $wpdb->get_charset_collate();
            
            $sql = "CREATE TABLE {$table_name} (
                id bigint(20) NOT NULL AUTO_INCREMENT,
                ip varchar(45) NOT NULL,
                country varchar(100) NOT NULL,
                region varchar(100) NOT NULL,
                zipcode varchar(20) NOT NULL,
                allowed tinyint(1) NOT NULL DEFAULT 0,
                flag_url varchar(255) NOT NULL,
                timestamp datetime NOT NULL,
                PRIMARY KEY (id),
                KEY ip (ip),
                KEY timestamp (timestamp)
            ) {$charset_collate};";
            
            require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
            dbDelta($sql);
            
            error_log("[AQM Security] Created visitor log table: {$table_name}");
            
            // Check if table was created successfully
            if ($wpdb->get_var("SHOW TABLES LIKE '{$table_name}'") !== $table_name) {
                error_log("[AQM Security] ERROR: Failed to create visitor log table!");
            }
        }
    }
    
    /**
     * Check if we should skip logging for this IP based on session throttle
     * 
     * @param string $ip The IP address to check
     * @return bool Whether logging should be skipped
     */
    private static function should_skip_logging($ip) {
        // Sanitize IP for use in transient name
        $ip_key = sanitize_key(str_replace('.', '_', $ip));
        $transient_name = 'aqms_log_throttle_' . $ip_key;
        
        // Check if we've logged this IP recently
        $last_logged = get_transient($transient_name);
        
        if ($last_logged) {
            // Get the throttle interval from settings, default to 24 hours (86400 seconds)
            $throttle_interval = intval(get_option('aqm_security_log_throttle', 86400));
            
            // If throttle is disabled (set to 0), always log
            if ($throttle_interval <= 0) {
                return false;
            }
            
            // Check if enough time has passed since the last log
            $time_diff = time() - intval($last_logged);
            
            // If we're within the throttle interval, skip logging
            if ($time_diff < $throttle_interval) {
                return true;
            }
        }
        
        // No recent log found or throttle interval passed, proceed with logging
        return false;
    }
    
    /**
     * Set the logging throttle for an IP address
     * 
     * @param string $ip The IP address to set throttle for
     */
    private static function set_logging_throttle($ip) {
        // Sanitize IP for use in transient name
        $ip_key = sanitize_key(str_replace('.', '_', $ip));
        $transient_name = 'aqms_log_throttle_' . $ip_key;
        
        // Get the throttle interval from settings, default to 24 hours (86400 seconds)
        $throttle_interval = intval(get_option('aqm_security_log_throttle', 86400));
        
        // If throttle is disabled, don't set the transient
        if ($throttle_interval <= 0) {
            return;
        }
        
        // Store current timestamp as the last logged time
        set_transient($transient_name, time(), $throttle_interval);
    }
    
    /**
     * Get logs for a specific date
     *
     * @param string $date Date to get logs for (Y-m-d format)
     * @param int $limit Number of results to return
     * @param int $offset Offset for pagination
     * @param array $filters Optional associative array of filter criteria
     * @return array Array of log entries
     */
    public static function get_logs($date, $limit = 1000, $offset = 0, $filters = array()) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        
        // Start building the WHERE clause
        $where_clauses = array();
        $query_args = array();
        
        // Always include date filter
        if (!empty($date)) {
            $where_clauses[] = "DATE(timestamp) = %s";
            $query_args[] = $date;
        }
        
        // Process additional filters
        if (!empty($filters)) {
            // IP filter (supports partial matches)
            if (!empty($filters['ip'])) {
                $where_clauses[] = "ip LIKE %s";
                $query_args[] = '%' . $wpdb->esc_like($filters['ip']) . '%';
            }
            
            // Country filter (exact match)
            if (!empty($filters['country'])) {
                $where_clauses[] = "country = %s";
                $query_args[] = $filters['country'];
            }
            
            // Region filter (exact match)
            if (!empty($filters['region'])) {
                $where_clauses[] = "region = %s";
                $query_args[] = $filters['region'];
            }
            
            // Zipcode filter (exact match)
            if (!empty($filters['zipcode'])) {
                $where_clauses[] = "zipcode = %s";
                $query_args[] = $filters['zipcode'];
            }
            
            // Status filter (allowed/blocked)
            if (isset($filters['allowed']) && $filters['allowed'] !== '') {
                $where_clauses[] = "allowed = %d";
                $query_args[] = (int)$filters['allowed'];
            }
            
            // Time range filter - start time
            if (!empty($filters['time_start'])) {
                $where_clauses[] = "TIME(timestamp) >= %s";
                $query_args[] = $filters['time_start'];
            }
            
            // Time range filter - end time
            if (!empty($filters['time_end'])) {
                $where_clauses[] = "TIME(timestamp) <= %s";
                $query_args[] = $filters['time_end'];
            }
        }
        
        // Build the final WHERE clause
        $where_clause = !empty($where_clauses) ? 'WHERE ' . implode(' AND ', $where_clauses) : '';
        
        // Add limit and offset to query args
        $query_args[] = $limit;
        $query_args[] = $offset;
        
        // Prepare and execute the query
        $sql = $wpdb->prepare(
            "SELECT id, ip, country, region, zipcode, allowed, flag_url, timestamp 
            FROM {$table_name} 
            {$where_clause} 
            ORDER BY timestamp DESC 
            LIMIT %d OFFSET %d",
            $query_args
        );
        
        return $wpdb->get_results($sql, ARRAY_A);
    }
    
    /**
     * Count total logs matching filter criteria
     *
     * @param string $date Date to get logs for (Y-m-d format)
     * @param array $filters Optional associative array of filter criteria
     * @return int Total number of matching log entries
     */
    public static function count_logs($date, $filters = array()) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        
        // Start building the WHERE clause
        $where_clauses = array();
        $query_args = array();
        
        // Always include date filter
        if (!empty($date)) {
            $where_clauses[] = "DATE(timestamp) = %s";
            $query_args[] = $date;
        }
        
        // Process additional filters
        if (!empty($filters)) {
            // IP filter (supports partial matches)
            if (!empty($filters['ip'])) {
                $where_clauses[] = "ip LIKE %s";
                $query_args[] = '%' . $wpdb->esc_like($filters['ip']) . '%';
            }
            
            // Country filter (exact match)
            if (!empty($filters['country'])) {
                $where_clauses[] = "country = %s";
                $query_args[] = $filters['country'];
            }
            
            // Region filter (exact match)
            if (!empty($filters['region'])) {
                $where_clauses[] = "region = %s";
                $query_args[] = $filters['region'];
            }
            
            // Zipcode filter (exact match)
            if (!empty($filters['zipcode'])) {
                $where_clauses[] = "zipcode = %s";
                $query_args[] = $filters['zipcode'];
            }
            
            // Status filter (allowed/blocked)
            if (isset($filters['allowed']) && $filters['allowed'] !== '') {
                $where_clauses[] = "allowed = %d";
                $query_args[] = (int)$filters['allowed'];
            }
            
            // Time range filter - start time
            if (!empty($filters['time_start'])) {
                $where_clauses[] = "TIME(timestamp) >= %s";
                $query_args[] = $filters['time_start'];
            }
            
            // Time range filter - end time
            if (!empty($filters['time_end'])) {
                $where_clauses[] = "TIME(timestamp) <= %s";
                $query_args[] = $filters['time_end'];
            }
        }
        
        // Build the final WHERE clause
        $where_clause = !empty($where_clauses) ? 'WHERE ' . implode(' AND ', $where_clauses) : '';
        
        // Prepare and execute the query
        $sql = $wpdb->prepare(
            "SELECT COUNT(*) FROM {$table_name} {$where_clause}",
            $query_args
        );
        
        return (int)$wpdb->get_var($sql);
    }
    
    /**
     * Get unique values for a column to populate filter dropdowns
     *
     * @param string $column Column to get unique values for
     * @param string $date Optional date filter
     * @return array Array of unique values
     */
    public static function get_unique_values($column, $date = '') {
        global $wpdb;
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        $column = sanitize_sql_orderby($column);
        
        // Make sure column is valid
        $valid_columns = array('ip', 'country', 'region', 'zipcode', 'allowed');
        if (!in_array($column, $valid_columns)) {
            return array();
        }
        
        $sql = "SELECT DISTINCT {$column} FROM {$table_name}";
        $args = array();
        
        // Add date filter if provided
        if (!empty($date)) {
            $sql .= " WHERE DATE(timestamp) = %s";
            $args[] = $date;
        }
        
        $sql .= " ORDER BY {$column} ASC";
        
        if (!empty($args)) {
            $sql = $wpdb->prepare($sql, $args);
        }
        
        return $wpdb->get_col($sql);
    }
    
    /**
     * Get available log dates
     *
     * @return array Array of dates with logs
     */
    public static function get_log_dates() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        
        $sql = "SELECT DISTINCT DATE(timestamp) as log_date FROM {$table_name} ORDER BY log_date DESC";
        
        return $wpdb->get_col($sql);
    }
    
    /**
     * Clear all visitor logs
     * 
     * @param string $date Optional date to clear (Y-m-d format). If empty, clears all logs.
     * @return bool Whether the operation was successful
     */
    public static function clear_logs($date = '') {
        global $wpdb;
        
        error_log("[AQM Security] clear_logs method called with date parameter: '{$date}'");
        
        // Ensure the table exists
        self::maybe_create_table();
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        error_log("[AQM Security] Using table: {$table_name}");
        
        // Check if table exists
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '{$table_name}'") === $table_name;
        if (!$table_exists) {
            error_log("[AQM Security] ERROR: Table {$table_name} does not exist!");
            return false;
        }
        
        // If date is specified, only clear logs for that date
        if (!empty($date)) {
            error_log("[AQM Security] Clearing logs for specific date: {$date}");
            $query = $wpdb->prepare("DELETE FROM {$table_name} WHERE DATE(timestamp) = %s", $date);
            error_log("[AQM Security] Running query: {$query}");
            
            $result = $wpdb->query($query);
            
            error_log("[AQM Security] Cleared visitor logs for date: {$date}. Result: " . ($result !== false ? $result : 'Failed') . ", Last error: {$wpdb->last_error}");
            
            return $result !== false;
        }
        
        // Clear all logs
        error_log("[AQM Security] Clearing ALL logs (empty date parameter)");
        $query = "TRUNCATE TABLE {$table_name}";
        error_log("[AQM Security] Running query: {$query}");
        
        $result = $wpdb->query($query);
        
        error_log("[AQM Security] Cleared all visitor logs. Result: " . ($result !== false ? 'Success' : 'Failed') . ", Last error: {$wpdb->last_error}");
        
        return $result !== false;
    }
    
    /**
     * Check if a log entry already exists for a specific IP address
     * 
     * @param string $ip Visitor IP address to check
     * @return bool Whether an entry exists
     */
    public static function has_log_entry($ip) {
        global $wpdb;
        
        // Ensure the table exists
        self::maybe_create_table();
        
        // Get the full table name with prefix
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        
        // Sanitize input
        $ip = sanitize_text_field($ip);
        
        // Get test mode setting
        $test_mode = get_option('aqm_security_test_mode', false);
        
        // If in test mode, consider each log unique to allow simulation of different IPs
        if ($test_mode) {
            $test_ip = get_option('aqm_security_test_ip', '');
            if (!empty($test_ip) && $ip === $test_ip) {
                // In test mode with test IP, check if we've logged this IP recently (in the last minute)
                // This allows for multiple test sessions while preventing duplicates within same session
                $one_minute_ago = date('Y-m-d H:i:s', strtotime('-1 minute'));
                $existing = $wpdb->get_var($wpdb->prepare(
                    "SELECT COUNT(*) FROM $table_name WHERE ip = %s AND timestamp > %s",
                    $ip,
                    $one_minute_ago
                ));
                
                // Debug logging
                error_log("[AQM Security] Test mode active - Checking for recent log entry for test IP: $ip - Found recent: " . ($existing > 0 ? 'Yes' : 'No'));
                
                return $existing > 0;
            }
        }
        
        // For non-test mode or if not using test IP, check if an entry exists for this IP
        $existing = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table_name WHERE ip = %s",
            $ip
        ));
        
        // Debug logging
        error_log("[AQM Security] Checking for existing log entry for IP: $ip - Found: " . ($existing > 0 ? 'Yes' : 'No'));
        
        return $existing > 0;
    }
    
    /**
     * Get visitor data by IP address from the logs
     * 
     * @param string $ip Visitor IP address to look up
     * @return array|false Visitor data array or false if not found
     */
    public static function get_visitor_by_ip($ip) {
        global $wpdb;
        
        // Ensure the table exists
        self::maybe_create_table();
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        
        // Get the throttle interval from settings, default to 24 hours (86400 seconds)
        $throttle_interval = intval(get_option('aqm_security_log_throttle', 86400));
        
        // Calculate the cutoff time based on the throttle interval
        $dt = new DateTime('now', new DateTimeZone('UTC'));
        $dt->modify('-' . $throttle_interval . ' seconds');
        $cutoff_time = $dt->format('Y-m-d H:i:s');
        
        // Get the most recent log entry for this IP that's within the throttle interval
        $query = $wpdb->prepare(
            "SELECT * FROM {$table_name} WHERE ip = %s AND timestamp >= %s ORDER BY timestamp DESC LIMIT 1",
            $ip,
            $cutoff_time
        );
        
        $result = $wpdb->get_row($query, ARRAY_A);
        
        if ($result) {
            self::debug_log("Found existing log entry for IP: {$ip} (ID: {$result['id']})");
            return array(
                'ip' => $result['ip'],
                'country_code' => $result['country'],
                'country_name' => $result['country'],
                'region_code' => $result['region'],
                'region' => $result['region'],
                'zip' => $result['zipcode'],
                'allowed' => (bool)$result['allowed'],
                'location' => array(
                    'country_flag' => $result['flag_url'],
                )
            );
        }
        
        self::debug_log("No recent log entry found for IP: {$ip}");
        return false;
    }
    
    /**
     * Purge old logs based on retention setting
     * 
     * @return int Number of logs purged
     */
    public static function purge_old_logs() {
        global $wpdb;
        
        // Get retention setting (in days)
        $retention_days = intval(get_option('aqm_security_log_retention', 30));
        
        // If retention is set to 0 (forever), don't purge anything
        if ($retention_days <= 0) {
            self::debug_log('Log retention set to forever, skipping purge');
            return 0;
        }
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        
        // Calculate cutoff date
        $dt = new DateTime('now', new DateTimeZone('UTC'));
        $dt->modify('-' . $retention_days . ' days');
        $cutoff_date = $dt->format('Y-m-d H:i:s');
        
        // Delete logs older than cutoff date
        $result = $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table_name} WHERE timestamp < %s",
            $cutoff_date
        ));
        
        if ($result !== false) {
            self::debug_log("Purged {$result} logs older than {$cutoff_date} (retention: {$retention_days} days)");
            return intval($result);
        } else {
            self::debug_log("Failed to purge old logs. Database error: {$wpdb->last_error}");
            return 0;
        }
    }
    
    /**
     * Debug log message
     * 
     * @param string $message Debug message
     * @return void
     */
    private static function debug_log($message) {
        if (defined('WP_DEBUG') && WP_DEBUG === true) {
            error_log('[AQM SECURITY LOGGER] ' . $message);
        }
    }
}
