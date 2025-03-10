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
     * @param string $zip Visitor zip code
     * @param bool $allowed Whether the visitor is allowed
     * @param string $country_flag URL to the country flag
     * @param bool $force_new Force a new log entry even if recent entry exists
     * @return int|bool Last insert ID or false on failure
     */
    public static function log_visitor($ip, $country, $region, $zip, $allowed, $country_flag = '', $force_new = false) {
        global $wpdb;
        
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
        $zip = sanitize_text_field($zip);
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
            return $existing_id;
        } else {
            // No existing entry, insert a new one
            $result = $wpdb->insert($table_name, $data, $format);
            
            if ($result === false) {
                error_log("[AQM Security] Failed to log visitor. Database error: " . $wpdb->last_error);
                return false;
            }
            
            error_log("[AQM Security] Successfully logged visitor with ID: " . $wpdb->insert_id);
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
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        
        // If date is specified, only clear logs for that date
        if (!empty($date)) {
            $result = $wpdb->query(
                $wpdb->prepare(
                    "DELETE FROM {$table_name} WHERE DATE(timestamp) = %s",
                    $date
                )
            );
            
            error_log("[AQM Security] Cleared visitor logs for date: {$date}. Result: " . ($result !== false ? $result : 'Failed'));
            
            return $result !== false;
        }
        
        // Clear all logs
        $result = $wpdb->query("TRUNCATE TABLE {$table_name}");
        
        error_log("[AQM Security] Cleared all visitor logs. Result: " . ($result !== false ? 'Success' : 'Failed'));
        
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
     * Debug log message
     * 
     * @param string $message Debug message
     * @return void
     */
    private static function debug_log($message) {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('[AQM Security Logger] ' . $message);
        }
    }
}
