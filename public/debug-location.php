<?php
/**
 * Debug Location Helper
 * 
 * This file provides a comprehensive debugging tool for the AQM Security plugin.
 * It displays detailed information about your location, the plugin's settings,
 * and how the blocking decision is being made.
 * 
 * INSTRUCTIONS:
 * 1. Upload this file to your WordPress site
 * 2. Visit any page with ?aqm_debug=1 in the URL
 * 3. The debug panel will appear at the bottom right of the screen
 */

// Only run on the frontend when debug parameter is present
if (!is_admin() && isset($_GET['aqm_debug'])) {
    // Add our debug panel to the footer
    add_action('wp_footer', 'aqm_security_debug_panel');
    
    // Force clear the cache
    add_action('init', function() {
        if (class_exists('AQM_Security_API')) {
            AQM_Security_API::clear_geolocation_cache();
        }
    });
}

/**
 * Display the debug panel
 */
function aqm_security_debug_panel() {
    if (!class_exists('AQM_Security_API')) {
        echo '<div style="position:fixed; bottom:10px; right:10px; background:#f8d7da; color:#721c24; border:1px solid #f5c6cb; padding:15px; z-index:9999; max-width:400px;">';
        echo '<h3>AQM Security Error</h3>';
        echo 'The AQM Security plugin is not active or not properly installed.';
        echo '</div>';
        return;
    }
    
    // Get fresh geolocation data
    $visitor = AQM_Security_API::get_visitor_geolocation(true);
    
    // Check if visitor is allowed
    $is_allowed = AQM_Security_API::is_visitor_allowed($visitor);
    
    // Get plugin settings
    $settings = aqm_security_get_all_settings();
    
    // Get detailed state check info
    $state_check_info = aqm_security_get_state_check_info($visitor, $settings);
    
    // Get cache info
    $cache_info = aqm_security_get_cache_info();
    
    // Output the debug panel
    echo '<div style="position:fixed; bottom:10px; right:10px; background:#fff; border:1px solid #ccc; padding:15px; z-index:9999; width:400px; max-height:80vh; overflow-y:auto; font-family:sans-serif; font-size:13px; box-shadow:0 0 10px rgba(0,0,0,0.1);">';
    
    // Header
    echo '<div style="margin-bottom:15px; border-bottom:1px solid #eee; padding-bottom:10px;">';
    echo '<h2 style="margin:0 0 5px 0; font-size:18px;">AQM Security Debug</h2>';
    echo '<div style="display:flex; justify-content:space-between;">';
    echo '<span>Plugin Version: ' . AQM_SECURITY_VERSION . '</span>';
    echo '<span style="background:' . ($is_allowed ? '#d4edda' : '#f8d7da') . '; color:' . ($is_allowed ? '#155724' : '#721c24') . '; padding:2px 8px; border-radius:3px; font-weight:bold;">' . ($is_allowed ? 'ALLOWED' : 'BLOCKED') . '</span>';
    echo '</div>';
    echo '</div>';
    
    // Your Location
    echo '<div style="margin-bottom:15px;">';
    echo '<h3 style="margin:0 0 8px 0; font-size:16px;">Your Location</h3>';
    echo '<table style="width:100%; border-collapse:collapse;">';
    echo '<tr><td style="padding:4px 0; font-weight:bold;">IP Address:</td><td>' . esc_html($visitor['ip'] ?? 'Unknown') . '</td></tr>';
    echo '<tr><td style="padding:4px 0; font-weight:bold;">Country:</td><td>' . esc_html(($visitor['country_code'] ?? 'Unknown') . ' - ' . ($visitor['country'] ?? 'Unknown')) . '</td></tr>';
    echo '<tr><td style="padding:4px 0; font-weight:bold;">State Code:</td><td>' . esc_html($visitor['region_code'] ?? 'Unknown') . '</td></tr>';
    echo '<tr><td style="padding:4px 0; font-weight:bold;">State Name:</td><td>' . esc_html($visitor['region'] ?? 'Unknown') . '</td></tr>';
    echo '</table>';
    echo '</div>';
    
    // Plugin Settings
    echo '<div style="margin-bottom:15px;">';
    echo '<h3 style="margin:0 0 8px 0; font-size:16px;">Plugin Settings</h3>';
    echo '<table style="width:100%; border-collapse:collapse;">';
    echo '<tr><td style="padding:4px 0; font-weight:bold;">Test Mode:</td><td>' . ($settings['test_mode'] ? 'Enabled' : 'Disabled') . '</td></tr>';
    if ($settings['test_mode']) {
        echo '<tr><td style="padding:4px 0; font-weight:bold;">Test IP:</td><td>' . esc_html($settings['test_ip']) . '</td></tr>';
    }
    echo '<tr><td style="padding:4px 0; font-weight:bold;">Allowed Countries:</td><td>' . (empty($settings['allowed_countries']) ? '<em>None</em>' : esc_html(implode(', ', $settings['allowed_countries']))) . '</td></tr>';
    echo '<tr><td style="padding:4px 0; font-weight:bold;">Allowed States:</td><td>' . (empty($settings['allowed_states']) ? '<em>None</em>' : esc_html(implode(', ', $settings['allowed_states']))) . '</td></tr>';
    echo '</table>';
    echo '</div>';
    
    // State Check Details
    echo '<div style="margin-bottom:15px;">';
    echo '<h3 style="margin:0 0 8px 0; font-size:16px;">State Check Details</h3>';
    echo '<div style="background:' . ($state_check_info['state_check'] ? '#d4edda' : '#f8d7da') . '; color:' . ($state_check_info['state_check'] ? '#155724' : '#721c24') . '; padding:8px; margin-bottom:10px; border-radius:3px;">';
    echo 'State Check: <strong>' . ($state_check_info['state_check'] ? 'PASS' : 'FAIL') . '</strong>';
    echo '</div>';
    echo '<p><strong>Your State (upper):</strong> ' . esc_html($state_check_info['visitor_region']) . '</p>';
    echo '<p><strong>Allowed States (upper):</strong> ' . (empty($state_check_info['allowed_states_upper']) ? '<em>None</em>' : esc_html(implode(', ', $state_check_info['allowed_states_upper']))) . '</p>';
    echo '<p><strong>Comparison Result:</strong> ' . ($state_check_info['state_check'] ? 'Your state is in the allowed list or no states are configured' : 'Your state is NOT in the allowed list') . '</p>';
    echo '</div>';
    
    // Cache Information
    echo '<div style="margin-bottom:15px;">';
    echo '<h3 style="margin:0 0 8px 0; font-size:16px;">Cache Information</h3>';
    echo '<p>Cache was cleared when this page loaded.</p>';
    echo '<p><strong>Cached Items Found:</strong> ' . count($cache_info) . '</p>';
    if (!empty($cache_info)) {
        echo '<ul style="margin:5px 0; padding-left:20px;">';
        foreach ($cache_info as $item) {
            echo '<li>' . esc_html($item) . '</li>';
        }
        echo '</ul>';
    }
    echo '</div>';
    
    // Actions
    echo '<div style="margin-top:15px; border-top:1px solid #eee; padding-top:10px; text-align:center;">';
    echo '<p>Refresh the page to perform a new check with fresh data.</p>';
    echo '<a href="' . esc_url(admin_url('admin.php?page=aqm-security-settings')) . '" style="display:inline-block; background:#0073aa; color:#fff; padding:5px 10px; text-decoration:none; border-radius:3px;">Go to Settings</a>';
    echo '</div>';
    
    echo '</div>';
}

/**
 * Get all relevant plugin settings
 * 
 * @return array Plugin settings
 */
function aqm_security_get_all_settings() {
    $settings = array(
        'test_mode' => get_option('aqm_security_test_mode', false),
        'test_ip' => get_option('aqm_security_test_ip', ''),
        'allowed_countries' => array(),
        'allowed_states' => array(),
        'blocked_message' => get_option('aqm_security_blocked_message', 'Sorry, but we do not offer services in {location}.'),
    );
    
    // Process allowed countries
    $allowed_countries = explode("\n", get_option('aqm_security_allowed_countries', ''));
    $allowed_countries = array_map('trim', $allowed_countries);
    $allowed_countries = array_filter($allowed_countries);
    
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
    $settings['allowed_countries'] = $processed_countries;
    
    // Process allowed states
    $allowed_states = explode("\n", get_option('aqm_security_allowed_states', ''));
    $allowed_states = array_map('trim', $allowed_states);
    $allowed_states = array_filter($allowed_states);
    
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
    $settings['allowed_states'] = $processed_states;
    
    return $settings;
}

/**
 * Get detailed information about the state check
 * 
 * @param array $visitor Visitor data
 * @param array $settings Plugin settings
 * @return array State check information
 */
function aqm_security_get_state_check_info($visitor, $settings) {
    // Get visitor region code
    $visitor_region = strtoupper(isset($visitor['region_code']) ? $visitor['region_code'] : '');
    
    // Convert all allowed values to uppercase for consistent comparison
    $allowed_states_upper = array_map('strtoupper', $settings['allowed_states']);
    
    // Check if state matches (if states list is present)
    $state_check = empty($allowed_states_upper) ? true : in_array($visitor_region, $allowed_states_upper);
    
    return array(
        'visitor_region' => $visitor_region,
        'allowed_states_upper' => $allowed_states_upper,
        'state_check' => $state_check,
    );
}

/**
 * Get information about the cache
 * 
 * @return array Cache information
 */
function aqm_security_get_cache_info() {
    global $wpdb;
    
    $cache_items = array();
    
    // Get all transients with our prefix
    $results = $wpdb->get_results("SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE '%_transient_aqm_security_%'");
    
    foreach ($results as $result) {
        $cache_items[] = $result->option_name;
    }
    
    return $cache_items;
}
