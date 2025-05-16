<?php
/**
 * Admin functionality for AQM Security
 */
class AQM_Security_Admin {

    /**
     * Initialize the class
     */
    public function __construct() {
        // Add menu items
        add_action('admin_menu', array($this, 'add_menu_items'));
        
        // Register settings
        add_action('admin_init', array($this, 'register_settings'));
        
        // Enqueue admin assets
        add_action('admin_enqueue_scripts', array($this, 'enqueue_assets'));
        
        // Register plugin hooks for admin
        $this->init();
    }

    /**
     * Add admin menu items
     */
    public function add_menu_items() {
        // Add top level menu
        add_menu_page(
            __('AQM Security', 'aqm-security'),
            __('AQM Security', 'aqm-security'),
            'manage_options',
            'aqm-security',
            array($this, 'display_plugin_settings_page'),
            'dashicons-shield',
            100
        );
        
        // Add settings submenu
        add_submenu_page(
            'aqm-security',
            __('Settings', 'aqm-security'),
            __('Settings', 'aqm-security'),
            'manage_options',
            'aqm-security',
            array($this, 'display_plugin_settings_page')
        );
        
        // Add logs submenu
        add_submenu_page(
            'aqm-security',
            __('Visitor Logs', 'aqm-security'),
            __('Visitor Logs', 'aqm-security'),
            'manage_options',
            'aqm-security-logs',
            array($this, 'display_logs_page')
        );
    }

    /**
     * Enqueue admin assets
     */
    public function enqueue_assets($hook) {
        // Only load on plugin pages
        if (strpos($hook, 'aqm-security') === false) {
            return;
        }
        
        // Enqueue styles
        $this->enqueue_styles();
        
        // Enqueue scripts
        $this->enqueue_scripts($hook);
    }

    /**
     * Register the stylesheets for the admin area.
     */
    public function enqueue_styles() {
        wp_enqueue_style(
            'aqm-security-admin', 
            AQM_SECURITY_PLUGIN_URL . 'admin/css/aqm-security-admin.css', 
            array(), 
            AQM_SECURITY_VERSION, 
            'all'
        );
    }

    /**
     * Register the JavaScript for the admin area.
     */
    public function enqueue_scripts($hook) {
        // Only load on our plugin pages
        if (strpos($hook, 'aqm-security') === false) {
            return;
        }
        
        wp_enqueue_script(
            'aqm-security-admin', 
            AQM_SECURITY_PLUGIN_URL . 'admin/js/aqm-security-admin.js', 
            array('jquery'), 
            AQM_SECURITY_VERSION, 
            false
        );
        
        wp_localize_script('aqm-security-admin', 'aqmSecurityAdmin', array(
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('aqm_security_admin_nonce'),
            'confirmClearLogs' => __('Are you sure you want to clear all visitor logs for this date? This cannot be undone.', 'aqm-security'),
            'confirmClearAllLogs' => __('Are you sure you want to clear ALL visitor logs across all dates? This action cannot be undone.', 'aqm-security'),
            'confirmClearDebug' => __('Are you sure you want to clear the debug log? This cannot be undone.', 'aqm-security'),
            'confirmClearCache' => __('Are you sure you want to clear the visitor geolocation cache? This will force fresh API lookups for all visitors.', 'aqm-security')
        ));
    }

    /**
     * Register all settings fields
     */
    public function register_settings() {
        // Register settings
        register_setting('aqm_security_options', 'aqm_security_api_key');
        register_setting('aqm_security_options', 'aqm_security_blocked_ips');
        register_setting('aqm_security_options', 'aqm_security_allowed_countries');
        register_setting('aqm_security_options', 'aqm_security_allowed_states');
        // ZIP code option removed in version 2.0.7
        register_setting('aqm_security_options', 'aqm_security_enable_debug');
        register_setting('aqm_security_options', 'aqm_security_test_mode');
        register_setting('aqm_security_options', 'aqm_security_test_ip');
        register_setting('aqm_security_options', 'aqm_security_blocked_message');
        register_setting('aqm_security_options', 'aqm_security_log_throttle', array(
            'default' => 86400, // Default to 24 hours (86400 seconds)
            'sanitize_callback' => 'absint' // Ensure it's a positive integer
        ));
        
        // Add callback to clear visitor cache when settings are updated
        add_action('update_option_aqm_security_allowed_countries', array($this, 'clear_visitor_cache'), 10, 2);
        add_action('update_option_aqm_security_allowed_states', array($this, 'clear_visitor_cache'), 10, 2);
        // ZIP code option removed in version 2.0.7
        add_action('update_option_aqm_security_blocked_ips', array($this, 'clear_visitor_cache'), 10, 2);
        
        // Add API settings section
        add_settings_section(
            'aqm_security_api_section',
            __('API Settings', 'aqm-security'),
            array($this, 'render_api_section'),
            'aqm-security'
        );
        
        // Add API key field
        add_settings_field(
            'aqm_security_api_key',
            __('API Key', 'aqm-security'),
            array($this, 'render_api_key_field'),
            'aqm-security',
            'aqm_security_api_section'
        );
        
        // Add geolocation rules section
        add_settings_section(
            'aqm_security_rules_section',
            __('Geolocation Rules', 'aqm-security'),
            array($this, 'render_rules_section'),
            'aqm-security'
        );
        
        // Add blocked IPs field
        add_settings_field(
            'aqm_security_blocked_ips',
            __('Blocked IP Addresses', 'aqm-security'),
            array($this, 'render_blocked_ips_field'),
            'aqm-security',
            'aqm_security_rules_section'
        );
        
        // Add allowed countries field
        add_settings_field(
            'aqm_security_allowed_countries',
            __('Allowed Countries', 'aqm-security'),
            array($this, 'render_allowed_countries_field'),
            'aqm-security',
            'aqm_security_rules_section'
        );
        
        // Add allowed states field
        add_settings_field(
            'aqm_security_allowed_states',
            __('Allowed States/Regions', 'aqm-security'),
            array($this, 'render_allowed_states_field'),
            'aqm-security',
            'aqm_security_rules_section'
        );
        
        // Add message settings section
        add_settings_section(
            'aqm_security_message_settings_section',
            __('Message Settings', 'aqm-security'),
            array($this, 'render_message_settings_section'),
            'aqm-security'
        );
        
        // Add blocked message field
        add_settings_field(
            'aqm_security_blocked_message',
            __('Blocked Message', 'aqm-security'),
            array($this, 'render_blocked_message_field'),
            'aqm-security',
            'aqm_security_message_settings_section'
        );
        
        // Add advanced section
        add_settings_section(
            'aqm_security_advanced_section',
            __('Advanced Settings', 'aqm-security'),
            array($this, 'render_advanced_section'),
            'aqm-security'
        );
        
        // Add debug field
        add_settings_field(
            'aqm_security_enable_debug',
            __('Enable Debug Logging', 'aqm-security'),
            array($this, 'render_enable_debug_field'),
            'aqm-security',
            'aqm_security_advanced_section'
        );
        
        // Add test mode field
        add_settings_field(
            'aqm_security_test_mode',
            __('Enable Test Mode', 'aqm-security'),
            array($this, 'render_test_mode_field'),
            'aqm-security',
            'aqm_security_advanced_section'
        );
        
        // Add test IP field
        add_settings_field(
            'aqm_security_test_ip',
            __('Test IP Address', 'aqm-security'),
            array($this, 'render_test_ip_field'),
            'aqm-security',
            'aqm_security_advanced_section',
            array('class' => 'aqm-security-test-ip-field')
        );
        
        // Add logging throttle field
        add_settings_field(
            'aqm_security_log_throttle',
            __('Visitor Logging Throttle', 'aqm-security'),
            array($this, 'render_log_throttle_field'),
            'aqm-security',
            'aqm_security_advanced_section'
        );
    }
    
    /**
     * Register plugin hooks for admin
     */
    public function init() {
        // Make sure logger table exists
        if (method_exists('AQM_Security_Logger', 'maybe_create_table')) {
            AQM_Security_Logger::maybe_create_table();
        }
        
        // Add settings page
        add_action('admin_menu', array($this, 'add_menu_items'));
        
        // Register settings
        add_action('admin_init', array($this, 'register_settings'));
        
        // Add AJAX handlers
        add_action('wp_ajax_aqm_security_test_api', array($this, 'ajax_test_api'));
        add_action('wp_ajax_aqm_security_download_logs', array($this, 'ajax_download_logs'));
        add_action('wp_ajax_aqm_security_clear_logs', array($this, 'ajax_clear_logs'));
        add_action('wp_ajax_aqm_security_clear_visitor_logs', array($this, 'ajax_clear_visitor_logs'));
        add_action('wp_ajax_aqm_security_clear_all_visitor_logs', array($this, 'ajax_clear_all_visitor_logs'));
        add_action('wp_ajax_aqm_security_download_log', array($this, 'ajax_download_log'));
        add_action('wp_ajax_aqm_security_clear_cache', array($this, 'ajax_clear_cache'));
        
        // Add debug notice if visiting logs page with no logs
        add_action('admin_notices', array($this, 'maybe_show_debug_notice'));
    }
    
    /**
     * Show debug notice if on logs page with no logs
     */
    public function maybe_show_debug_notice() {
        $current_screen = get_current_screen();
        
        // Only show on our logs page
        if (!isset($current_screen->base) || $current_screen->base !== 'aqm-security_page_aqm-security-logs') {
            return;
        }
        
        // Get logs dates
        $dates = AQM_Security_Logger::get_log_dates();
        
        // If no logs, show debug info
        if (empty($dates)) {
            // Enable debugging if not already enabled
            if (!get_option('aqm_security_enable_debug')) {
                update_option('aqm_security_enable_debug', true);
                AQM_Security_API::debug_log('Debug logging automatically enabled to troubleshoot missing logs');
            }
            
            // Ensure test mode is enabled
            if (!get_option('aqm_security_test_mode')) {
                update_option('aqm_security_test_mode', true);
                AQM_Security_API::debug_log('Test mode automatically enabled to troubleshoot missing logs');
            }
            
            echo '<div class="notice notice-warning">';
            echo '<p><strong>' . __('AQM Security: Troubleshooting Mode', 'aqm-security') . '</strong></p>';
            echo '<p>' . __('Debug logging and Test Mode have been enabled to help diagnose why visitor logs are not appearing.', 'aqm-security') . '</p>';
            echo '<p>' . __('Try visiting your site homepage again, then check the debug log for more information.', 'aqm-security') . '</p>';
            echo '<p><a href="' . admin_url('admin.php?page=aqm-security-settings') . '" class="button">' . __('View Debug Settings', 'aqm-security') . '</a></p>';
            echo '</div>';
            
            // Force table creation again
            AQM_Security_Logger::maybe_create_table();
        }
    }
    
    /**
     * Render API section
     */
    public function render_api_section() {
        echo '<p>' . __('Configure your ipapi.com API settings here. You can get an API key by signing up at ipapi.com', 'aqm-security') . '</p>';
    }
    
    /**
     * Render API key field
     */
    public function render_api_key_field() {
        $api_key = get_option('aqm_security_api_key', '');
        
        echo '<input type="password" id="aqm_security_api_key" name="aqm_security_api_key" value="' . esc_attr($api_key) . '" class="regular-text" />';
        echo '<button type="button" id="aqm_security_test_api" class="button button-secondary">' . __('Test API', 'aqm-security') . '</button>';
        echo '<div id="aqm_security_api_test_result" style="margin-top: 10px;"></div>';
    }
    
    /**
     * Render geolocation rules section
     */
    public function render_rules_section() {
        echo '<p>' . __('Configure which visitors are allowed to access forms on your site. Leave fields blank to ignore that rule.', 'aqm-security') . '</p>';
        echo '<p>' . __('Rules are checked in this order: Blocked IPs, Allowed Countries, Allowed States.', 'aqm-security') . '</p>';
    }
    
    /**
     * Render blocked IPs field
     */
    public function render_blocked_ips_field() {
        $blocked_ips = get_option('aqm_security_blocked_ips', '');
        
        echo '<textarea id="aqm_security_blocked_ips" name="aqm_security_blocked_ips" class="large-text code" rows="5" placeholder="' . __('Enter one IP address per line', 'aqm-security') . '">' . esc_textarea($blocked_ips) . '</textarea>';
        echo '<p class="description">' . __('Enter one IP address per line. Visitors with these IPs will always be blocked.', 'aqm-security') . '</p>';
    }
    
    /**
     * Render allowed countries field
     */
    public function render_allowed_countries_field() {
        $allowed_countries = get_option('aqm_security_allowed_countries', '');
        
        echo '<textarea id="aqm_security_allowed_countries" name="aqm_security_allowed_countries" class="large-text code" rows="5" placeholder="' . __('Enter one country code per line', 'aqm-security') . '">' . esc_textarea($allowed_countries) . '</textarea>';
        echo '<p class="description">' . __('Enter one country code per line (e.g., US, CA, UK). Visitors from these countries will be allowed. Use 2-letter country codes per ISO 3166-1 alpha-2 standard.', 'aqm-security') . '</p>';
    }
    
    /**
     * Render allowed states field
     */
    public function render_allowed_states_field() {
        $allowed_states = get_option('aqm_security_allowed_states', '');
        
        echo '<textarea id="aqm_security_allowed_states" name="aqm_security_allowed_states" class="large-text code" rows="5" placeholder="' . __('Enter one state/region code per line', 'aqm-security') . '">' . esc_textarea($allowed_states) . '</textarea>';
        echo '<p class="description">' . __('Enter one state/region code per line (e.g., CA for California, TX for Texas). Visitors from these states will be allowed. Use standard region codes returned by the API.', 'aqm-security') . '</p>';
    }
    
    /**
     * Render allowed zip codes field - REMOVED in version 2.0.7
     */
    public function render_allowed_zip_codes_field() {
        // This field has been removed
    }
    
    /**
     * Render message settings section
     */
    public function render_message_settings_section() {
        echo '<p>' . __('Configure the message shown to blocked visitors when forms are hidden.', 'aqm-security') . '</p>';
    }
    
    /**
     * Render blocked message field
     */
    public function render_blocked_message_field() {
        $value = get_option('aqm_security_blocked_message', __('Form access is restricted based on your location.', 'aqm-security'));
        
        wp_editor($value, 'aqm_security_blocked_message', array(
            'textarea_name' => 'aqm_security_blocked_message',
            'textarea_rows' => 5,
            'media_buttons' => true,
            'teeny'         => false,
            'quicktags'     => true,
        ));
        
        echo '<p class="description">' . __('This message will be displayed instead of Formidable Forms for visitors from blocked locations.', 'aqm-security') . '</p>';
    }
    
    /**
     * Render advanced section
     */
    public function render_advanced_section() {
        echo '<p>' . __('Advanced settings for testing and debugging purposes.', 'aqm-security') . '</p>';
        echo '<div class="aqm-security-advanced-actions">';
        echo '<button type="button" id="aqm_security_clear_cache" class="button button-secondary">' . __('Clear Visitor Cache', 'aqm-security') . '</button>';
        echo '<span class="spinner"></span>';
        echo '<div id="aqm_security_clear_cache_result" style="display:inline-block; margin-left: 10px;"></div>';
        echo '<p class="description">' . __('Clear all cached visitor geolocation data. Use this after changing settings or if you\'re experiencing issues with visitor detection.', 'aqm-security') . '</p>';
        echo '</div>';
    }
    
    /**
     * Render enable debug field
     */
    public function render_enable_debug_field() {
        $enable_debug = get_option('aqm_security_enable_debug', false);
        
        echo '<input type="checkbox" id="aqm_security_enable_debug" name="aqm_security_enable_debug" value="1" ' . checked(1, $enable_debug, false) . ' />';
        echo '<label for="aqm_security_enable_debug">' . __('Enable debug logging to help troubleshoot issues', 'aqm-security') . '</label>';
        
        // If debug is enabled, show the log file status and clear button
        if ($enable_debug) {
            $log_file = WP_CONTENT_DIR . '/aqm-security-logs/debug.log';
            $log_size = file_exists($log_file) ? size_format(filesize($log_file)) : '0 KB';
            $download_url = admin_url('admin-ajax.php?action=aqm_security_download_log');
            
            echo '<div style="margin-top: 10px;">';
            echo '<p>' . sprintf(__('Log file size: %s', 'aqm-security'), '<strong>' . $log_size . '</strong>') . '</p>';
            echo '<div style="display: flex; gap: 10px;">';
            echo '<a href="' . esc_url($download_url) . '" class="button button-secondary" target="_blank">' . __('Download Log File', 'aqm-security') . '</a>';
            echo '<button type="button" id="aqm_security_clear_logs" class="button button-secondary">' . __('Clear Debug Log', 'aqm-security') . '</button>';
            echo '</div></div>';
        }
    }
    
    /**
     * Render test mode field
     */
    public function render_test_mode_field() {
        $test_mode = get_option('aqm_security_test_mode', false);
        
        echo '<input type="checkbox" id="aqm_security_test_mode" name="aqm_security_test_mode" value="1" ' . checked(1, $test_mode, false) . ' />';
        echo '<label for="aqm_security_test_mode">' . __('Enable test mode to simulate different IP addresses', 'aqm-security') . '</label>';
        echo '<p class="description">' . __('When enabled, the plugin will use the test IP address below instead of the actual visitor IP.', 'aqm-security') . '</p>';
    }
    
    /**
     * Render test IP field
     */
    public function render_test_ip_field() {
        $test_ip = get_option('aqm_security_test_ip', '');
        $test_mode = get_option('aqm_security_test_mode', false);
        
        // Add a warning if test mode is enabled but no IP is set
        if ($test_mode && empty($test_ip)) {
            echo '<div class="notice notice-warning inline"><p>';
            echo __('Test mode is enabled but no test IP address is set. Please enter an IP address below.', 'aqm-security');
            echo '</p></div>';
        }
        
        echo '<input type="text" id="aqm_security_test_ip" name="aqm_security_test_ip" value="' . esc_attr($test_ip) . '" class="regular-text" placeholder="8.8.8.8" />';
        echo '<p class="description">' . __('Enter an IP address to test. Examples: 8.8.8.8 (US), 212.58.244.22 (UK), 219.76.10.1 (Hong Kong)', 'aqm-security') . '</p>';
        
        // If test mode is on, add a "Test Now" button
        if ($test_mode) {
            echo '<p><a href="' . esc_url(home_url('/')) . '" target="_blank" class="button">';
            echo __('View Site with Test IP', 'aqm-security') . '</a>';
            echo ' <a href="' . esc_url(admin_url('admin.php?page=aqm-security-logs')) . '" class="button button-secondary">';
            echo __('View Visitor Logs', 'aqm-security') . '</a></p>';
        }
        
        // Add a special style and script to show/hide the field based on test mode
        echo '<style>
            .aqm-security-test-ip-field { display: none; }
            .aqm-security-test-mode-active .aqm-security-test-ip-field { display: table-row; }
        </style>';
        
        echo '<script>
            jQuery(document).ready(function($) {
                function toggleTestIPField() {
                    if($("#aqm_security_test_mode").is(":checked")) {
                        $("body").addClass("aqm-security-test-mode-active");
                    } else {
                        $("body").removeClass("aqm-security-test-mode-active");
                    }
                }
                
                // Initial state
                toggleTestIPField();
                
                // When test mode changes
                $("#aqm_security_test_mode").on("change", toggleTestIPField);
            });
        </script>';
    }
    
    /**
     * Render logging throttle field
     */
    public function render_log_throttle_field() {
        $throttle_seconds = intval(get_option('aqm_security_log_throttle', 86400));
        
        // Create dropdown options for common time intervals
        $options = array(
            0 => __('Disabled (log every visit)', 'aqm-security'),
            60 => __('1 minute', 'aqm-security'),
            300 => __('5 minutes', 'aqm-security'),
            900 => __('15 minutes', 'aqm-security'),
            1800 => __('30 minutes', 'aqm-security'),
            3600 => __('1 hour', 'aqm-security'),
            7200 => __('2 hours', 'aqm-security'),
            14400 => __('4 hours', 'aqm-security'),
            28800 => __('8 hours', 'aqm-security'),
            43200 => __('12 hours', 'aqm-security'),
            86400 => __('24 hours', 'aqm-security')
        );
        
        echo '<select id="aqm_security_log_throttle" name="aqm_security_log_throttle">';
        
        foreach ($options as $value => $label) {
            echo '<option value="' . esc_attr($value) . '" ' . selected($throttle_seconds, $value, false) . '>' . esc_html($label) . '</option>';
        }
        
        echo '</select>';
        echo '<p class="description">' . __('How often to log the same visitor IP address. This prevents multiple log entries for the same visitor during a single browsing session.', 'aqm-security') . '</p>';
    }
    
    /**
     * Display the plugin settings page
     */
    public function display_plugin_settings_page() {
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <form method="post" action="options.php">
                <?php
                // Output security fields
                settings_fields('aqm_security_options');
                
                // Output setting sections and their fields
                do_settings_sections('aqm-security');
                
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }
    
    /**
     * Display the plugin logs page
     */
    public function display_logs_page() {
        // Clear any cached results to ensure fresh display
        $logs_transient_key = 'aqm_security_logs_' . date('Y-m-d');
        delete_transient($logs_transient_key);
        
        require_once AQM_SECURITY_PLUGIN_DIR . 'admin/partials/aqm-security-logs-display.php';
    }
    
    /**
     * AJAX handler for testing the API
     */
    public function ajax_test_api() {
        // Check nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'aqm_security_admin_nonce')) {
            wp_send_json_error(array(
                'message' => __('Security check failed.', 'aqm-security')
            ));
        }
        
        // Get current admin's IP address
        $ip = AQM_Security_API::get_client_ip();
        
        // Check if this is a local/private IP which won't work with the API
        if ($ip == '127.0.0.1' || $ip == '::1' || strpos($ip, '192.168.') === 0 || strpos($ip, '10.') === 0) {
            // Use a fallback public IP for testing
            $ip = '98.118.92.174'; // Using the example IP from your temp.json
        }
        
        // Get geolocation data
        $geo_data = AQM_Security_API::get_geolocation_data($ip);
        
        if (is_wp_error($geo_data)) {
            wp_send_json_error(array(
                'message' => $geo_data->get_error_message()
            ));
        }
        
        // Return the raw API response
        wp_send_json_success(array(
            'message' => __('API test successful!', 'aqm-security'),
            'data' => $geo_data // Return the complete API response
        ));
    }
    
    /**
     * AJAX handler for downloading logs
     */
    public function ajax_download_logs() {
        // Check nonce
        if (!isset($_GET['nonce']) || !wp_verify_nonce($_GET['nonce'], 'aqm_security_admin_nonce')) {
            wp_die(__('Security check failed.', 'aqm-security'));
        }
        
        // Check if date parameter exists
        if (!isset($_GET['date']) || empty($_GET['date'])) {
            wp_die(__('Date parameter is required.', 'aqm-security'));
        }
        
        $date = sanitize_text_field($_GET['date']);
        
        // Generate CSV file
        $file_path = AQM_Security_Logger::generate_csv_for_date($date);
        
        if (!$file_path || !file_exists($file_path)) {
            wp_die(__('Error generating CSV file.', 'aqm-security'));
        }
        
        // Set headers for download
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="' . basename($file_path) . '"');
        header('Content-Length: ' . filesize($file_path));
        
        // Output file content
        readfile($file_path);
        
        // Delete the file after download
        unlink($file_path);
        
        exit;
    }
    
    /**
     * AJAX handler for clearing debug logs
     */
    public function ajax_clear_logs() {
        // Check nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'aqm_security_admin_nonce')) {
            wp_send_json_error(array(
                'message' => __('Security check failed.', 'aqm-security')
            ));
        }
        
        // Check user permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array(
                'message' => __('You do not have permission to perform this action.', 'aqm-security')
            ));
        }
        
        $log_file = WP_CONTENT_DIR . '/aqm-security-logs/debug.log';
        
        if (file_exists($log_file)) {
            // Empty the file (truncate to zero size)
            $result = file_put_contents($log_file, '');
            
            if ($result !== false) {
                wp_send_json_success(array(
                    'message' => __('Debug log file cleared.', 'aqm-security')
                ));
            } else {
                wp_send_json_error(array(
                    'message' => __('Failed to clear log file. Check file permissions.', 'aqm-security')
                ));
            }
        } else {
            wp_send_json_success(array(
                'message' => __('No log file exists yet.', 'aqm-security')
            ));
        }
    }
    
    /**
     * AJAX handler for clearing visitor logs for a specific date
     */
    public function ajax_clear_visitor_logs() {
        // Debug log the request
        error_log('[AQM Security] Clear logs for date AJAX request received: ' . print_r($_POST, true));
        
        // Check nonce for security
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'aqm_security_admin_nonce')) {
            error_log('[AQM Security] Nonce verification failed');
            wp_send_json_error(array('message' => __('Security check failed.', 'aqm-security')));
        }
        
        // Check if user has permission
        if (!current_user_can('manage_options')) {
            error_log('[AQM Security] Permission check failed');
            wp_send_json_error(array('message' => __('You do not have permission to perform this action.', 'aqm-security')));
        }
        
        // Get date parameter if set
        $date = isset($_POST['date']) ? sanitize_text_field($_POST['date']) : '';
        error_log('[AQM Security] Clearing logs with date parameter: "' . $date . '"');
        
        // Clear logs
        $result = AQM_Security_Logger::clear_logs($date);
        error_log('[AQM Security] Clear logs result: ' . ($result ? 'success' : 'failure'));
        
        if ($result) {
            $message = $date ? 
                sprintf(__('Logs for %s cleared successfully.', 'aqm-security'), $date) : 
                __('All logs cleared successfully.', 'aqm-security');
            error_log('[AQM Security] Success message: ' . $message);
            wp_send_json_success(array('message' => $message));
        } else {
            error_log('[AQM Security] Failed to clear logs');
            wp_send_json_error(array('message' => __('Failed to clear logs.', 'aqm-security')));
        }
    }
    
    /**
     * AJAX handler for clearing ALL visitor logs
     */
    public function ajax_clear_all_visitor_logs() {
        // Debug log the request
        error_log('[AQM Security] Clear ALL logs AJAX request received: ' . print_r($_POST, true));
        
        // Check nonce for security
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'aqm_security_admin_nonce')) {
            error_log('[AQM Security] Nonce verification failed');
            wp_send_json_error(array('message' => __('Security check failed.', 'aqm-security')));
        }
        
        // Check if user has permission
        if (!current_user_can('manage_options')) {
            error_log('[AQM Security] Permission check failed');
            wp_send_json_error(array('message' => __('You do not have permission to perform this action.', 'aqm-security')));
        }
        
        // Clear ALL logs using TRUNCATE
        global $wpdb;
        $table_name = $wpdb->prefix . AQM_Security_Logger::TABLE_NAME;
        
        error_log('[AQM Security] Attempting to truncate table: ' . $table_name);
        $result = $wpdb->query("TRUNCATE TABLE {$table_name}");
        
        if ($result !== false) {
            error_log('[AQM Security] Successfully truncated table: ' . $table_name);
            wp_send_json_success(array('message' => __('All logs cleared successfully.', 'aqm-security')));
        } else {
            error_log('[AQM Security] Failed to truncate table: ' . $table_name . '. Error: ' . $wpdb->last_error);
            wp_send_json_error(array('message' => __('Failed to clear all logs.', 'aqm-security')));
        }
    }
    
    /**
     * AJAX handler for downloading the log file
     */
    public function ajax_download_log() {
        // Verify permissions
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have permission to perform this action.', 'aqm-security'));
        }
        
        $log_file = WP_CONTENT_DIR . '/aqm-security-logs/debug.log';
        
        if (file_exists($log_file)) {
            // Set headers for file download
            header('Content-Description: File Transfer');
            header('Content-Type: text/plain');
            header('Content-Disposition: attachment; filename="aqm-security-debug.log"');
            header('Expires: 0');
            header('Cache-Control: must-revalidate');
            header('Pragma: public');
            header('Content-Length: ' . filesize($log_file));
            
            // Clear output buffer
            ob_clean();
            flush();
            
            // Output file contents
            readfile($log_file);
            exit;
        } else {
            wp_die(__('Debug log file does not exist.', 'aqm-security'));
        }
    }
    
    /**
     * AJAX handler for clearing the visitor cache
     */
    public function ajax_clear_cache() {
        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You do not have permission to perform this action.', 'aqm-security')));
        }
        
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'aqm_security_admin_nonce')) {
            wp_send_json_error(array('message' => __('Security check failed.', 'aqm-security')));
        }
        
        // Clear the cache
        AQM_Security_API::clear_geolocation_cache();
        
        // Log the action
        AQM_Security_API::debug_log('Visitor cache cleared manually by admin');
        
        // Send success response
        wp_send_json_success(array(
            'message' => __('Visitor geolocation cache cleared successfully!', 'aqm-security'),
            'timestamp' => current_time('mysql')
        ));
    }
    
    /**
     * Clear visitor cache when settings are updated
     */
    public function clear_visitor_cache($old_value, $new_value) {
        // Clear any existing visitor data transients to ensure settings take effect immediately
        AQM_Security_API::clear_geolocation_cache();
        
        // Force log a message to indicate settings were updated
        error_log('[AQM Security] Settings updated: forcing visitor cache clear');
        
        // If settings that affect visitor access have changed, clear all Formidable Forms caches too
        $access_settings = ['allowed_countries', 'allowed_states', 'test_mode', 'test_ip'];
        $update_access = false;
        
        foreach ($access_settings as $setting) {
            $old_setting = isset($old_value['aqm_security_' . $setting]) ? $old_value['aqm_security_' . $setting] : '';
            $new_setting = isset($new_value['aqm_security_' . $setting]) ? $new_value['aqm_security_' . $setting] : '';
            
            if ($old_setting != $new_setting) {
                $update_access = true;
                error_log('[AQM Security] Access-related setting changed: ' . $setting);
                break;
            }
        }
        
        if ($update_access && function_exists('FrmFormActionsController::delete_cache_for_all_forms')) {
            // Clear Formidable Forms cache if available
            FrmFormActionsController::delete_cache_for_all_forms();
            error_log('[AQM Security] Formidable Forms cache cleared');
        }
    }
}
