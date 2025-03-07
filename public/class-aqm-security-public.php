<?php
/**
 * The public-facing functionality of the plugin.
 */
class AQM_Security_Public {

    /**
     * Visitor geolocation data
     * 
     * @var array
     */
    private $geo_data = null;
    
    /**
     * Whether visitor is allowed
     * 
     * @var bool|null
     */
    private $is_allowed = null;

    /**
     * Initialize the class and set its properties.
     *
     * @since    1.0.0
     * @param      string    $plugin_name       The name of the plugin.
     * @param      string    $version    The version of this plugin.
     */
    public function __construct($plugin_name = 'aqm-security', $version = '1.0.0') {
        $this->plugin_name = $plugin_name;
        $this->version = $version;
        
        // Initialize properties
        $this->is_allowed = null;
        $this->geo_data = null;
        
        // Initialize shortcodes first
        add_action('init', array($this, 'initialize_shortcodes'), 5);
        
        // Initialize geolocation check on init to ensure it runs for all pages
        add_action('init', array($this, 'initialize_geolocation_check'), 10);
        
        // Add hooks for the plugin's main functionality
        add_action('wp_enqueue_scripts', array($this, 'enqueue_styles'));
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        
        // Initialize Formidable Forms hooks if class exists
        if (class_exists('FrmForm')) {
            // Filter for form display
            add_filter('frm_form_options_before_update', array($this, 'check_formidable_options'), 10, 1);
            
            // Ensure the formidable forms hooks are set up properly
            add_action('wp_loaded', function() {
                // Reset any form blocking on each page load to ensure consistent behavior
                delete_option('aqm_security_forms_blocked');
            }, 1);
        }
    }

    /**
     * Initialize shortcodes early to ensure they're properly replaced
     */
    public function initialize_shortcodes() {
        // Register shortcode for blocked form message
        add_shortcode('aqm_blocked_form', array($this, 'blocked_form_shortcode'));
        
        // Check if Formidable Forms is active
        if (!class_exists('FrmForm')) {
            return;
        }
        
        // Store the original shortcode handler
        global $shortcode_tags;
        if (isset($shortcode_tags['formidable'])) {
            // Save the original handler for later restoration if needed
            $this->original_formidable_shortcode = $shortcode_tags['formidable'];
        }
    }
    
    /**
     * Initialize geolocation check early in the page load
     */
    public function initialize_geolocation_check() {
        try {
            // Skip admin pages and AJAX requests
            if (is_admin() || (defined('DOING_AJAX') && DOING_AJAX)) {
                return;
            }
            
            // Get visitor data and check if they're allowed
            $this->check_geolocation();

            // CRITICAL: Apply form blocking immediately - don't wait for template redirect
            // Forms must be blocked if visitor is explicitly blocked
            if (isset($this->is_allowed) && $this->is_allowed === false) {
                $this->apply_formidable_visibility(false);
                
                // Force CSS to be added to head to hide forms
                add_action('wp_head', array($this, 'add_blocked_form_styles'), 1);
                
                // Add stronger direct output of CSS right away
                add_action('wp_print_styles', function() {
                    echo '<style type="text/css">
                        .aqm-security-blocked-message {
                            padding: 15px !important;
                            background-color: #f8d7da !important;
                            color: #721c24 !important;
                            border: 1px solid #f5c6cb !important;
                            border-radius: 4px !important;
                            margin: 10px 0 !important;
                            font-size: 16px !important;
                            text-align: center !important;
                        }
                        
                        /* Hide ANY forms that might slip through with !important flags */
                        .frm_forms, .with_frm_style, .frm_form_fields, .frm-show-form, 
                        .frm_js_validation, .frm_logic_form, .frm_page_num_form, .frm_no_hide_form, 
                        .frm_form_field, .frm-show-form, .frm_first_form, form.frm-show-form { 
                            display: none !important; 
                            visibility: hidden !important;
                            opacity: 0 !important;
                            height: 0 !important;
                            overflow: hidden !important;
                        }
                    </style>';
                }, 1);
                
                // Log the form blocking
                error_log("[AQM Security] Forms blocked for visitor with IP: " . AQM_Security_API::get_client_ip());
            } else {
                // Debug log for allowed visitors
                error_log("[AQM Security] Visitor is allowed, forms should be visible");
                
                // Ensure any form blocking from previous checks is removed
                $this->restore_formidable_forms();
            }
            
            // Ensure visitor is logged for all page types
            if ($this->is_allowed === null) {
                error_log("[AQM Security] WARNING: is_allowed is null - forcing visitor data collection");
                $visitor = AQM_Security_API::get_visitor_geolocation(true);
                if ($visitor) {
                    $this->log_visitor_access(false, $visitor);
                }
            }
        } catch (Exception $e) {
            AQM_Security_API::debug_log('Error initializing geolocation check: ' . $e->getMessage());
        }
    }
    
    /**
     * Check visitor's geolocation and determine if they are allowed
     * 
     * @return bool Whether the visitor is allowed
     */
    public function check_geolocation() {
        static $already_checked = false;
        
        // Avoid running this multiple times per request
        if ($already_checked) {
            return $this->is_allowed;
        }
        
        try {
            $already_checked = true;
            
            // Check if test mode is enabled - get fresh from options
            $test_mode = get_option('aqm_security_test_mode', false);
            
            // Skip all checks for admin users when not in test mode
            if (current_user_can('manage_options') && !$test_mode) {
                $this->is_allowed = true;
                $this->log_visitor_access($test_mode);
                return $this->is_allowed;
            }
            
            // Always get fresh visitor data and FORCE check against IP block list
            $visitor = AQM_Security_API::get_visitor_geolocation(true);
            
            // Make sure we have visitor data
            if (!$visitor || empty($visitor)) {
                // Default to allowing access if we can't get visitor data
                AQM_Security_API::debug_log('Could not get visitor data, defaulting to allowed');
                $this->is_allowed = true;
                $this->geo_data = null;
                return $this->is_allowed;
            }
            
            // Store visitor data for later use
            $this->geo_data = $visitor;
            
            // Check if visitor should be blocked or allowed based on blocklist
            // CRITICAL: Always check this fresh even if we've checked before
            $this->is_allowed = AQM_Security_API::is_visitor_allowed($visitor);
            
            // Log visitor access
            $this->log_visitor_access($test_mode, $visitor);
            
            // Additional logging to help troubleshoot IP blocking
            $visitor_ip = isset($visitor['ip']) ? $visitor['ip'] : 'unknown';
            error_log("[AQM Security] Visitor IP checked: $visitor_ip - Access allowed: " . 
                ($this->is_allowed ? 'Yes' : 'NO - BLOCKED!'));
            
            return $this->is_allowed;
        } catch (Exception $e) {
            // Default to allowing access in case of errors
            AQM_Security_API::debug_log('Error checking geolocation: ' . $e->getMessage());
            $this->is_allowed = true;
            return $this->is_allowed;
        }
    }
    
    /**
     * Restore Formidable Forms functionality
     */
    private function restore_formidable_forms() {
        if (!class_exists('FrmForm')) {
            return;
        }
        
        // Clear any previous form block status
        update_option('aqm_security_forms_blocked', false);
        
        // Remove our custom shortcodes if they exist
        remove_shortcode('formidable');
        remove_shortcode('display-frm-data');
        remove_shortcode('frm-stats');
        
        // Remove our hooks
        remove_action('frm_pre_get_form', array($this, 'prevent_form_display'), 1);
        remove_filter('frm_display_entries_content', array($this, 'blocked_form_content'), 10);
        
        // Re-register original Formidable shortcodes
        if (class_exists('FrmFormsController') && method_exists('FrmFormsController', 'get_form_shortcode')) {
            add_shortcode('formidable', 'FrmFormsController::get_form_shortcode');
        }
        
        if (class_exists('FrmEntriesController') && method_exists('FrmEntriesController', 'get_shortcode')) {
            add_shortcode('display-frm-data', 'FrmEntriesController::get_shortcode');
        }
        
        if (class_exists('FrmStatisticsController') && method_exists('FrmStatisticsController', 'stats_shortcode')) {
            add_shortcode('frm-stats', 'FrmStatisticsController::stats_shortcode');
        }
        
        AQM_Security_API::debug_log('Original Formidable Forms functionality restored');
    }
    
    /**
     * Apply Formidable Forms visibility settings
     * 
     * @param bool $is_allowed Whether the visitor is allowed
     */
    public function apply_formidable_visibility($is_allowed) {
        // Only apply if Formidable Forms is active
        if (!class_exists('FrmForm')) {
            return;
        }
        
        if (!$is_allowed) {
            // If visitor is not allowed, replace form content with blocked message
            AQM_Security_API::debug_log('BLOCKING FORMS: Applying form restrictions for blocked visitor');
            
            // 1. Hook into pre_get_form to prevent the form from being displayed
            add_filter('frm_pre_get_form', array($this, 'prevent_form_display'), 1, 3);
            
            // 2. Replace ALL Formidable shortcodes with our blocked message
            if (function_exists('frm_replace_shortcodes')) {
                remove_shortcode('formidable');
                add_shortcode('formidable', array($this, 'blocked_form_shortcode'));
            }
            
            if (function_exists('frm_display_entries_shortcode')) {
                remove_shortcode('display-frm-data');
                add_shortcode('display-frm-data', array($this, 'blocked_form_shortcode'));
            }
            
            // 3. Also hook into content filters to catch any forms that slip through
            add_filter('the_content', array($this, 'replace_form_content'), 1);
            add_filter('widget_text', array($this, 'replace_form_content'), 1);
            
            // 4. Add a filter to block form HTML directly
            add_filter('frm_main_form_tag', array($this, 'prevent_form_display'), 1, 3);
            add_filter('frm_submit_button_html', '__return_false', 1);
            add_filter('frm_form_fields_html', array($this, 'prevent_form_display'), 1, 3);
            
            // 5. Add styles for the blocked form message
            add_action('wp_head', array($this, 'add_blocked_form_styles'), 1);
            
            // 6. Set a flag that forms are blocked
            update_option('aqm_security_forms_blocked', true);
            
            AQM_Security_API::debug_log('Formidable Forms visibility rules applied for blocked visitor');
        } else {
            // For allowed visitors, ensure the original functionality is restored
            
            // Restore all original shortcodes if they exist
            if (function_exists('frm_replace_shortcodes')) {
                remove_shortcode('formidable');
                add_shortcode('formidable', 'frm_replace_shortcodes');
            }
            
            if (function_exists('frm_display_entries_shortcode')) {
                remove_shortcode('display-frm-data');
                add_shortcode('display-frm-data', 'frm_display_entries_shortcode');
            }
            
            // Remove our filters
            remove_filter('frm_pre_get_form', array($this, 'prevent_form_display'), 1);
            remove_filter('the_content', array($this, 'replace_form_content'), 1);
            remove_filter('widget_text', array($this, 'replace_form_content'), 1);
            remove_filter('frm_main_form_tag', array($this, 'prevent_form_display'), 1);
            remove_filter('frm_submit_button_html', '__return_false', 1);
            remove_filter('frm_form_fields_html', array($this, 'prevent_form_display'), 1);
            
            // Remove the blocking flag
            delete_option('aqm_security_forms_blocked');
            
            AQM_Security_API::debug_log('Original Formidable Forms functionality restored');
        }
    }
    
    /**
     * Add styles for blocked form messages
     */
    public function add_blocked_form_styles() {
        echo '<style type="text/css">
            .aqm-security-blocked-message {
                padding: 15px !important;
                background-color: #f8d7da !important;
                color: #721c24 !important;
                border: 1px solid #f5c6cb !important;
                border-radius: 4px !important;
                margin: 10px 0 !important;
                font-size: 16px !important;
                text-align: center !important;
            }
            
            /* Hide any Formidable Forms that might slip through with !important */
            .frm_forms, .with_frm_style, .frm_form_fields, .frm-show-form, 
            .frm_js_validation, .frm_logic_form, .frm_page_num_form, .frm_no_hide_form, 
            .frm_form_field, .frm-show-form, .frm_first_form, form.frm-show-form { 
                display: none !important; 
                visibility: hidden !important;
                opacity: 0 !important;
                height: 0 !important;
                overflow: hidden !important;
            }
        </style>';
    }
    
    /**
     * Log visitor access explicitly - separate from the geolocation check
     * 
     * @param bool $is_test_mode Whether we're in test mode
     * @param array $visitor Optional visitor data
     * @return bool Whether logging was successful
     */
    public function log_visitor_access($is_test_mode = false, $visitor = null) {
        // If no visitor data was passed, get it
        if ($visitor === null) {
            $api = new AQM_Security_API();
            $visitor = $api->get_visitor_geolocation($is_test_mode);
        }
        
        // If still no visitor data, log error and return
        if (!$visitor || empty($visitor)) {
            AQM_Security_API::debug_log('Failed to get visitor data for logging');
            return false;
        }
        
        // Check if visitor is allowed if not already set
        if ($this->is_allowed === null) {
            $this->is_allowed = AQM_Security_API::is_visitor_allowed($visitor);
        }
        
        // Get flag URL
        $flag_url = isset($visitor['location']['country_flag']) ? $visitor['location']['country_flag'] : '';
        
        // Write to log file to help with debugging
        error_log("[AQM Security] About to log visitor: IP=" . 
            (isset($visitor['ip']) ? $visitor['ip'] : 'Unknown') . 
            ", Country=" . (isset($visitor['country']) ? $visitor['country'] : 'Unknown') .
            ", Mode=" . ($is_test_mode ? 'Test' : 'Normal'));
        
        // Force a new log entry to ensure it's logged
        $result = AQM_Security_Logger::log_visitor(
            isset($visitor['ip']) ? $visitor['ip'] : '0.0.0.0',
            isset($visitor['country']) ? $visitor['country'] : 'Unknown',
            isset($visitor['region']) ? $visitor['region'] : 'Unknown',
            isset($visitor['zip']) ? $visitor['zip'] : 'Unknown',
            $this->is_allowed,
            $flag_url,
            true // Always force new log entry
        );
        
        // Debug log the visitor access
        AQM_Security_API::debug_log(
            'Visitor access logged. ' .
            'IP: ' . (isset($visitor['ip']) ? $visitor['ip'] : 'Unknown') . 
            ', Is Test Mode: ' . ($is_test_mode ? 'Yes' : 'No') .
            ', Is Allowed: ' . ($this->is_allowed ? 'Yes' : 'No')
        );
        
        return $result;
    }
    
    /**
     * Replace any form content with blocked message
     */
    public function replace_form_content($content) {
        if (empty($content)) {
            return $content;
        }
        
        // If content has form shortcodes, replace them with blocked message
        if (strpos($content, '[formidable') !== false || 
            strpos($content, '[display-frm-data') !== false) {
            
            // Get blocked message
            $blocked_message = get_option('aqm_security_blocked_message', 'Access to this form is restricted based on your location.');
            
            // Create the message HTML
            $message_html = '<div class="aqm-security-blocked-message">' . esc_html($blocked_message) . '</div>';
            
            // Use regex to replace all formidable shortcodes with the blocked message
            $content = preg_replace('/\[formidable.*?\]/', $message_html, $content);
            $content = preg_replace('/\[display-frm-data.*?\]/', $message_html, $content);
        }
        
        return $content;
    }
    
    /**
     * Shortcode replacement for blocked forms
     */
    public function blocked_form_shortcode($atts, $content = '') {
        // Get blocked message
        $blocked_message = get_option('aqm_security_blocked_message', 'Access to this form is restricted based on your location.');
        
        // Create the message HTML with a specific class for styling
        return '<div class="aqm-security-blocked-message">' . esc_html($blocked_message) . '</div>';
    }
    
    /**
     * Prevent the form from being displayed
     */
    public function prevent_form_display($form, $form_id = 0, $key = '') {
        // Get blocked message
        $blocked_message = get_option('aqm_security_blocked_message', 'Access to this form is restricted based on your location.');
        
        // Add debug info
        AQM_Security_API::debug_log("Preventing form display for form ID: $form_id");
        
        // Return an HTML div instead of the form
        return '<div class="aqm-security-blocked-message">' . esc_html($blocked_message) . '</div>';
    }
    
    /**
     * Register the stylesheets for the public-facing side of the site.
     */
    public function enqueue_styles() {
        // Only enqueue scripts if we have geolocation data
        if (isset($this->is_allowed) && !$this->is_allowed) {
            wp_enqueue_style('aqm-security-public', plugin_dir_url(__FILE__) . 'css/aqm-security-public.css', array(), $this->version, 'all');
        }
    }
    
    /**
     * Register the JavaScript for the public-facing side of the site.
     */
    public function enqueue_scripts() {
        // Only enqueue scripts if we have geolocation data
        if (isset($this->is_allowed) && !$this->is_allowed) {
            wp_enqueue_script('aqm-security-public', plugin_dir_url(__FILE__) . 'js/aqm-security-public.js', array('jquery'), $this->version, false);
        }
    }
    
    /**
     * Get visitor geolocation data and check if allowed
     * 
     * @param bool $force_fresh Force fresh data retrieval
     * @return array Geolocation data
     */
    private function get_visitor_data($force_fresh = false) {
        $api = new AQM_Security_API();
        
        // Add a debug log to determine why visitor might not be logged
        AQM_Security_API::debug_log('Getting visitor data. Force fresh: ' . ($force_fresh ? 'Yes' : 'No'));
        
        // Get geolocation data - this will handle API calls and caching
        $visitor = $api->get_visitor_geolocation($force_fresh);
        
        // Add more logging to help debug
        if (!$visitor || empty($visitor)) {
            AQM_Security_API::debug_log('Failed to get visitor geolocation data');
        } else {
            AQM_Security_API::debug_log('Visitor data retrieved: ' . 
                (isset($visitor['ip']) ? 'IP: ' . $visitor['ip'] : 'IP unknown') . ', ' .
                (isset($visitor['region_code']) ? 'Region: ' . $visitor['region_code'] : 'Region unknown')
            );
        }
        
        return $visitor;
    }
    
    /**
     * Display test mode notice
     * 
     * @return void
     */
    public function display_test_mode_notice() {
        $test_ip = get_option('aqm_security_test_ip', '');
        $visitor = $this->get_visitor_data();
        
        // Default values in case they're not set
        $ip = isset($visitor['ip']) ? $visitor['ip'] : 'Unknown';
        $country = isset($visitor['country']) ? $visitor['country'] : 'Unknown';
        $region = isset($visitor['region']) ? $visitor['region'] : 'Unknown';
        $zip = isset($visitor['zip']) ? $visitor['zip'] : 'Unknown';
        
        echo '<div style="position: fixed; bottom: 0; left: 0; right: 0; background-color: #ffeb3b; color: #333; text-align: center; padding: 10px; z-index: 9999; border-top: 1px solid #ffc107; font-family: sans-serif;">';
        echo '<strong>AQM Security Test Mode Active:</strong> ';
        echo 'Using IP: ' . esc_html($ip) . ' | ';
        echo 'Location: ' . esc_html($country) . ', ' . esc_html($region) . ', ' . esc_html($zip);
        echo ' <a href="' . esc_url(admin_url('admin.php?page=aqm-security-settings')) . '" style="color: #0288d1; margin-left: 10px;">Change Settings</a>';
        echo '</div>';
    }
    
    /**
     * Display blocked message
     * 
     * @return void
     */
    public function display_blocked_message() {
        // Get blocked message from options
        $message = get_option(
            'aqm_security_blocked_message', 
            __('Access to this form is restricted based on your location.', 'aqm-security')
        );
        
        // Apply filters to message
        $message = apply_filters('aqm_security_blocked_message', $message);
        
        // Display message
        echo '<div class="aqm-security-blocked-message">' . wp_kses_post($message) . '</div>';
        exit;
    }
    
    /**
     * Check if visitor is allowed
     * 
     * @return bool True if allowed, false if blocked
     */
    public function is_visitor_allowed() {
        // If we haven't checked yet, do it now
        if ($this->is_allowed === null) {
            $this->get_visitor_data();
        }
        
        // Admin users always allowed
        if (current_user_can('manage_options')) {
            return true;
        }
        
        return $this->is_allowed;
    }
    
    /**
     * Maybe block form submission
     * 
     * @param bool $continue Whether to continue with form creation
     * @param int $form_id Form ID
     * @return bool Whether to continue with form creation
     */
    public function maybe_block_form($continue, $form_id) {
        // If already blocked or admin user, return unchanged
        if (!$continue || current_user_can('manage_options')) {
            return $continue;
        }
        
        // If visitor is not allowed, block form submission
        if (!$this->is_visitor_allowed()) {
            return false;
        }
        
        return $continue;
    }
    
    /**
     * Maybe replace form with blocked message
     * 
     * @param mixed $form Form data
     * @return mixed Modified form data
     */
    public function maybe_replace_form($form) {
        // If admin user, show form
        if (current_user_can('manage_options')) {
            return $form;
        }
        
        // If visitor is not allowed, replace form with message
        if (!$this->is_visitor_allowed()) {
            // Get blocked message from options
            $message = get_option(
                'aqm_security_blocked_message',
                __('Access to this form is restricted based on your location.', 'aqm-security')
            );
            
            // Apply filters to message
            $message = apply_filters('aqm_security_blocked_message', $message);
            
            // Return message instead of form
            return '<div class="aqm-security-blocked-message">' . wp_kses_post($message) . '</div>';
        }
        
        return $form;
    }
    
    /**
     * Filter Formidable Forms shortcodes
     *
     * @param string $output Shortcode output
     * @param string $tag Shortcode name
     * @param array $attr Shortcode attributes
     * @param array $m Regex match data
     * @return string Filtered output
     */
    public function filter_formidable_shortcode($output, $tag, $attr, $m) {
        // Only filter Formidable Forms related shortcodes
        if (!in_array($tag, array('formidable', 'display-frm-data', 'frm-stats'))) {
            return $output;
        }
        
        // If visitor is not allowed, replace with blocked message
        if (isset($this->is_allowed) && !$this->is_allowed) {
            $message = get_option(
                'aqm_security_blocked_message',
                __('Access to this form is restricted based on your location.', 'aqm-security')
            );
            
            return '<div class="frm-blocked-message">' . wp_kses_post($message) . '</div>';
        }
        
        // Otherwise, return original output
        return $output;
    }
    
    /**
     * Filter form content in widgets
     *
     * @param string $content Widget content
     * @return string Filtered content
     */
    public function filter_form_widget_content($content) {
        // If visitor is allowed or we don't know yet, return original content
        if (!isset($this->is_allowed) || $this->is_allowed) {
            return $content;
        }
        
        // If content has form shortcodes, replace them with blocked message
        
        // 1. Hook into pre_get_form to prevent the form from being displayed
        add_filter('frm_pre_get_form', array($this, 'prevent_form_display'), 10, 3);
        
        // 2. Replace ALL Formidable shortcodes with our blocked message
        if (function_exists('frm_replace_shortcodes')) {
            remove_shortcode('formidable');
            add_shortcode('formidable', array($this, 'blocked_form_shortcode'));
        }
        
        if (function_exists('frm_display_entries_shortcode')) {
            remove_shortcode('display-frm-data');
            add_shortcode('display-frm-data', array($this, 'blocked_form_shortcode'));
        }
        
        remove_shortcode('frm-stats');
        add_shortcode('frm-stats', array($this, 'blocked_form_shortcode'));
        
        remove_shortcode('frm-graph');
        add_shortcode('frm-graph', array($this, 'blocked_form_shortcode'));
        
        remove_shortcode('frm-search');
        add_shortcode('frm-search', array($this, 'blocked_form_shortcode'));
        
        // 3. Replace form view content
        add_filter('frm_content', array($this, 'blocked_form_content'), 10, 2);
        add_filter('frm_display_entries_content', array($this, 'blocked_form_content'), 10, 2);
        
        // 4. Add styles for the blocked form message
        add_action('wp_head', array($this, 'add_blocked_form_styles'));
        
        // 5. Extra: Add CSS to hide any forms that might slip through
        add_action('wp_head', function() {
            echo '<style type="text/css">
                .frm_forms, .with_frm_style, .frm_form_fields, .frm-show-form, 
                .frm_js_validation, .frm_logic_form, .frm_page_num_form, .frm_no_hide_form, 
                .frm_form_field, .frm-show-form, .frm_first_form { 
                    display: none !important; 
                }
            </style>';
        });
        
        // Force re-check of all needed hooks
        do_action('frm_load_hook_for_form');
        
        // Set a flag that forms are blocked
        update_option('aqm_security_forms_blocked', true);
        
        AQM_Security_API::debug_log('Formidable Forms visibility rules applied for blocked visitor');
        
        // If content has form shortcodes, replace them with blocked message
        if (strpos($content, '[formidable') !== false || 
            strpos($content, '[display-frm-data') !== false ||
            strpos($content, '[frm-stats') !== false) {
            
            $message = get_option(
                'aqm_security_blocked_message',
                __('Access to this form is restricted based on your location.', 'aqm-security')
            );
            
            return '<div class="frm-blocked-message">' . wp_kses_post($message) . '</div>';
        }
        
        return $content;
    }
    
    /**
     * Filter form content in posts
     *
     * @param string $content Post content
     * @return string Filtered content
     */
    public function filter_form_content($content) {
        // Same as widget_text filter
        return $this->filter_form_widget_content($content);
    }
}
