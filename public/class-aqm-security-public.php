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
     * Whether the current page has forms
     * 
     * @var bool|null
     */
    private $has_forms = null;

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
        $this->has_forms = null;
        
        // Setup WP Rocket compatibility
        add_filter('rocket_cache_reject_uri', array($this, 'exclude_forms_from_cache'));
        
        // Add DONOTCACHEPAGE constant for pages with forms
        add_action('template_redirect', array($this, 'maybe_prevent_caching'), 5);
        
        // Initialize shortcodes first
        add_action('init', array($this, 'initialize_shortcodes'), 5);
        
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
            
            // Add filters for form detection
            add_filter('frm_display_get_form', array($this, 'detect_form_and_check_geolocation'), 5, 2);
            add_filter('frm_filter_final_form', array($this, 'detect_form_and_check_geolocation'), 5, 2);
            add_filter('the_content', array($this, 'detect_form_in_content'), 5);
            add_filter('widget_text', array($this, 'detect_form_in_content'), 5);
            add_filter('frm_replace_shortcodes', array($this, 'detect_form_in_shortcode'), 5, 2);
        } catch (Exception $e) {
            // Log any errors
            error_log('[AQM Security] Error in initialize_geolocation_check: ' . $e->getMessage());
        }
    }
    
    /**
     * Detect forms in page content and trigger geolocation check if needed
     * 
     * @param string $content The content to check
     * @return string The original content
     */
    public function detect_form_in_content($content) {
        // Only proceed if we haven't checked geolocation yet
        if ($this->is_allowed === null) {
            // Look for form shortcodes or HTML
            if (
                strpos($content, '[formidable') !== false || 
                strpos($content, '[display-frm-data') !== false ||
                strpos($content, 'class="frm_forms') !== false ||
                strpos($content, 'class="frm-show-form') !== false
            ) {
                // Form detected, check geolocation
                AQM_Security_API::debug_log('Form detected in content, checking geolocation');
                $this->check_geolocation();
            }
        }
        
        return $content;
    }
    
    /**
     * Detect forms in shortcodes and trigger geolocation check if needed
     * 
     * @param string $content The shortcode content
     * @param array $shortcode_atts The shortcode attributes
     * @return string The original content
     */
    public function detect_form_in_shortcode($content, $shortcode_atts) {
        // Only proceed if we haven't checked geolocation yet
        if ($this->is_allowed === null) {
            AQM_Security_API::debug_log('Form shortcode detected, checking geolocation');
            $this->check_geolocation();
        }
        
        return $content;
    }
    
    /**
     * Detect form and check geolocation when a form is being displayed
     * 
     * @param mixed $form The form to be displayed
     * @param mixed $extra Additional parameters
     * @return mixed The original form
     */
    public function detect_form_and_check_geolocation($form, $extra = null) {
        // Only proceed if we haven't checked geolocation yet
        if ($this->is_allowed === null) {
            AQM_Security_API::debug_log('Form detected, checking geolocation');
            $this->check_geolocation();
        }
        
        return $form;
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
                // Make sure to pass the visitor data for proper logging
                $visitor = AQM_Security_API::get_visitor_geolocation(true);
                $this->log_visitor_access($test_mode, $visitor);
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
            $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'unknown';
            $is_safari = stripos($ua, 'safari') !== false && stripos($ua, 'chrome') === false;
            
            if ($is_safari) {
                AQM_Security_API::debug_log('Safari browser detected, using IP-only geolocation: ' . $visitor_ip);
            }
            
            if ($this->is_allowed) {
                AQM_Security_API::debug_log('ALLOWED: Visitor from IP: ' . $visitor_ip);
                
                // Ensure forms are visible
                $this->restore_formidable_forms();
                
                // Add specific style for Safari to ensure forms are visible
                if ($is_safari) {
                    add_action('wp_head', function() {
                        echo '<style type="text/css">
                            /* Force visibility for Safari browsers */
                            .frm_forms, .with_frm_style, .frm_form_fields, .frm-show-form, 
                            .frm_js_validation, .frm_logic_form, .frm_page_num_form, .frm_no_hide_form, 
                            .frm_form_field, .frm-show-form, .frm_first_form, form.frm-show-form { 
                                display: block !important; 
                                visibility: visible !important;
                                opacity: 1 !important;
                                height: auto !important;
                                overflow: visible !important;
                            }
                        </style>';
                    }, 999);
                }
            } else {
                AQM_Security_API::debug_log('BLOCKED: Visitor from IP: ' . $visitor_ip);
                
                // Apply form blocking rules
                $this->apply_formidable_visibility(false);
                
                // ENHANCED: Use wp_print_scripts hook which runs earlier than wp_head
                add_action('wp_print_scripts', array($this, 'add_blocked_form_styles'), 1);
                
                // ENHANCED: Use output buffer to catch and replace any form HTML
                ob_start(array($this, 'catch_and_replace_forms'));
                
                // ENHANCED: Add JavaScript as early as possible to ensure forms are hidden
                add_action('wp_print_scripts', function() {
                    echo '<script type="text/javascript">
                    /* Immediately execute script to hide forms */
                    (function() {
                        function hideAllForms() {
                            // Target all possible Formidable Forms elements
                            var formElements = document.querySelectorAll(".frm_forms, .with_frm_style, .frm_form_fields, .frm-show-form, .frm_js_validation, .frm_logic_form, .frm_page_num_form, .frm_no_hide_form, .frm_form_field, form.frm-show-form");
                            
                            // Hide each form
                            for(var i = 0; i < formElements.length; i++) {
                                formElements[i].style.display = "none";
                                formElements[i].style.visibility = "hidden";
                                formElements[i].style.opacity = "0";
                                formElements[i].style.height = "0";
                                formElements[i].style.overflow = "hidden";
                                
                                // Add a blocked message before the form
                                var message = document.createElement("div");
                                message.className = "aqm-security-blocked-message";
                                message.innerHTML = "' . esc_js(get_option('aqm_security_blocked_message', 'Access to this form is restricted based on your location.')) . '";
                                formElements[i].parentNode.insertBefore(message, formElements[i]);
                            }
                        }
                        
                        // Run on page load
                        hideAllForms();
                        
                        // Also run after DOM is loaded to catch dynamically loaded forms
                        document.addEventListener("DOMContentLoaded", hideAllForms);
                        
                        // Set up a MutationObserver to watch for new forms
                        if(typeof MutationObserver !== "undefined") {
                            var observer = new MutationObserver(function(mutations) {
                                for(var i = 0; i < mutations.length; i++) {
                                    if(mutations[i].addedNodes.length) {
                                        hideAllForms();
                                    }
                                }
                            });
                            
                            observer.observe(document.body, { childList: true, subtree: true });
                        }
                    })();
                    </script>';
                }, 1);
                
                // ENHANCED: Add stronger CSS rules with more specific selectors
                add_action('wp_print_styles', function() {
                    echo '<style type="text/css">
                        /* Blocked message styling */
                        .aqm-security-blocked-message {
                            padding: 15px !important;
                            background-color: #f8d7da !important;
                            color: #721c24 !important;
                            border: 1px solid #f5c6cb !important;
                            border-radius: 4px !important;
                            margin: 10px 0 !important;
                            font-size: 16px !important;
                            text-align: center !important;
                            display: block !important;
                            visibility: visible !important;
                            opacity: 1 !important;
                        }
                        
                        /* Enhanced specificity for hiding forms */
                        body .frm_forms, 
                        body .frm_form_fields,
                        body .with_frm_style,
                        body .frm-show-form,
                        body .frm_js_validation,
                        body .frm_logic_form,
                        body .frm_page_num_form,
                        body .frm_no_hide_form,
                        body .frm_form_field,
                        body form.frm-show-form,
                        div.frm_forms,
                        div[class*="frm_form_"],
                        form[class*="frm_form_"],
                        html body .frm_forms,
                        html body .with_frm_style { 
                            display: none !important; 
                            visibility: hidden !important;
                            opacity: 0 !important;
                            height: 0 !important;
                            overflow: hidden !important;
                            position: absolute !important;
                            left: -9999px !important;
                            max-height: 0 !important;
                            max-width: 0 !important;
                            padding: 0 !important;
                            margin: 0 !important;
                            border: 0 !important;
                        }
                    </style>';
                }, 1);
                
                // Log the form blocking
                error_log("[AQM Security] Forms blocked for visitor with IP: " . AQM_Security_API::get_client_ip());
            }
            
            // Return whether the visitor is allowed
            return $this->is_allowed;
        } catch (Exception $e) {
            // Log any errors during geolocation check
            error_log('[AQM Security] Error in check_geolocation: ' . $e->getMessage());
            
            // Default to allowing access if an error occurs
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
            
            // ENHANCED: Add more aggressive hooks to catch form rendering
            add_filter('frm_before_display_form', array($this, 'prevent_form_display'), 1, 3);
            add_filter('frm_filter_final_form', array($this, 'prevent_form_display'), 1, 3);
            add_filter('frm_form_classes', '__return_empty_string', 1);
            
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
            
            // ENHANCED: Also remove our enhanced hooks
            remove_filter('frm_before_display_form', array($this, 'prevent_form_display'), 1);
            remove_filter('frm_filter_final_form', array($this, 'prevent_form_display'), 1);
            remove_filter('frm_form_classes', '__return_empty_string', 1);
            
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
                display: block !important;
                visibility: visible !important;
                opacity: 1 !important;
            }
            
            /* Enhanced specificity for hiding forms */
            body .frm_forms, 
            body .frm_form_fields,
            body .with_frm_style,
            body .frm-show-form,
            body .frm_js_validation,
            body .frm_logic_form,
            body .frm_page_num_form,
            body .frm_no_hide_form,
            body .frm_form_field,
            body form.frm-show-form,
            div.frm_forms,
            div[class*="frm_form_"],
            form[class*="frm_form_"],
            html body .frm_forms,
            html body .with_frm_style { 
                display: none !important; 
                visibility: hidden !important;
                opacity: 0 !important;
                height: 0 !important;
                overflow: hidden !important;
                position: absolute !important;
                left: -9999px !important;
                max-height: 0 !important;
                max-width: 0 !important;
                padding: 0 !important;
                margin: 0 !important;
                border: 0 !important;
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
        try {
            // Skip logging for admin pages
            if (is_admin()) {
                return false;
            }
            
            // If visitor data wasn't passed, try to get it from the instance variable
            if (empty($visitor)) {
                if (isset($this->geo_data) && !empty($this->geo_data)) {
                    $visitor = $this->geo_data;
                } else {
                    // Try to get visitor data if we don't have it yet
                    $visitor = AQM_Security_API::get_visitor_geolocation(true);
                }
            }
            
            // If we don't have visitor data, we can't log
            if (empty($visitor)) {
                error_log("[AQM Security] Error: Cannot log visitor access - no visitor data.");
                return false;
            }
            
            // Check if the visitor is allowed if not already determined
            if ($this->is_allowed === null) {
                $this->is_allowed = AQM_Security_API::is_visitor_allowed($visitor);
            }
            
            // Log the visitor with their current status
            $result = AQM_Security_Logger::log_visitor(
                $visitor['ip'],
                isset($visitor['country']) ? $visitor['country'] : '',
                isset($visitor['region']) ? $visitor['region'] : '',
                $this->is_allowed,
                isset($visitor['location']['country_flag']) ? $visitor['location']['country_flag'] : '',
                false // Always update existing records, never force new entries
            );
            
            return ($result !== false);
        } catch (Exception $e) {
            error_log("[AQM Security] Error logging visitor access: " . $e->getMessage());
            return false;
        }
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
        // Enqueue the existing script
        wp_enqueue_script($this->plugin_name, AQM_SECURITY_PLUGIN_URL . 'public/js/aqm-security-public.js', array('jquery'), $this->version, false);
        
        // This inlines critical Safari-specific code to ensure forms are properly handled
        $safari_fix_script = "
            (function() {
                // Wrap everything in a DOMContentLoaded event to ensure DOM is ready
                document.addEventListener('DOMContentLoaded', function() {
                    // Detect Safari browser (excludes Chrome which also includes Safari in UA)
                    var isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
                    
                    if (isSafari && document.body) {
                        // For Safari, add a class to the body for CSS targeting
                        document.body.classList.add('aqm-safari-browser');
                        
                        // Add a small delay to ensure forms are properly visible in Safari
                        setTimeout(function() {
                            // Find all form elements that might be hidden
                            var forms = document.querySelectorAll('.frm_forms, .with_frm_style, .frm_form_fields, .frm-show-form');
                            
                            // If we detect allowed forms, ensure they're visible
                            if (forms.length > 0 && !document.querySelector('.aqm-security-blocked-message')) {
                                forms.forEach(function(form) {
                                    form.style.display = 'block';
                                    form.style.visibility = 'visible';
                                    form.style.opacity = '1';
                                    form.style.height = 'auto';
                                    form.style.overflow = 'visible';
                                });
                            }
                        }, 100);
                    }
                });
            })();
        ";
        
        // Add the inline script
        wp_add_inline_script($this->plugin_name, $safari_fix_script);
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
            $this->is_allowed = true;
            // Ensure admin users are logged when checked through this method
            $test_mode = get_option('aqm_security_test_mode', false);
            $visitor = AQM_Security_API::get_visitor_geolocation(true);
            $this->log_visitor_access($test_mode, $visitor);
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
    
    /**
     * Exclude pages with Formidable Forms from WP Rocket caching
     *
     * @param array $uris URIs to exclude from caching
     * @return array Modified URIs
     */
    public function exclude_forms_from_cache($uris) {
        // Get form patterns from options
        $form_patterns = get_option('aqm_security_form_patterns', 'formidable');
        
        if (!empty($form_patterns)) {
            // Add the current page if it contains forms
            global $wp;
            $current_uri = home_url($wp->request);
            
            if ($this->page_has_forms()) {
                $uris[] = str_replace(home_url(), '', $current_uri);
                AQM_Security_API::debug_log('Excluding URI from WP Rocket cache: ' . $current_uri);
            }
            
            // Add form submission endpoints
            $uris[] = '/wp-json/frm/(.*)';
            $uris[] = '/wp-admin/admin-ajax.php';
        }
        
        return $uris;
    }
    
    /**
     * Set DONOTCACHEPAGE constant for pages with forms
     */
    public function maybe_prevent_caching() {
        if ($this->page_has_forms()) {
            if (!defined('DONOTCACHEPAGE')) {
                define('DONOTCACHEPAGE', true);
            }
            AQM_Security_API::debug_log('Set DONOTCACHEPAGE constant for form page');
            
            // Also set WP Rocket specific constants if available
            if (!defined('DONOTROCKETOPTIMIZE')) {
                define('DONOTROCKETOPTIMIZE', true);
            }
        }
    }

    /**
     * Check if the current page has forms
     *
     * @return bool Whether the page has forms
     */
    public function page_has_forms() {
        // If we've already checked, return the cached result
        if ($this->has_forms !== null) {
            return $this->has_forms;
        }
        
        // Default to false
        $this->has_forms = false;
        
        // Get form patterns from options
        $form_patterns = get_option('aqm_security_form_patterns', 'formidable');
        
        if (empty($form_patterns)) {
            return $this->has_forms;
        }
        
        // Convert patterns to array if it's a string
        if (!is_array($form_patterns)) {
            $form_patterns = explode(',', $form_patterns);
        }
        
        // Clean up patterns
        $patterns = array();
        foreach ($form_patterns as $pattern) {
            $pattern = trim($pattern);
            if (!empty($pattern)) {
                $patterns[] = $pattern;
            }
        }
        
        // If no valid patterns, return false
        if (empty($patterns)) {
            return $this->has_forms;
        }
        
        // Check if we're on a page with Formidable Forms
        if (class_exists('FrmForm')) {
            global $post;
            
            // Check post content if available
            if ($post && !empty($post->post_content)) {
                $content = $post->post_content;
                
                // Check for form shortcodes
                if (stripos($content, '[formidable') !== false || 
                    stripos($content, '[display-frm-data') !== false) {
                    $this->has_forms = true;
                    return true;
                }
                
                // Check for pattern matches in content
                foreach ($patterns as $pattern) {
                    if (stripos($content, $pattern) !== false) {
                        $this->has_forms = true;
                        return true;
                    }
                }
            }
            
            // Check if Formidable Forms is in use on this page
            if (defined('DOING_AJAX') && DOING_AJAX && 
                isset($_POST['action']) && strpos($_POST['action'], 'frm_') === 0) {
                $this->has_forms = true;
                return true;
            }
            
            // Check for form-specific query parameters
            if (isset($_GET['frm-page-num']) || isset($_GET['frm_action'])) {
                $this->has_forms = true;
                return true;
            }
        }
        
        // For any other form types, check common URL patterns
        if (strpos($_SERVER['REQUEST_URI'], 'wp-json/frm/') !== false || 
            (isset($_GET['action']) && strpos($_GET['action'], 'form') !== false)) {
            $this->has_forms = true;
            return true;
        }
        
        // If we're submitting a form via POST
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST)) {
            $this->has_forms = true;
            return true;
        }
        
        return $this->has_forms;
    }
    
    /**
     * NEW METHOD: Output buffer callback to catch and replace forms
     * 
     * @param string $buffer The page output buffer
     * @return string Modified output buffer
     */
    public function catch_and_replace_forms($buffer) {
        if ($this->is_allowed !== false) {
            return $buffer;
        }
        
        $blocked_message = get_option('aqm_security_blocked_message', 'Access to this form is restricted based on your location.');
        $message_html = '<div class="aqm-security-blocked-message">' . esc_html($blocked_message) . '</div>';
        
        // Replace all instances of Formidable Forms with our blocked message
        $patterns = array(
            // Form classes and structure
            '/<div[^>]*class=["\'][^"\']*frm[_-]form[^"\']*["\'][^>]*>.*?<\/form>/is',
            '/<div[^>]*class=["\'][^"\']*frm_forms[^"\']*["\'][^>]*>.*?<\/div><\/div>/is',
            '/<form[^>]*class=["\'][^"\']*frm[_-]form[^"\']*["\'][^>]*>.*?<\/form>/is',
            // Shortcode remnants
            '/\[formidable.*?\]/',
            '/\[display-frm-data.*?\]/',
            // Any hidden form remains
            '/<div[^>]*class=["\'].*?frm_forms.*?["\'][^>]*>.*?<\/div>/is',
        );
        
        foreach ($patterns as $pattern) {
            $buffer = preg_replace($pattern, $message_html, $buffer);
        }
        
        return $buffer;
    }
}
