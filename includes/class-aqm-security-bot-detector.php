<?php
/**
 * Bot detection functionality for AQM Security
 *
 * @since      2.3.0
 * @package    AQM_Security
 * @subpackage AQM_Security/includes
 */

class AQM_Security_Bot_Detector {

    /**
     * The ID of this plugin.
     *
     * @since    2.3.0
     * @access   private
     * @var      string    $plugin_name    The ID of this plugin.
     */
    private $plugin_name;

    /**
     * The version of this plugin.
     *
     * @since    2.3.0
     * @access   private
     * @var      string    $version    The current version of this plugin.
     */
    private $version;

    /**
     * Initialize the class and set its properties.
     *
     * @since    2.3.0
     * @param    string    $plugin_name       The name of this plugin.
     * @param    string    $version    The version of this plugin.
     */
    public function __construct($plugin_name, $version) {
        $this->plugin_name = $plugin_name;
        $this->version = $version;

        // Add hooks for bot detection
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        
        // Add honeypot fields to Formidable Forms
        add_filter('frm_form_fields_class', array($this, 'add_honeypot_fields'), 10, 2);
        
        // Add validation for bot detection
        add_filter('frm_validate_entry', array($this, 'validate_bot_detection'), 10, 2);
        
        // Add decoy fields to Formidable Forms
        add_filter('frm_form_fields_class', array($this, 'add_decoy_fields'), 10, 2);
    }

    /**
     * Register the JavaScript for bot detection.
     *
     * @since    2.3.0
     */
    public function enqueue_scripts() {
        // Only enqueue on pages with Formidable Forms
        if (!$this->page_has_forms()) {
            return;
        }

        // Enqueue the bot detection script
        wp_enqueue_script(
            'aqm-security-bot-detector',
            AQM_SECURITY_PLUGIN_URL . 'public/js/aqm-security-bot-detector.js',
            array('jquery'),
            $this->version,
            true
        );

        // Pass data to the script
        wp_localize_script(
            'aqm-security-bot-detector',
            'aqmSecurityBotDetector',
            array(
                'ajaxurl' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('aqm_security_bot_detector'),
                'honeypotFieldName' => $this->get_honeypot_field_name(),
                'formLoadTime' => time(),
                'tokenFieldName' => $this->get_token_field_name(),
                'tokenValue' => $this->generate_token(),
            )
        );
    }

    /**
     * Check if the current page has Formidable Forms
     *
     * @since    2.3.0
     * @return   boolean    True if the page has forms
     */
    private function page_has_forms() {
        global $post;
        
        if (!is_object($post)) {
            return false;
        }
        
        $content = $post->post_content;
        
        // Check for Formidable shortcodes
        if (
            strpos($content, '[formidable') !== false || 
            strpos($content, '[display-frm-data') !== false ||
            strpos($content, 'class="frm_forms') !== false ||
            strpos($content, 'class="frm-show-form') !== false
        ) {
            return true;
        }
        
        return false;
    }

    /**
     * Add honeypot fields to Formidable Forms
     *
     * @since    2.3.0
     * @param    string    $classes    The CSS classes for the form
     * @param    object    $form       The form object
     * @return   string                The modified CSS classes
     */
    public function add_honeypot_fields($classes, $form) {
        // Only add honeypot if enabled in settings
        if (!get_option('aqm_security_enable_honeypot', true)) {
            return $classes;
        }
        
        // Add hidden honeypot field
        add_action('frm_entry_form', function($form_id) use ($form) {
            // Handle various types of form ID parameters
            if (is_object($form) && isset($form->id)) {
                // If form is an object with id property
                $form_id_to_match = intval($form->id);
            } elseif (is_array($form) && isset($form['id'])) {
                // If form is an array with id key
                $form_id_to_match = intval($form['id']);
            } else {
                // Default fallback
                $form_id_to_match = 0;
            }
            
            // Convert $form_id to integer for proper comparison
            $current_form_id = is_object($form_id) ? 0 : intval($form_id);
            
            if ($current_form_id === $form_id_to_match) {
                echo $this->get_honeypot_field_html();
                echo $this->get_time_trap_field_html();
                echo $this->get_js_validation_field_html();
            }
        });
        
        return $classes;
    }

    /**
     * Add decoy fields to Formidable Forms
     * 
     * This method is kept as a stub for backward compatibility but no longer adds decoy fields
     *
     * @since    2.3.0
     * @param    string    $classes    The CSS classes for the form
     * @param    object    $form       The form object
     * @return   string                The modified CSS classes
     */
    public function add_decoy_fields($classes, $form) {
        // Decoy fields have been disabled as per user request
        return $classes;
    }

    /**
     * Validate bot detection methods
     *
     * @since    2.3.0
     * @param    array    $errors    The current validation errors
     * @param    array    $values    The form values
     * @return   array               The modified validation errors
     */
    public function validate_bot_detection($errors, $values) {
        // Skip for admin users or during AJAX
        if (current_user_can('manage_options') || (defined('DOING_AJAX') && DOING_AJAX)) {
            return $errors;
        }
        
        // Get form ID
        $form_id = isset($values['form_id']) ? absint($values['form_id']) : 0;
        if (!$form_id) {
            return $errors;
        }
        
        // Validate honeypot field if enabled
        if (get_option('aqm_security_enable_honeypot', true)) {
            $honeypot_errors = $this->validate_honeypot($values);
            if (!empty($honeypot_errors)) {
                $errors = array_merge($errors, $honeypot_errors);
                AQM_Security_API::debug_log('Bot detected: Honeypot field filled', $values);
            }
        }
        
        // Validate time trap if enabled
        if (get_option('aqm_security_enable_time_trap', true)) {
            $time_errors = $this->validate_time_trap($values);
            if (!empty($time_errors)) {
                $errors = array_merge($errors, $time_errors);
                AQM_Security_API::debug_log('Bot detected: Form submitted too quickly', $values);
            }
        }
        
        // Validate JavaScript token if enabled
        if (get_option('aqm_security_enable_js_validation', true)) {
            $js_errors = $this->validate_js_token($values);
            if (!empty($js_errors)) {
                $errors = array_merge($errors, $js_errors);
                AQM_Security_API::debug_log('Bot detected: JavaScript validation failed', $values);
            }
        }
        
        // Validate decoy field if enabled
        if (get_option('aqm_security_enable_decoy_fields', true)) {
            $decoy_errors = $this->validate_decoy_field($values);
            if (!empty($decoy_errors)) {
                $errors = array_merge($errors, $decoy_errors);
                AQM_Security_API::debug_log('Bot detected: Decoy field filled', $values);
            }
        }
        
        // If bot detected, log the IP
        if (!empty($errors) && !isset($errors['aqm_security'])) {
            $visitor_ip = AQM_Security_API::get_client_ip();
            AQM_Security_API::debug_log('Bot activity detected from IP: ' . $visitor_ip, $values);
            
            // Add the IP to the block list if auto-block is enabled
            if (get_option('aqm_security_auto_block_bots', false)) {
                $this->add_ip_to_blocklist($visitor_ip);
            }
            
            // Add a generic error message
            $errors['aqm_security'] = __('Form submission blocked due to suspicious activity.', 'aqm-security');
        }
        
        return $errors;
    }

    /**
     * Add an IP to the block list
     *
     * @since    2.3.0
     * @param    string    $ip    The IP address to block
     */
    private function add_ip_to_blocklist($ip) {
        // Get current blocked IPs
        $blocked_ips = get_option('aqm_security_blocked_ips', '');
        
        // Check if IP is already blocked
        if (strpos($blocked_ips, $ip) !== false) {
            return;
        }
        
        // Add the IP to the list
        if (!empty($blocked_ips)) {
            $blocked_ips .= "\n";
        }
        $blocked_ips .= $ip;
        
        // Update the option
        update_option('aqm_security_blocked_ips', $blocked_ips);
        
        AQM_Security_API::debug_log('Added bot IP to block list: ' . $ip);
    }

    /**
     * Validate the honeypot field
     *
     * @since    2.3.0
     * @param    array    $values    The form values
     * @return   array               Validation errors if honeypot is filled
     */
    private function validate_honeypot($values) {
        $errors = array();
        $honeypot_field = $this->get_honeypot_field_name();
        
        // If honeypot field exists and is not empty, it's a bot
        if (isset($_POST[$honeypot_field]) && !empty($_POST[$honeypot_field])) {
            $errors['honeypot'] = __('Bot activity detected.', 'aqm-security');
        }
        
        return $errors;
    }

    /**
     * Validate the time trap
     *
     * @since    2.3.0
     * @param    array    $values    The form values
     * @return   array               Validation errors if form submitted too quickly
     */
    private function validate_time_trap($values) {
        $errors = array();
        $time_field = $this->get_time_trap_field_name();
        
        // If time field exists
        if (isset($_POST[$time_field])) {
            $form_load_time = intval($_POST[$time_field]);
            $current_time = time();
            $time_diff = $current_time - $form_load_time;
            
            // If form was submitted too quickly (less than 3 seconds), it's likely a bot
            $min_time = get_option('aqm_security_min_form_time', 3);
            if ($time_diff < $min_time) {
                $errors['time_trap'] = __('Form submitted too quickly. Please try again.', 'aqm-security');
            }
            
            // If the timestamp is in the future or too old (more than 1 hour), it's suspicious
            if ($form_load_time > $current_time || $time_diff > 3600) {
                $errors['time_trap'] = __('Invalid form submission time.', 'aqm-security');
            }
        }
        
        return $errors;
    }

    /**
     * Validate the JavaScript token
     *
     * @since    2.3.0
     * @param    array    $values    The form values
     * @return   array               Validation errors if token is invalid
     */
    private function validate_js_token($values) {
        $errors = array();
        $token_field = $this->get_token_field_name();
        
        // If token field exists
        if (isset($_POST[$token_field])) {
            $submitted_token = $_POST[$token_field];
            $expected_token = $this->verify_token($submitted_token);
            
            // If token is invalid, it's likely a bot
            if (!$expected_token) {
                $errors['js_validation'] = __('Invalid form submission.', 'aqm-security');
            }
        } else {
            // If token field doesn't exist, JavaScript didn't run (likely a bot)
            $errors['js_validation'] = __('Form validation failed.', 'aqm-security');
        }
        
        return $errors;
    }

    /**
     * Validate the decoy field
     *
     * @since    2.3.0
     * @param    array    $values    The form values
     * @return   array               Validation errors if decoy field is filled
     */
    private function validate_decoy_field($values) {
        $errors = array();
        $decoy_field = $this->get_decoy_field_name();
        
        // If decoy field exists and is not empty, it's a bot
        if (isset($_POST[$decoy_field]) && !empty($_POST[$decoy_field])) {
            $errors['decoy'] = __('Bot activity detected.', 'aqm-security');
        }
        
        return $errors;
    }

    /**
     * Get the honeypot field HTML
     *
     * @since    2.3.0
     * @return   string    The honeypot field HTML
     */
    private function get_honeypot_field_html() {
        $field_name = $this->get_honeypot_field_name();
        
        return '<div class="aqm-honeypot" aria-hidden="true" style="position: absolute !important; width: 0 !important; height: 0 !important; overflow: hidden !important; left: -9999px !important; top: -9999px !important; z-index: -9999 !important;">
            <label for="' . esc_attr($field_name) . '">' . __('Leave this field empty', 'aqm-security') . '</label>
            <input type="text" name="' . esc_attr($field_name) . '" id="' . esc_attr($field_name) . '" value="" autocomplete="off" tabindex="-1">
        </div>';
    }

    /**
     * Get the time trap field HTML
     *
     * @since    2.3.0
     * @return   string    The time trap field HTML
     */
    private function get_time_trap_field_html() {
        $field_name = $this->get_time_trap_field_name();
        $current_time = time();
        
        return '<input type="hidden" name="' . esc_attr($field_name) . '" value="' . esc_attr($current_time) . '">';
    }

    /**
     * Get the JavaScript validation field HTML
     *
     * @since    2.3.0
     * @return   string    The JavaScript validation field HTML
     */
    private function get_js_validation_field_html() {
        $field_name = $this->get_token_field_name();
        
        // This field will be populated by JavaScript
        return '<input type="hidden" name="' . esc_attr($field_name) . '" id="' . esc_attr($field_name) . '" value="">';
    }

    /**
     * Get the decoy field HTML
     *
     * @since    2.3.0
     * @return   string    The decoy field HTML
     */
    private function get_decoy_field_html() {
        $field_name = $this->get_decoy_field_name();
        
        return '<div class="frm_form_field form-field">
            <label for="' . esc_attr($field_name) . '" class="frm_primary_label">
                ' . __('Please leave this field blank (spam protection)', 'aqm-security') . '
            </label>
            <input type="text" name="' . esc_attr($field_name) . '" id="' . esc_attr($field_name) . '" value="" class="frm_verify" aria-describedby="frm_desc_field">
            <div id="frm_desc_field" class="frm_description">' . __('This field helps us prevent spam. Please leave it empty.', 'aqm-security') . '</div>
        </div>';
    }

    /**
     * Get the honeypot field name
     *
     * @since    2.3.0
     * @return   string    The honeypot field name
     */
    private function get_honeypot_field_name() {
        return 'zip_code_verify';
    }

    /**
     * Get the time trap field name
     *
     * @since    2.3.0
     * @return   string    The time trap field name
     */
    private function get_time_trap_field_name() {
        return 'form_time_stamp';
    }

    /**
     * Get the token field name
     *
     * @since    2.3.0
     * @return   string    The token field name
     */
    private function get_token_field_name() {
        return 'security_token';
    }

    /**
     * Get the decoy field name
     *
     * @since    2.3.0
     * @return   string    The decoy field name
     */
    private function get_decoy_field_name() {
        return 'address_confirm';
    }

    /**
     * Generate a security token
     *
     * @since    2.3.0
     * @return   string    The security token
     */
    private function generate_token() {
        // Generate a random token
        $token = wp_generate_password(32, false);
        
        // Store the token in a transient for 1 hour
        set_transient('aqm_security_token_' . $token, '1', 3600);
        
        return $token;
    }

    /**
     * Verify a security token
     *
     * @since    2.3.0
     * @param    string    $token    The token to verify
     * @return   boolean             True if token is valid
     */
    private function verify_token($token) {
        // Check if token exists in transients
        $valid = get_transient('aqm_security_token_' . $token);
        
        // Delete the token after checking (one-time use)
        delete_transient('aqm_security_token_' . $token);
        
        return !empty($valid);
    }
}
