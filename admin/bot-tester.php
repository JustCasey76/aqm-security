<?php
/**
 * Bot Testing Script for AQM Security
 * 
 * This script simulates bot behavior to test the bot detection features.
 * Only use this in test mode on a staging environment.
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

class AQM_Security_Bot_Tester {
    /**
     * Initialize the bot tester
     */
    public function __construct() {
        add_action('admin_menu', array($this, 'add_bot_tester_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_scripts'));
        add_action('wp_ajax_aqm_security_run_bot_test', array($this, 'run_bot_test'));
    }

    /**
     * Add bot tester menu
     */
    public function add_bot_tester_menu() {
        add_submenu_page(
            'aqm-security',
            __('Bot Tester', 'aqm-security'),
            __('Bot Tester', 'aqm-security'),
            'manage_options',
            'aqm-security-bot-tester',
            array($this, 'render_bot_tester_page')
        );
    }

    /**
     * Enqueue scripts for bot tester
     */
    public function enqueue_scripts($hook) {
        if ($hook !== 'aqm-security_page_aqm-security-bot-tester') {
            return;
        }

        wp_enqueue_script(
            'aqm-security-bot-tester',
            AQM_SECURITY_PLUGIN_URL . 'admin/js/aqm-security-bot-tester.js',
            array('jquery'),
            AQM_SECURITY_VERSION,
            true
        );

        wp_localize_script(
            'aqm-security-bot-tester',
            'aqmSecurityBotTester',
            array(
                'ajaxurl' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('aqm_security_bot_tester_nonce'),
                'testingMessage' => __('Running bot test...', 'aqm-security'),
                'successMessage' => __('Test completed!', 'aqm-security'),
                'errorMessage' => __('Test failed. See console for details.', 'aqm-security')
            )
        );
    }

    /**
     * Render bot tester page
     */
    public function render_bot_tester_page() {
        // Check if test mode is enabled
        $test_mode = get_option('aqm_security_test_mode', false);
        if (!$test_mode) {
            echo '<div class="notice notice-error"><p>' . 
                __('Test mode must be enabled to use the bot tester. Please enable test mode in the AQM Security settings.', 'aqm-security') . 
                '</p></div>';
            return;
        }

        // Get available forms
        $forms = $this->get_formidable_forms();
        ?>
        <div class="wrap">
            <h1><?php _e('AQM Security Bot Tester', 'aqm-security'); ?></h1>
            <p><?php _e('This tool simulates bot behavior to test your bot detection features.', 'aqm-security'); ?></p>
            <p class="description"><?php _e('Note: This tool will only work when test mode is enabled.', 'aqm-security'); ?></p>
            
            <div class="aqm-security-bot-tester-container">
                <h2><?php _e('Test Configuration', 'aqm-security'); ?></h2>
                
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Select Form', 'aqm-security'); ?></th>
                        <td>
                            <select id="aqm-security-test-form">
                                <?php foreach ($forms as $form_id => $form_name) : ?>
                                    <option value="<?php echo esc_attr($form_id); ?>"><?php echo esc_html($form_name); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Bot Behaviors to Test', 'aqm-security'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="aqm-security-test-honeypot" checked>
                                <?php _e('Fill Honeypot Fields', 'aqm-security'); ?>
                            </label><br>
                            
                            <label>
                                <input type="checkbox" id="aqm-security-test-time-trap" checked>
                                <?php _e('Submit Form Instantly', 'aqm-security'); ?>
                            </label><br>
                            
                            <label>
                                <input type="checkbox" id="aqm-security-test-js-validation" checked>
                                <?php _e('Skip JavaScript Validation', 'aqm-security'); ?>
                            </label><br>
                        </td>
                    </tr>
                </table>
                
                <p class="submit">
                    <button id="aqm-security-run-bot-test" class="button button-primary"><?php _e('Run Bot Test', 'aqm-security'); ?></button>
                </p>
                
                <div id="aqm-security-test-results" style="display: none;">
                    <h3><?php _e('Test Results', 'aqm-security'); ?></h3>
                    <div id="aqm-security-test-results-content"></div>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Get all Formidable Forms
     * 
     * @return array Array of form IDs and names
     */
    private function get_formidable_forms() {
        $forms = array();
        
        if (class_exists('FrmForm')) {
            $all_forms = FrmForm::get_published_forms();
            
            foreach ($all_forms as $form) {
                $forms[$form->id] = $form->name;
            }
        }
        
        return $forms;
    }

    /**
     * Run bot test
     */
    public function run_bot_test() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'aqm_security_bot_tester_nonce')) {
            wp_send_json_error(array('message' => 'Invalid nonce'));
            exit;
        }
        
        // Check if user has permission
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Permission denied'));
            exit;
        }
        
        // Check if test mode is enabled
        $test_mode = get_option('aqm_security_test_mode', false);
        if (!$test_mode) {
            wp_send_json_error(array('message' => 'Test mode must be enabled to run bot tests'));
            exit;
        }
        
        // Get test parameters
        $form_id = isset($_POST['form_id']) ? intval($_POST['form_id']) : 0;
        $test_honeypot = isset($_POST['test_honeypot']) ? filter_var($_POST['test_honeypot'], FILTER_VALIDATE_BOOLEAN) : false;
        $test_time_trap = isset($_POST['test_time_trap']) ? filter_var($_POST['test_time_trap'], FILTER_VALIDATE_BOOLEAN) : false;
        $test_js_validation = isset($_POST['test_js_validation']) ? filter_var($_POST['test_js_validation'], FILTER_VALIDATE_BOOLEAN) : false;
        
        // Validate form ID
        if (!$form_id || !class_exists('FrmForm') || !FrmForm::getOne($form_id)) {
            wp_send_json_error(array('message' => 'Invalid form ID'));
            exit;
        }
        
        // Run the tests
        $results = $this->simulate_bot_submission($form_id, $test_honeypot, $test_time_trap, $test_js_validation);
        
        wp_send_json_success($results);
    }

    /**
     * Simulate bot submission
     * 
     * @param int $form_id Form ID
     * @param bool $test_honeypot Test honeypot fields
     * @param bool $test_time_trap Test time trap
     * @param bool $test_js_validation Test JavaScript validation
     * @return array Test results
     */
    private function simulate_bot_submission($form_id, $test_honeypot, $test_time_trap, $test_js_validation) {
        // Reset any previous test data
        $_POST = array();
        
        $results = array(
            'form_id' => $form_id,
            'tests' => array(),
            'overall_result' => 'success',
            'message' => ''
        );
        
        // Get form fields
        $form_fields = array();
        if (class_exists('FrmField')) {
            $form_fields = FrmField::get_all_for_form($form_id);
        }
        
        // Prepare form data
        $form_data = array(
            'form_id' => $form_id,
            'item_meta' => array()
        );
        
        // Fill form fields with dummy data
        foreach ($form_fields as $field) {
            switch ($field->type) {
                case 'text':
                case 'email':
                    $form_data['item_meta'][$field->id] = 'test_' . $field->id . '@example.com';
                    break;
                case 'phone':
                    $form_data['item_meta'][$field->id] = '555-123-4567';
                    break;
                case 'number':
                    $form_data['item_meta'][$field->id] = '42';
                    break;
                case 'textarea':
                    $form_data['item_meta'][$field->id] = 'This is a test submission from the AQM Security Bot Tester.';
                    break;
                case 'checkbox':
                case 'radio':
                case 'select':
                    // Get the first option
                    $options = maybe_unserialize($field->options);
                    if (is_array($options) && !empty($options)) {
                        $first_option = reset($options);
                        $form_data['item_meta'][$field->id] = $first_option;
                    }
                    break;
                default:
                    $form_data['item_meta'][$field->id] = 'test';
            }
        }
        
        // Only add selected tests to the results
        $active_tests = array();
        
        // Test honeypot fields
        if ($test_honeypot) {
            // Add honeypot field
            $honeypot_field_name = 'zip_code_verify';
            $_POST[$honeypot_field_name] = 'bot_filled_this';
            
            $results['tests']['honeypot'] = array(
                'name' => 'Honeypot Fields',
                'result' => 'success',
                'message' => 'Honeypot field added to submission'
            );
            
            $active_tests[] = 'Honeypot Fields';
        }
        
        // Test time trap
        if ($test_time_trap) {
            // Set form time to current time (instant submission)
            $time_field_name = 'form_time_stamp';
            $_POST[$time_field_name] = time();
            
            $results['tests']['time_trap'] = array(
                'name' => 'Time Trap',
                'result' => 'success',
                'message' => 'Time trap test configured for instant submission'
            );
            
            $active_tests[] = 'Time Trap';
        }
        
        // Test JavaScript validation
        if ($test_js_validation) {
            // Don't add the token field that JavaScript would normally add
            // This simulates a bot that doesn't execute JavaScript
            
            $results['tests']['js_validation'] = array(
                'name' => 'JavaScript Validation',
                'result' => 'success',
                'message' => 'JavaScript validation token omitted'
            );
            
            $active_tests[] = 'JavaScript Validation';
        }
        
        // Log the test
        $this->log_bot_test($form_id, $results);
        
        if (count($active_tests) > 0) {
            $results['message'] = 'Bot test configured successfully. The form submission would be blocked by the following detection methods: ' . 
                implode(', ', $active_tests);
        } else {
            $results['message'] = 'No bot detection tests were run. Please select at least one test behavior to check.';
            $results['overall_result'] = 'warning';
        }
        
        return $results;
    }

    /**
     * Log bot test
     * 
     * @param int $form_id Form ID
     * @param array $results Test results
     */
    private function log_bot_test($form_id, $results) {
        if (class_exists('AQM_Security_API')) {
            AQM_Security_API::debug_log('Bot test run on form #' . $form_id, $results);
        }
    }
}

// Initialize the bot tester
$aqm_security_bot_tester = new AQM_Security_Bot_Tester();
