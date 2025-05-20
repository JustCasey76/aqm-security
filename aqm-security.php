<?php
/**
 * Plugin Name: AQM Security
 * Plugin URI: https://github.com/JustCasey76/aqm-security
 * Description: Geolocation-based security plugin using ipapi.com to control access to Formidable Forms.
 * Version: 2.1.8
 * Author: AQM
 * Author URI: https://justcasey76.com
 * Text Domain: aqm-security
 * GitHub Plugin URI: https://github.com/JustCasey76/aqm-security
 * Primary Branch: main
 * Requires at least: 5.6
 * Requires PHP: 7.3
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

// Define plugin constants
define('AQM_SECURITY_VERSION', '2.1.8');
define('AQM_SECURITY_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('AQM_SECURITY_PLUGIN_URL', plugin_dir_url(__FILE__));
define('AQM_SECURITY_BASENAME', plugin_basename(__FILE__));

// Include required files
require_once AQM_SECURITY_PLUGIN_DIR . 'includes/class-aqm-security.php';

// Include the GitHub Updater class
require_once AQM_SECURITY_PLUGIN_DIR . 'includes/class-aqm-security-updater.php';

// Register activation and deactivation hooks
register_activation_hook(__FILE__, 'aqm_security_activate');
register_deactivation_hook(__FILE__, 'aqm_security_deactivate');

/**
 * Plugin activation function
 */
function aqm_security_activate() {
    // Store activation state in options table
    update_option('aqm_security_active', true);
}

/**
 * Plugin deactivation function
 */
function aqm_security_deactivate() {
    // Update activation state in options table
    update_option('aqm_security_active', false);
    // Store that the plugin was active before deactivation
    update_option('aqm_security_was_active', false);
}

// Initialize the GitHub Updater
function aqm_security_init_github_updater() {
    // Log that we're initializing the updater
    if (defined('WP_DEBUG') && WP_DEBUG === true) {
        error_log('=========================================================');
        error_log('[AQM SECURITY v' . AQM_SECURITY_VERSION . '] USING CUSTOM UPDATER CLASS');
        error_log('=========================================================');
    }
    
    if (class_exists('AQM_Security_Updater')) {
        try {
            new AQM_Security_Updater(
                __FILE__,                // Plugin File
                'JustCasey76',           // GitHub username
                'aqm-security',          // GitHub repository name
                ''                       // Optional GitHub access token (for private repos)
            );
            
            // Set last update check time
            update_option('aqm_security_last_update_check', time());
        } catch (Exception $e) {
            if (defined('WP_DEBUG') && WP_DEBUG === true) {
                error_log('[AQM SECURITY] Error initializing updater: ' . $e->getMessage());
            }
        }
    } else {
        if (defined('WP_DEBUG') && WP_DEBUG === true) {
            error_log('[AQM SECURITY] Updater class not found');
        }
    }
}
add_action('admin_init', 'aqm_security_init_github_updater');

// Show update success message
function aqm_security_show_update_success() {
    // Only show on plugins page
    $screen = get_current_screen();
    if (!$screen || $screen->id !== 'plugins') {
        return;
    }
    
    // Check if we're coming from an update
    if (isset($_GET['aqm_updated']) && $_GET['aqm_updated'] === '1') {
        echo '<div class="notice notice-success is-dismissible">
            <p><strong>AQM Security Updated Successfully!</strong> The plugin has been updated to version ' . AQM_SECURITY_VERSION . '.</p>
        </div>';
    }
    
    // Check if we're showing a reactivation notice
    if (get_transient('aqm_security_reactivated')) {
        // Delete the transient
        delete_transient('aqm_security_reactivated');
        
        echo '<div class="notice notice-success is-dismissible">
            <p><strong>AQM Security Reactivated!</strong> The plugin has been reactivated after an update.</p>
        </div>';
    }
}
add_action('admin_notices', 'aqm_security_show_update_success');

/**
 * Handle the AJAX request to check for plugin updates.
 */
function aqm_security_handle_check_updates_ajax() {
    // Verify nonce
    check_ajax_referer('aqm-security-check-updates', 'nonce');
    
    // Clear update transients to force a fresh check
    delete_transient('aqm_security_github_data_' . md5('JustCasey76' . 'aqm-security'));
    delete_site_transient('update_plugins');
    
    // Force WordPress to check for updates
    wp_clean_plugins_cache(true);
    
    // Log the manual update check
    if (defined('WP_DEBUG') && WP_DEBUG === true) {
        error_log('[AQM SECURITY] Manual update check triggered');
    }
    
    // Update the last check time
    update_option('aqm_security_last_update_check', time());
    
    // Send success response
    wp_send_json_success(array('message' => 'Update check completed successfully.'));
}
add_action('wp_ajax_aqm_security_check_updates', 'aqm_security_handle_check_updates_ajax');

/**
 * Add custom action links to the plugin entry on the plugins page.
 *
 * @param array $links An array of plugin action links.
 * @return array An array of plugin action links.
 */
function aqm_security_add_action_links($links) {
    // Add 'Check for Updates' link
    $check_update_link = '<a href="' . wp_nonce_url(admin_url('admin-ajax.php?action=aqm_security_check_updates'), 'aqm-security-check-updates') . '" class="aqm-security-check-updates">Check for Updates</a>';
    array_unshift($links, $check_update_link);
    
    return $links;
}
add_filter('plugin_action_links_' . AQM_SECURITY_BASENAME, 'aqm_security_add_action_links');

/**
 * Enqueue admin scripts for the plugins page.
 *
 * @param string $hook The current admin page.
 */
function aqm_security_enqueue_admin_scripts($hook) {
    if ($hook !== 'plugins.php') {
        return;
    }
    
    // Enqueue inline script for the update check button
    wp_enqueue_script('jquery');
    
    add_action('admin_footer', function() {
        ?>
        <script type="text/javascript">
        jQuery(document).ready(function($) {
            // Handle the "Check for Updates" link click
            $('.aqm-security-check-updates').on('click', function(e) {
                e.preventDefault();
                
                var $link = $(this);
                var originalText = $link.text();
                
                // Show loading state
                $link.text('Checking...').css('opacity', '0.7');
                
                // Make the AJAX request
                $.ajax({
                    url: $link.attr('href'),
                    type: 'GET',
                    dataType: 'json',
                    success: function(response) {
                        if (response.success) {
                            // Show success message
                            $link.text('Check Complete!');
                            
                            // Show an admin notice
                            var notice = $('<div class="notice notice-success is-dismissible"><p><strong>AQM Security:</strong> ' + response.data.message + '</p></div>');
                            $('.wrap h1').after(notice);
                            
                            // Reset the button after 2 seconds
                            setTimeout(function() {
                                $link.text(originalText).css('opacity', '1');
                            }, 2000);
                            
                            // Reload the page after 3 seconds to show any updates
                            setTimeout(function() {
                                window.location.reload();
                            }, 3000);
                        }
                    },
                    error: function() {
                        // Show error message
                        $link.text('Check Failed!');
                        
                        // Reset the button after 2 seconds
                        setTimeout(function() {
                            $link.text(originalText).css('opacity', '1');
                        }, 2000);
                    }
                });
            });
        });
        </script>
        <?php
    });
}
add_action('admin_enqueue_scripts', 'aqm_security_enqueue_admin_scripts');

// Initialize the plugin
function run_aqm_security() {
    $plugin = new AQM_Security();
    $plugin->run();
}
run_aqm_security();
