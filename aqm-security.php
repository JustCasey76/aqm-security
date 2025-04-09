<?php
/**
 * Plugin Name: AQM Security
 * Plugin URI: https://github.com/JustCasey76/aqm-security
 * Description: Geolocation-based security plugin using ipapi.com to control access to Formidable Forms.
 * Version: 2.0.1
 * Author: AQM
 * Author URI: https://justcasey76.com
 * Text Domain: aqm-security
 * GitHub Plugin URI: https://github.com/JustCasey76/aqm-security
 * GitHub Branch: main
 * Primary Branch: main
 * Release Asset: true
 * Requires at least: 5.6
 * Requires PHP: 7.3
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

// Define plugin constants
define('AQM_SECURITY_VERSION', '2.0.1');
define('AQM_SECURITY_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('AQM_SECURITY_PLUGIN_URL', plugin_dir_url(__FILE__));

/**
 * Include the GitHub Updater class
 * Use a unique class name to avoid conflicts with other plugins
 */
require_once AQM_SECURITY_PLUGIN_DIR . 'includes/class-aqm-github-updater.php';

// Initialize GitHub Updater with a unique class check to avoid conflicts
if (class_exists('AQM_Security_GitHub_Updater')) {
    // Make sure we're using our own updater class, not one from another plugin
    $updater_class = AQM_SECURITY_PLUGIN_DIR . 'includes/class-aqm-github-updater.php';
    if (file_exists($updater_class)) {
        $updater = new AQM_Security_GitHub_Updater([
            'slug' => plugin_basename(__FILE__),
            'proper_folder_name' => 'aqm-security',
            'api_url' => 'https://api.github.com/repos/JustCasey76/aqm-security',
            'raw_url' => 'https://raw.githubusercontent.com/JustCasey76/aqm-security/master',
            'github_url' => 'https://github.com/JustCasey76/aqm-security',
            'zip_url' => 'https://github.com/JustCasey76/aqm-security/archive/master.zip',
            'sslverify' => true,
            'requires' => '5.6',
            'tested' => '6.4',
            'readme' => 'README.md',
            'access_token' => '',
        ]);
    }
}

// Include required files
require_once AQM_SECURITY_PLUGIN_DIR . 'includes/class-aqm-security.php';

// Initialize the plugin
function run_aqm_security() {
    $plugin = new AQM_Security();
    $plugin->run();
}
run_aqm_security();
