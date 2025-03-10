<?php
/**
 * Plugin Name: AQM Security
 * Plugin URI: https://github.com/JustCasey76/aqm-security
 * Description: Geolocation-based security plugin using ipapi.com to control access to Formidable Forms.
 * Version: 1.2.9
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
define('AQM_SECURITY_VERSION', '1.2.9');
define('AQM_SECURITY_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('AQM_SECURITY_PLUGIN_URL', plugin_dir_url(__FILE__));

/**
 * Include the GitHub Updater class if available
 */
if (!class_exists('AQM_GitHub_Updater')) {
    require_once AQM_SECURITY_PLUGIN_DIR . 'includes/class-aqm-github-updater.php';
}

// Initialize GitHub Updater
if (class_exists('AQM_GitHub_Updater')) {
    new AQM_GitHub_Updater([
        'slug' => plugin_basename(__FILE__),
        'proper_folder_name' => 'aqm-security',
        'api_url' => 'https://api.github.com/repos/JustCasey76/aqm-security',
        'raw_url' => 'https://raw.githubusercontent.com/JustCasey76/aqm-security/main',
        'github_url' => 'https://github.com/JustCasey76/aqm-security',
        'zip_url' => 'https://github.com/JustCasey76/aqm-security/archive/main.zip',
        'sslverify' => true,
        'requires' => '5.6',
        'tested' => '6.4',
        'readme' => 'README.md',
    ]);
}

// Include required files
require_once AQM_SECURITY_PLUGIN_DIR . 'includes/class-aqm-security.php';

// Initialize the plugin
function run_aqm_security() {
    $plugin = new AQM_Security();
    $plugin->run();
}
run_aqm_security();
