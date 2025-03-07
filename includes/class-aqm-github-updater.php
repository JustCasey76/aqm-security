<?php
/**
 * GitHub Updater Class
 *
 * Enables automatic updates from a GitHub repository for the AQM Security plugin.
 *
 * @package    AQM_Security
 * @subpackage AQM_Security/includes
 */

if (!class_exists('AQM_GitHub_Updater')):

class AQM_GitHub_Updater {

    /**
     * GitHub repository data
     *
     * @var array
     */
    private $config;

    /**
     * The plugin basename
     * 
     * @var string
     */
    private $basename;

    /**
     * The plugin slug
     * 
     * @var string
     */
    private $slug;

    /**
     * GitHub API response data
     * 
     * @var object
     */
    private $github_response;

    /**
     * Constructor
     * 
     * @param array $config Configuration settings for the updater
     */
    public function __construct($config = []) {
        $defaults = [
            'slug' => plugin_basename(__FILE__),
            'proper_folder_name' => dirname(plugin_basename(__FILE__)),
            'api_url' => 'https://api.github.com/repos/JustCasey76/aqm-security',
            'raw_url' => 'https://raw.github.com/JustCasey76/aqm-security/main',
            'github_url' => 'https://github.com/JustCasey76/aqm-security',
            'zip_url' => 'https://github.com/JustCasey76/aqm-security/archive/main.zip',
            'sslverify' => true,
            'requires' => '5.6',
            'tested' => '6.4',
            'readme' => 'README.md',
            'access_token' => '',
        ];

        $this->config = wp_parse_args($config, $defaults);
        $this->set_basename();

        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_update']);
        add_filter('plugins_api', [$this, 'plugin_popup'], 10, 3);
        add_filter('upgrader_post_install', [$this, 'after_install'], 10, 3);
        
        // Clean up options when plugin is deleted
        register_deactivation_hook($this->config['slug'], [$this, 'flush_update_cache']);
    }

    /**
     * Set the plugin basename
     */
    private function set_basename() {
        $this->basename = $this->config['slug'];
        $this->slug = dirname($this->basename);
    }

    /**
     * Get GitHub data from the specified repository
     *
     * @return array Updated version number and download link
     */
    private function get_repository_info() {
        if (!empty($this->github_response)) {
            return;
        }

        // Use GitHub API v3 to get the latest release info
        $request_uri = $this->config['api_url'] . '/releases/latest';
        
        // Set headers for GitHub API request
        $request_headers = [];
        $request_headers[] = 'Accept: application/vnd.github.v3+json';
        
        // Use access token if available
        if (!empty($this->config['access_token'])) {
            $request_headers[] = 'Authorization: token ' . $this->config['access_token'];
        }

        $response = wp_remote_get(
            $request_uri,
            [
                'headers' => $request_headers,
                'sslverify' => $this->config['sslverify'],
            ]
        );

        if (is_wp_error($response) || 200 !== wp_remote_retrieve_response_code($response)) {
            $this->log_error('Error fetching GitHub release info: ' . wp_remote_retrieve_response_message($response));
            return;
        }

        $response_body = json_decode(wp_remote_retrieve_body($response));
        
        // If there's no release data or no tag name, return
        if (empty($response_body) || !isset($response_body->tag_name)) {
            $this->log_error('Invalid GitHub release data received');
            return;
        }

        // Parse release info
        $this->github_response = new stdClass();
        $this->github_response->tag_name = $response_body->tag_name;
        $this->github_response->version = ltrim($response_body->tag_name, 'v');
        $this->github_response->published_at = $response_body->published_at;
        $this->github_response->zipball_url = $response_body->zipball_url;
        $this->github_response->body = $response_body->body; // Release notes

        // Check if there are any assets (pre-built zip files)
        if (!empty($response_body->assets) && $this->config['release_asset']) {
            foreach ($response_body->assets as $asset) {
                if (strpos($asset->name, '.zip') !== false) {
                    $this->github_response->download_url = $asset->browser_download_url;
                    break;
                }
            }
        }

        // If no asset found, use the source code zip
        if (empty($this->github_response->download_url)) {
            $this->github_response->download_url = $response_body->zipball_url;
        }
    }

    /**
     * Check for updates and modify the update transient
     *
     * @param object $transient Update transient object
     * @return object Modified update transient
     */
    public function check_update($transient) {
        if (empty($transient->checked)) {
            return $transient;
        }

        // Get current plugin version
        $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $this->basename);
        $current_version = $plugin_data['Version'];

        // Get repository data
        $this->get_repository_info();

        // If no response or error, return original transient
        if (empty($this->github_response)) {
            return $transient;
        }

        // Compare versions using version_compare
        $github_version = $this->github_response->version;
        $update_available = version_compare($github_version, $current_version, '>');
        
        // Log version comparison for debugging
        $this->log_error("Version comparison: GitHub version: {$github_version}, Current version: {$current_version}, Update available: " . ($update_available ? 'Yes' : 'No'));
        
        // If newer version exists, add it to the transient
        if ($update_available) {
            $package = $this->github_response->download_url;
            
            // Create the plugin update object
            $obj = new stdClass();
            $obj->slug = $this->slug;
            $obj->new_version = $github_version;
            $obj->url = $this->config['github_url'];
            $obj->package = $package;
            
            // Plugin folder might be named differently than slug
            $obj->plugin = $this->basename;
            
            $transient->response[$this->basename] = $obj;
        }
        
        return $transient;
    }

    /**
     * Get plugin information for the update details popup
     *
     * @param bool|object $result The result object or false
     * @param string $action The API function being performed
     * @param object $args Plugin arguments
     * @return object|bool Plugin information or false
     */
    public function plugin_popup($result, $action, $args) {
        if ($action !== 'plugin_information') {
            return $result;
        }

        if (!isset($args->slug) || $args->slug !== $this->slug) {
            return $result;
        }

        // Get repository info
        $this->get_repository_info();

        if (empty($this->github_response)) {
            return $result;
        }

        $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $this->basename);

        $obj = new stdClass();
        $obj->name = $plugin_data['Name'];
        $obj->slug = $this->slug;
        $obj->version = $this->github_response->version;
        $obj->tested = $this->config['tested'];
        $obj->requires = $this->config['requires'];
        $obj->author = $plugin_data['Author'];
        $obj->author_profile = $plugin_data['AuthorURI'];
        $obj->homepage = $this->config['github_url'];
        $obj->download_link = $this->github_response->download_url;
        $obj->trunk = $this->github_response->download_url;
        $obj->last_updated = $this->github_response->published_at;
        
        // Format release notes
        $obj->sections = [
            'description' => $plugin_data['Description'],
            'changelog' => $this->format_release_notes($this->github_response->body),
        ];

        return $obj;
    }

    /**
     * Format GitHub release notes to WordPress format
     *
     * @param string $notes GitHub release notes (markdown)
     * @return string Formatted release notes
     */
    private function format_release_notes($notes) {
        // Basic markdown to HTML conversion
        $notes = preg_replace('/[#]+(.*)/', '<h4>$1</h4>', $notes);
        $notes = preg_replace('/[*|-](.*)/', '<li>$1</li>', $notes);
        $notes = preg_replace('/\n/', '<br>', $notes);
        
        return '<div class="changelog">' . $notes . '</div>';
    }

    /**
     * Rename the folder after update is complete
     *
     * @param bool $response Installation response
     * @param array $hook_extra Extra arguments passed to hook
     * @param array $result Installation result data
     * @return array Modified installation result data
     */
    public function after_install($response, $hook_extra, $result) {
        // If this is not our plugin, exit
        if (!isset($hook_extra['plugin']) || $hook_extra['plugin'] !== $this->basename) {
            return $result;
        }

        // Move the plugin to the correct folder
        global $wp_filesystem;
        $wp_filesystem->move($result['destination'], WP_PLUGIN_DIR . '/' . $this->config['proper_folder_name']);
        $result['destination'] = WP_PLUGIN_DIR . '/' . $this->config['proper_folder_name'];

        // Activate the plugin again
        $activate = activate_plugin($this->basename);
        
        return $result;
    }

    /**
     * Clean up update data on plugin deactivation
     */
    public function flush_update_cache() {
        delete_site_transient('update_plugins');
        delete_site_transient('aqm_github_updater_latest_release');
        delete_site_transient($this->slug . '_github_data');
    }

    /**
     * Log errors for debugging
     *
     * @param string $message Error message to log
     */
    private function log_error($message) {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('[AQM GitHub Updater] ' . $message);
        }
    }
}

endif; // class_exists check
