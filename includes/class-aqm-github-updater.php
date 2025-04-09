<?php
/**
 * GitHub Updater Class
 *
 * Enables automatic updates from a GitHub repository for the AQM Security plugin.
 *
 * @package    AQM_Security
 * @subpackage AQM_Security/includes
 */

if (!class_exists('AQM_Security_GitHub_Updater')):

class AQM_Security_GitHub_Updater {

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
            'api_url' => 'https://api.github.com/repos/JustCasey76/aqm-plugins',
            'raw_url' => 'https://raw.github.com/JustCasey76/aqm-plugins/main',
            'github_url' => 'https://github.com/JustCasey76/aqm-plugins',
            'zip_url' => 'https://github.com/JustCasey76/aqm-plugins/archive/main.zip',
            'sslverify' => true,
            'requires' => '5.6',
            'tested' => '6.4',
            'readme' => 'README.md',
            'access_token' => '',
            'subdir' => '', // New parameter for plugin subdirectory within the repository
        ];

        $this->config = wp_parse_args($config, $defaults);
        $this->set_basename();

        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_update']);
        add_filter('plugins_api', [$this, 'plugin_popup'], 10, 3);
        add_filter('upgrader_post_install', [$this, 'after_install'], 10, 3);
        
        // Add "Check for Updates" link to plugin list
        add_filter('plugin_action_links_' . $this->basename, [$this, 'add_check_update_link']);
        
        // Handle the manual update check action
        add_action('admin_init', [$this, 'handle_manual_update_check']);
        
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
        
        // Log the API request for debugging
        $this->log_error("Making GitHub API request to: {$request_uri}");
        
        // Set headers for GitHub API request
        $request_headers = [];
        $request_headers[] = 'Accept: application/vnd.github.v3+json';
        $request_headers[] = 'User-Agent: WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url');
        
        // Use access token if available
        if (!empty($this->config['access_token'])) {
            $request_headers[] = 'Authorization: token ' . $this->config['access_token'];
        }

        // Build the request arguments
        $request_args = [
            'headers' => $request_headers,
            'sslverify' => $this->config['sslverify'],
            'timeout' => 10
        ];

        // Make the request
        $response = wp_remote_get($request_uri, $request_args);

        // Check for errors
        if (is_wp_error($response)) {
            $this->log_error('Error fetching GitHub repository data: ' . $response->get_error_message());
            return;
        }

        // Check response code
        $response_code = wp_remote_retrieve_response_code($response);
        if ($response_code !== 200) {
            $this->log_error("GitHub API returned non-200 status code: {$response_code}");
            $body = wp_remote_retrieve_body($response);
            $this->log_error("Response body: " . substr($body, 0, 500));
            return;
        }

        // Parse the response
        $response_body = wp_remote_retrieve_body($response);
        $release_data = json_decode($response_body);

        // Check if we got valid data
        if (empty($release_data) || !is_object($release_data)) {
            $this->log_error('Invalid GitHub API response: ' . substr($response_body, 0, 300) . '...');
            return;
        }

        // Log successful API response
        $this->log_error("Successfully retrieved GitHub release data. Tag name: " . (isset($release_data->tag_name) ? $release_data->tag_name : 'Tag not found'));
        
        // Force refresh transients when manually checking
        if (isset($_GET['action']) && $_GET['action'] === 'check_for_updates' && 
            isset($_GET['plugin']) && $_GET['plugin'] === $this->basename) {
            delete_site_transient('update_plugins');
        }

        // Store the response for use in check_update
        $this->github_response = $release_data;
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

        // Force update check if manually triggered
        $force_check = isset($_GET['action']) && $_GET['action'] === 'check_for_updates' && 
                      isset($_GET['plugin']) && $_GET['plugin'] === $this->basename;
        
        // Get data from GitHub
        $this->get_repository_info();

        // Check if a new version is available
        if (isset($this->github_response->tag_name)) {
            // GitHub releases have 'v' prefix (v1.3.4) but our versions don't (1.3.4)
            $tag_version = ltrim($this->github_response->tag_name, 'v');
            
            // Log version comparison for debugging
            $this->log_error("Comparing versions: GitHub tag: {$this->github_response->tag_name}, Cleaned tag: {$tag_version}, Current version: " . AQM_SECURITY_VERSION . ", Result: " . (version_compare($tag_version, AQM_SECURITY_VERSION, '>') ? 'Update Available' : 'No Update Needed'));
            
            if (version_compare($tag_version, AQM_SECURITY_VERSION, '>')) {
                $download_link = isset($this->github_response->zipball_url) 
                    ? $this->github_response->zipball_url 
                    : $this->github_response->tarball_url;

                // Add authorization to download URL if token is available
                if (!empty($this->config['access_token'])) {
                    $download_link = add_query_arg(
                        ['access_token' => $this->config['access_token']],
                        $download_link
                    );
                }

                $obj = new stdClass();
                $obj->slug = $this->slug;
                $obj->new_version = $this->github_response->tag_name;
                $obj->url = $this->config['github_url'];
                $obj->package = $download_link;
                $obj->tested = $this->config['tested'];
                $obj->requires = $this->config['requires'];
                $obj->last_updated = isset($this->github_response->published_at) ? $this->github_response->published_at : date('Y-m-d');
                
                // Add plugin info to transient
                $transient->response[$this->basename] = $obj;

                // Log successful update check
                $this->log_error("Update available: {$obj->new_version}");
            } else {
                // If no update is available, remove from response to avoid confusion
                if (isset($transient->response[$this->basename])) {
                    unset($transient->response[$this->basename]);
                }

                // Add to no_update list for clarity
                if (!isset($transient->no_update[$this->basename])) {
                    $obj = new stdClass();
                    $obj->slug = $this->slug;
                    $obj->plugin = $this->basename;
                    $obj->new_version = AQM_SECURITY_VERSION;
                    $obj->url = $this->config['github_url'];
                    $obj->package = '';
                    $obj->tested = $this->config['tested'];
                    $transient->no_update[$this->basename] = $obj;
                }
            }
        }

        // Show admin notice for manual checks
        if ($force_check) {
            add_action('admin_notices', function() {
                echo '<div class="notice notice-info is-dismissible"><p>AQM Security: Update check completed.</p></div>';
            });
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
        $obj->version = $this->github_response->tag_name;
        $obj->tested = $this->config['tested'];
        $obj->requires = $this->config['requires'];
        $obj->author = $plugin_data['Author'];
        $obj->author_profile = $plugin_data['AuthorURI'];
        $obj->homepage = $this->config['github_url'];
        $obj->download_link = $this->github_response->zipball_url;
        $obj->trunk = $this->github_response->zipball_url;
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

        global $wp_filesystem;
        
        // If plugin is in a subdirectory within the repository, move it from there
        if (!empty($this->config['subdir'])) {
            $subdir_source = $result['destination'] . '/' . $this->config['subdir'];
            
            // Check if the subdirectory exists in the downloaded package
            if ($wp_filesystem->exists($subdir_source)) {
                // Create a temporary directory
                $temp_dir = WP_PLUGIN_DIR . '/temp_' . time();
                $wp_filesystem->mkdir($temp_dir);
                
                // Move plugin files from subdirectory to temp directory
                $wp_filesystem->move($subdir_source, $temp_dir, true);
                
                // Delete the original extracted directory
                $wp_filesystem->delete($result['destination'], true);
                
                // Move from temp directory to final destination
                $wp_filesystem->move($temp_dir, WP_PLUGIN_DIR . '/' . $this->config['proper_folder_name'], true);
                $result['destination'] = WP_PLUGIN_DIR . '/' . $this->config['proper_folder_name'];
            } else {
                // If subdirectory doesn't exist, handle the default case
                $wp_filesystem->move($result['destination'], WP_PLUGIN_DIR . '/' . $this->config['proper_folder_name']);
                $result['destination'] = WP_PLUGIN_DIR . '/' . $this->config['proper_folder_name'];
            }
        } else {
            // Original behavior for non-subdirectory plugins
            $wp_filesystem->move($result['destination'], WP_PLUGIN_DIR . '/' . $this->config['proper_folder_name']);
            $result['destination'] = WP_PLUGIN_DIR . '/' . $this->config['proper_folder_name'];
        }

        // Activate the plugin again
        $activate = activate_plugin($this->basename);
        
        return $result;
    }

    /**
     * Add "Check for Updates" link to plugin list
     *
     * @param array $links Plugin action links
     * @return array Modified plugin action links
     */
    public function add_check_update_link($links) {
        $links[] = '<a href="' . admin_url('plugins.php?action=check_for_updates&plugin=' . $this->basename) . '">Check for Updates</a>';
        return $links;
    }

    /**
     * Handle manual update check action
     */
    public function handle_manual_update_check() {
        if (isset($_GET['action']) && $_GET['action'] === 'check_for_updates' && isset($_GET['plugin']) && $_GET['plugin'] === $this->basename) {
            $this->check_update(get_site_transient('update_plugins'));
            wp_redirect(admin_url('plugins.php'));
            exit;
        }
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
     * Log error messages for debugging
     * 
     * @param string $message Error message to log
     */
    private function log_error($message) {
        // Only save errors if WP_DEBUG is true
        if (defined('WP_DEBUG') && WP_DEBUG === true) {
            $log_file = WP_CONTENT_DIR . '/aqm-security-updater.log';
            
            // Include more context with each log message
            $date = date('Y-m-d H:i:s');
            $version = 'Plugin Version: ' . AQM_SECURITY_VERSION;
            $api_url = 'API URL: ' . $this->config['api_url'];
            
            error_log("[{$date}] {$message} | {$version} | {$api_url}\n", 3, $log_file);
        }
    }
}

endif; // class_exists check
