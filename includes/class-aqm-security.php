<?php
/**
 * The core plugin class.
 */
class AQM_Security {

    /**
     * The loader that's responsible for maintaining and registering all hooks.
     *
     * @access protected
     * @var AQM_Security_Loader $loader Maintains and registers all hooks for the plugin.
     */
    protected $loader;
    
    /**
     * The name of the plugin.
     *
     * @since    1.0.0
     * @access   public
     * @var      string    $plugin_name    The name of the plugin.
     */
    public $plugin_name;
    
    /**
     * The current version of the plugin.
     *
     * @since    1.0.0
     * @access   public
     * @var      string    $version    The current version of the plugin.
     */
    public $version;

    /**
     * Define the core functionality of the plugin.
     */
    public function __construct() {
        $this->plugin_name = 'aqm-security';
        $this->version = AQM_SECURITY_VERSION;
        
        $this->load_dependencies();
        $this->define_admin_hooks();
        $this->define_public_hooks();
        
        // Create log table on plugin load
        AQM_Security_Logger::maybe_create_table();
    }

    /**
     * Load the required dependencies for this plugin.
     *
     * @access private
     */
    private function load_dependencies() {
        // The class responsible for orchestrating the actions and filters of the core plugin.
        require_once AQM_SECURITY_PLUGIN_DIR . 'includes/class-aqm-security-loader.php';
        
        // The class responsible for defining all actions related to admin area.
        require_once AQM_SECURITY_PLUGIN_DIR . 'admin/class-aqm-security-admin.php';
        
        // The class responsible for defining all public-facing functionality.
        require_once AQM_SECURITY_PLUGIN_DIR . 'public/class-aqm-security-public.php';
        
        // The class responsible for API operations with ipapi.com
        require_once AQM_SECURITY_PLUGIN_DIR . 'includes/class-aqm-security-api.php';
        
        // The class responsible for logging visitor information
        require_once AQM_SECURITY_PLUGIN_DIR . 'includes/class-aqm-security-logger.php';

        $this->loader = new AQM_Security_Loader();
    }

    /**
     * Register all of the hooks related to the admin area functionality.
     *
     * @access private
     */
    private function define_admin_hooks() {
        $plugin_admin = new AQM_Security_Admin();
        
        $this->loader->add_action('admin_enqueue_scripts', $plugin_admin, 'enqueue_styles');
        $this->loader->add_action('admin_enqueue_scripts', $plugin_admin, 'enqueue_scripts');
        
        // Add menu items
        $this->loader->add_action('admin_menu', $plugin_admin, 'add_menu_items');
        
        // Save/Update settings
        $this->loader->add_action('admin_init', $plugin_admin, 'register_settings');
    }

    /**
     * Register all of the hooks related to the public-facing functionality.
     *
     * @access private
     */
    private function define_public_hooks() {
        $plugin_public = new AQM_Security_Public($this->get_plugin_name(), $this->get_version());
        
        $this->loader->add_action('wp_enqueue_scripts', $plugin_public, 'enqueue_styles');
        $this->loader->add_action('wp_enqueue_scripts', $plugin_public, 'enqueue_scripts');
        
        // CRITICAL FIX: Use both wp and template_redirect hooks to ensure visitor logging works in all cases
        // The wp hook might be too early for logging in some cases, so we use template_redirect as a backup
        $this->loader->add_action('wp', $plugin_public, 'check_geolocation', 5);
        $this->loader->add_action('template_redirect', $plugin_public, 'check_geolocation', 5);
        
        // Hook into Formidable Forms if they exist
        if (class_exists('FrmForm')) {
            $this->loader->add_filter('frm_continue_to_new', $plugin_public, 'maybe_block_form', 10, 2);
            $this->loader->add_filter('frm_pre_display_form', $plugin_public, 'maybe_replace_form', 10, 1);
        }
    }

    /**
     * Run the loader to execute all of the hooks with WordPress.
     */
    public function run() {
        $this->loader->run();
    }

    /**
     * Get the plugin name
     *
     * @return string
     */
    public function get_plugin_name() {
        return $this->plugin_name;
    }

    /**
     * Get the plugin version
     *
     * @return string
     */
    public function get_version() {
        return $this->version;
    }
}
