<?php
/**
 * Admin Bar Notification
 *
 * Adds location and form visibility information to the admin bar for logged-in administrators.
 *
 * @package    AQM_Security
 * @subpackage AQM_Security/public
 * @since      1.3.9
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}

/**
 * Class for handling admin bar notifications
 */
class AQM_Security_Admin_Bar {

    /**
     * Initialize the class
     */
    public static function init() {
        // Only add the admin bar for administrators
        add_action( 'admin_bar_menu', array( __CLASS__, 'add_admin_bar_info' ), 999 );
        
        // Add styles to both frontend and admin area
        add_action( 'wp_head', array( __CLASS__, 'admin_bar_styles' ) );
        add_action( 'admin_head', array( __CLASS__, 'admin_bar_styles' ) );
    }

    /**
     * Add location and form visibility information to the admin bar
     * 
     * @param WP_Admin_Bar $wp_admin_bar Admin bar object
     */
    public static function add_admin_bar_info( $wp_admin_bar ) {
        // Only show for administrators
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        // Always show for admins, even in admin area

        // Get visitor geolocation data
        if ( ! class_exists( 'AQM_Security_API' ) ) {
            return;
        }

        $visitor_data = AQM_Security_API::get_visitor_geolocation( true );
        $is_allowed = AQM_Security_API::is_visitor_allowed( $visitor_data );

        // Get country and region information
        $country = isset( $visitor_data['country_code'] ) ? $visitor_data['country_code'] : 'Unknown';
        $country_name = isset( $visitor_data['country_name'] ) ? $visitor_data['country_name'] : 'Unknown';
        $region = isset( $visitor_data['region_code'] ) ? $visitor_data['region_code'] : '';
        $region_name = isset( $visitor_data['region_name'] ) ? $visitor_data['region_name'] : '';
        
        // Get flag emoji if available
        $flag = '';
        if ( isset( $visitor_data['location'] ) && isset( $visitor_data['location']['country_flag_emoji'] ) ) {
            $flag = $visitor_data['location']['country_flag_emoji'] . ' ';
        }

        // Get IP address
        $ip = isset( $visitor_data['ip'] ) ? $visitor_data['ip'] : 'Unknown';
        
        // Create the main node with status - no flag, just country code and status
        $status_class = $is_allowed ? 'aqm-allowed' : 'aqm-blocked';
        $status_text = $is_allowed ? 'ALLOWED' : 'BLOCKED';
        
        $title = '<span class="ab-icon"></span><span class="ab-label">' . $country . ' | ' . 
                 '<span class="aqm-status ' . $status_class . '">' . $status_text . '</span></span>';
        
        $wp_admin_bar->add_node( array(
            'id'    => 'aqm-security-location',
            'title' => $title,
            'href'  => admin_url( 'admin.php?page=aqm-security' ),
            'meta'  => array(
                'title' => 'AQM Security Location Info',
            ),
        ) );
        
        // No dropdown parent - we'll add items directly to the main node
        
        // Add items directly to the main node
        // IP Address
        $wp_admin_bar->add_node( array(
            'id'     => 'aqm-security-ip',
            'parent' => 'aqm-security-location',
            'title'  => 'IP: ' . $ip,
        ) );
        
        // Country Code
        $wp_admin_bar->add_node( array(
            'id'     => 'aqm-security-country',
            'parent' => 'aqm-security-location',
            'title'  => 'Country: ' . $country,
        ) );
        
        // State Code (if available)
        if ( ! empty( $region ) ) {
            $wp_admin_bar->add_node( array(
                'id'     => 'aqm-security-region',
                'parent' => 'aqm-security-location',
                'title'  => 'State: ' . $region,
            ) );
        }
        
        // Forms Visibility Status - using a different approach to avoid the random "1"
        $status_display = 'Forms: ' . $status_text;
        $wp_admin_bar->add_node( array(
            'id'     => 'aqm-security-forms-status',
            'parent' => 'aqm-security-location',
            'title'  => $status_display,
            'meta'   => array(
                'class' => 'aqm-forms-status ' . $status_class,
            ),
        ) );
        
        // Settings Link
        $wp_admin_bar->add_node( array(
            'id'     => 'aqm-security-settings',
            'parent' => 'aqm-security-location',
            'title'  => 'Manage Settings',
            'href'   => admin_url( 'admin.php?page=aqm-security' ),
        ) );
    }
    
    /**
     * Add custom styles for the admin bar
     */
    public static function admin_bar_styles() {
        // Only for administrators
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        
        ?>
        <style type="text/css">
            /* Main admin bar item styling */
            #wp-admin-bar-aqm-security-location .ab-icon:before {
                content: "\f230";
                top: 2px;
            }
            #wp-admin-bar-aqm-security-location .aqm-status {
                font-weight: bold;
                padding: 1px 5px;
                border-radius: 3px;
                display: inline-block;
                margin-left: 5px;
            }
            #wp-admin-bar-aqm-security-location .aqm-allowed {
                background-color: #46b450;
                color: #fff;
            }
            #wp-admin-bar-aqm-security-location .aqm-blocked {
                background-color: #dc3232;
                color: #fff;
            }
            
            /* Container for all location info */
            .aqm-info-container {
                padding: 8px 12px;
                min-width: 250px;
                font-size: 13px;
                line-height: 1.5;
            }
            
            /* Each row of information */
            .aqm-info-row {
                margin-bottom: 8px;
                display: block;
                clear: both;
            }
            
            /* Settings button row */
            .aqm-settings-row {
                margin-top: 12px;
                text-align: center;
            }
            
            /* Settings button styling */
            .aqm-settings-button {
                display: inline-block;
                padding: 5px 12px;
                background: #0073aa;
                color: #fff !important;
                border-radius: 3px;
                text-decoration: none !important;
                text-align: center;
            }
            .aqm-settings-button:hover {
                background: #0085ba;
            }
            
            /* Fix for admin bar dropdown */
            #wpadminbar .ab-submenu .ab-item {
                color: #eee;
            }
            
            /* Fix for status indicators in dropdown */
            #wp-admin-bar-aqm-security-forms-status.aqm-allowed .ab-item {
                background-color: #46b450 !important;
                color: #ffffff !important;
                font-weight: bold;
                border-radius: 3px;
                padding: 0 5px !important;
            }
            #wp-admin-bar-aqm-security-forms-status.aqm-blocked .ab-item {
                background-color: #dc3232 !important;
                color: #ffffff !important;
                font-weight: bold;
                border-radius: 3px;
                padding: 0 5px !important;
            }
        </style>
        <?php
    }
}

// Initialize the class
AQM_Security_Admin_Bar::init();
