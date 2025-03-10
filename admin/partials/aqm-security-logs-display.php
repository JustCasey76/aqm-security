<?php
/**
 * Provide a admin area view for the plugin logs page
 */

// Get available dates
$dates = AQM_Security_Logger::get_log_dates();

// Get current date, defaulting to today if none specified
$current_date = isset($_GET['date']) ? sanitize_text_field($_GET['date']) : date('Y-m-d');

// Get filter parameters
$filters = array();
$filter_fields = array('ip', 'country', 'region', 'zipcode', 'allowed');

foreach ($filter_fields as $field) {
    if (isset($_GET[$field]) && $_GET[$field] !== '') {
        $filters[$field] = sanitize_text_field($_GET[$field]);
    }
}

// Get total logs count with filters
$total_logs = AQM_Security_Logger::count_logs($current_date, $filters);

// Pagination settings
$per_page = 50;
$total_pages = ceil($total_logs / $per_page);
$current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
$offset = ($current_page - 1) * $per_page;

// Get paginated logs with filters
$logs = AQM_Security_Logger::get_logs($current_date, $per_page, $offset, $filters);

// Get unique values for filter dropdowns
$countries = AQM_Security_Logger::get_unique_values('country', $current_date);
$regions = AQM_Security_Logger::get_unique_values('region', $current_date);
$zipcodes = AQM_Security_Logger::get_unique_values('zipcode', $current_date);

// Format the current URL without filters for reset button
$reset_url = add_query_arg(array(
    'page' => 'aqm-security-logs',
    'date' => $current_date
), admin_url('admin.php'));
?>
<div class="wrap">
    <h1><?php echo esc_html__('AQM Security Visitor Logs', 'aqm-security'); ?></h1>
    
    <?php if (empty($dates)): ?>
        <div class="notice notice-info">
            <p><?php echo esc_html__('No visitor logs available.', 'aqm-security'); ?></p>
        </div>
    <?php else: ?>
        <!-- Date selection dropdown -->
        <div class="tablenav top">
            <div class="alignleft actions">
                <form method="get" action="<?php echo esc_url(admin_url('admin.php')); ?>">
                    <input type="hidden" name="page" value="aqm-security-logs">
                    
                    <!-- Date Filter -->
                    <select name="date">
                        <?php foreach ($dates as $date): ?>
                            <option value="<?php echo esc_attr($date); ?>" <?php selected($date, $current_date); ?>>
                                <?php echo esc_html($date); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                    
                    <!-- Filter Bar -->
                    <div style="display: inline-block; margin-left: 10px;">
                        <!-- IP Address Filter -->
                        <input type="text" name="ip" placeholder="<?php echo esc_attr__('IP Address', 'aqm-security'); ?>" 
                               value="<?php echo isset($filters['ip']) ? esc_attr($filters['ip']) : ''; ?>" 
                               style="width: 120px;">
                        
                        <!-- Country Filter -->
                        <select name="country" style="width: 120px;">
                            <option value=""><?php echo esc_html__('All Countries', 'aqm-security'); ?></option>
                            <?php foreach ($countries as $country): ?>
                                <option value="<?php echo esc_attr($country); ?>" <?php selected(isset($filters['country']) ? $filters['country'] : '', $country); ?>>
                                    <?php echo esc_html($country); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        
                        <!-- Region Filter -->
                        <select name="region" style="width: 120px;">
                            <option value=""><?php echo esc_html__('All Regions', 'aqm-security'); ?></option>
                            <?php foreach ($regions as $region): ?>
                                <option value="<?php echo esc_attr($region); ?>" <?php selected(isset($filters['region']) ? $filters['region'] : '', $region); ?>>
                                    <?php echo esc_html($region); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        
                        <!-- Zipcode Filter -->
                        <select name="zipcode" style="width: 120px;">
                            <option value=""><?php echo esc_html__('All Zipcodes', 'aqm-security'); ?></option>
                            <?php foreach ($zipcodes as $zipcode): ?>
                                <option value="<?php echo esc_attr($zipcode); ?>" <?php selected(isset($filters['zipcode']) ? $filters['zipcode'] : '', $zipcode); ?>>
                                    <?php echo esc_html($zipcode); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        
                        <!-- Status Filter -->
                        <select name="allowed" style="width: 120px;">
                            <option value=""><?php echo esc_html__('All Status', 'aqm-security'); ?></option>
                            <option value="1" <?php selected(isset($filters['allowed']) && $filters['allowed'] === '1', true); ?>>
                                <?php echo esc_html__('Allowed', 'aqm-security'); ?>
                            </option>
                            <option value="0" <?php selected(isset($filters['allowed']) && $filters['allowed'] === '0', true); ?>>
                                <?php echo esc_html__('Blocked', 'aqm-security'); ?>
                            </option>
                        </select>
                    </div>
                    
                    <input type="submit" class="button" value="<?php echo esc_attr__('Apply Filters', 'aqm-security'); ?>">
                    <a href="<?php echo esc_url($reset_url); ?>" class="button"><?php echo esc_html__('Reset Filters', 'aqm-security'); ?></a>
                    <a href="<?php echo esc_url(add_query_arg('date', date('Y-m-d'))); ?>" class="button"><?php echo esc_html__('Today', 'aqm-security'); ?></a>
                </form>
            </div>
            <div class="alignright">
                <form method="post" onsubmit="return confirm('<?php echo esc_js(__('Are you sure you want to clear all logs for this date?', 'aqm-security')); ?>');">
                    <?php wp_nonce_field('aqm_security_admin_nonce', 'aqm_security_nonce'); ?>
                    <button type="button" id="aqm_security_clear_visitor_logs" class="button" data-date="<?php echo esc_attr($current_date); ?>">
                        <?php echo esc_html__('Clear Logs for This Date', 'aqm-security'); ?>
                    </button>
                </form>
            </div>
            <br class="clear">
        </div>
        
        <?php if (empty($logs)): ?>
            <div class="notice notice-info">
                <p><?php echo esc_html__('No visitor logs available for the selected date and filters.', 'aqm-security'); ?></p>
            </div>
        <?php else: ?>
            <!-- Results summary -->
            <div class="tablenav top">
                <div class="tablenav-pages">
                    <span class="displaying-num">
                        <?php printf(
                            esc_html(_n('%s item', '%s items', $total_logs, 'aqm-security')),
                            number_format_i18n($total_logs)
                        ); ?>
                    </span>
                    <?php if (count($filters) > 0): ?>
                        <span class="filter-summary">
                            <?php 
                            $filter_labels = array(
                                'ip' => __('IP', 'aqm-security'),
                                'country' => __('Country', 'aqm-security'),
                                'region' => __('Region', 'aqm-security'),
                                'zipcode' => __('Zipcode', 'aqm-security'),
                                'allowed' => __('Status', 'aqm-security')
                            );
                            
                            $active_filters = array();
                            foreach ($filters as $key => $value) {
                                if ($key === 'allowed') {
                                    $status_value = $value == '1' ? __('Allowed', 'aqm-security') : __('Blocked', 'aqm-security');
                                    $active_filters[] = sprintf('%s: %s', $filter_labels[$key], $status_value);
                                } else {
                                    $active_filters[] = sprintf('%s: %s', $filter_labels[$key], $value);
                                }
                            }
                            
                            if (!empty($active_filters)) {
                                echo '| <strong>' . esc_html__('Active Filters:', 'aqm-security') . '</strong> ';
                                echo esc_html(implode(' | ', $active_filters));
                            }
                            ?>
                        </span>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- Visitor logs table -->
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php echo esc_html__('Date & Time (EST)', 'aqm-security'); ?></th>
                        <th><?php echo esc_html__('IP Address', 'aqm-security'); ?></th>
                        <th><?php echo esc_html__('Country', 'aqm-security'); ?></th>
                        <th><?php echo esc_html__('Region', 'aqm-security'); ?></th>
                        <th><?php echo esc_html__('Zipcode', 'aqm-security'); ?></th>
                        <th><?php echo esc_html__('Status', 'aqm-security'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($logs as $log): ?>
                        <tr>
                            <td><?php 
                                // Get the timestamp
                                $timestamp = strtotime($log['timestamp']);
                                
                                // Convert to EST timezone
                                $date = new DateTime();
                                $date->setTimestamp($timestamp);
                                $date->setTimezone(new DateTimeZone('America/New_York'));
                                
                                // Format: YYYY-MM-DD h:MM:SS AM/PM EST (12-hour format with AM/PM)
                                echo esc_html($date->format('Y-m-d g:i:s A').' EST'); 
                            ?></td>
                            <td>
                                <?php echo esc_html($log['ip']); ?>
                                <div class="row-actions">
                                    <span class="filter">
                                        <a href="<?php echo esc_url(add_query_arg(array('page' => 'aqm-security-logs', 'date' => $current_date, 'ip' => $log['ip']))); ?>">
                                            <?php echo esc_html__('Filter', 'aqm-security'); ?>
                                        </a>
                                    </span>
                                </div>
                            </td>
                            <td>
                                <?php if (!empty($log['flag_url'])): ?>
                                    <img src="<?php echo esc_url($log['flag_url']); ?>" alt="<?php echo esc_attr($log['country']); ?>" 
                                         style="width: 20px; height: auto; vertical-align: middle; margin-right: 5px;">
                                <?php endif; ?>
                                <?php echo esc_html($log['country']); ?>
                                <div class="row-actions">
                                    <span class="filter">
                                        <a href="<?php echo esc_url(add_query_arg(array('page' => 'aqm-security-logs', 'date' => $current_date, 'country' => $log['country']))); ?>">
                                            <?php echo esc_html__('Filter', 'aqm-security'); ?>
                                        </a>
                                    </span>
                                </div>
                            </td>
                            <td>
                                <?php echo esc_html($log['region']); ?>
                                <div class="row-actions">
                                    <span class="filter">
                                        <a href="<?php echo esc_url(add_query_arg(array('page' => 'aqm-security-logs', 'date' => $current_date, 'region' => $log['region']))); ?>">
                                            <?php echo esc_html__('Filter', 'aqm-security'); ?>
                                        </a>
                                    </span>
                                </div>
                            </td>
                            <td>
                                <?php echo esc_html($log['zipcode']); ?>
                                <div class="row-actions">
                                    <span class="filter">
                                        <a href="<?php echo esc_url(add_query_arg(array('page' => 'aqm-security-logs', 'date' => $current_date, 'zipcode' => $log['zipcode']))); ?>">
                                            <?php echo esc_html__('Filter', 'aqm-security'); ?>
                                        </a>
                                    </span>
                                </div>
                            </td>
                            <td>
                                <?php if ($log['allowed']): ?>
                                    <span class="dashicons dashicons-yes-alt" style="color: green;" title="<?php echo esc_attr__('Allowed', 'aqm-security'); ?>"></span>
                                    <span style="color: green; font-weight: bold;"><?php echo esc_html__('Allowed', 'aqm-security'); ?></span>
                                <?php else: ?>
                                    <span class="dashicons dashicons-dismiss" style="color: red;" title="<?php echo esc_attr__('Blocked', 'aqm-security'); ?>"></span>
                                    <span style="color: red; font-weight: bold;"><?php echo esc_html__('Blocked', 'aqm-security'); ?></span>
                                <?php endif; ?>
                                <div class="row-actions">
                                    <span class="filter">
                                        <a href="<?php echo esc_url(add_query_arg(array('page' => 'aqm-security-logs', 'date' => $current_date, 'allowed' => $log['allowed']))); ?>">
                                            <?php echo esc_html__('Filter', 'aqm-security'); ?>
                                        </a>
                                    </span>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            
            <!-- Pagination -->
            <?php if ($total_pages > 1): ?>
                <div class="tablenav bottom">
                    <div class="tablenav-pages">
                        <span class="displaying-num">
                            <?php printf(
                                esc_html(_n('%s item', '%s items', $total_logs, 'aqm-security')),
                                number_format_i18n($total_logs)
                            ); ?>
                        </span>
                        <span class="pagination-links">
                            <?php
                            // Build pagination links preserving all filters
                            $pagination_args = array_merge(
                                array('page' => 'aqm-security-logs', 'date' => $current_date),
                                $filters
                            );
                            
                            echo paginate_links(array(
                                'base' => add_query_arg('paged', '%#%'),
                                'format' => '',
                                'prev_text' => __('&laquo;'),
                                'next_text' => __('&raquo;'),
                                'total' => $total_pages,
                                'current' => $current_page,
                                'add_args' => $filters
                            ));
                            ?>
                        </span>
                    </div>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    <?php endif; ?>
    
    <style>
        /* Improve filter styling */
        .tablenav .alignleft.actions {
            padding: 10px;
            background: #f9f9f9;
            border: 1px solid #e5e5e5;
            border-radius: 4px;
            margin-bottom: 10px;
        }
        
        /* Style for active filters display */
        .filter-summary {
            margin-left: 10px;
            font-size: 12px;
        }
        
        /* Style hover effect for row actions */
        .wp-list-table .row-actions {
            visibility: hidden;
            font-size: 11px;
            color: #666;
        }
        
        .wp-list-table tr:hover .row-actions {
            visibility: visible;
        }
        
        .wp-list-table .row-actions .filter a {
            color: #0073aa;
        }
        
        /* Responsive styling for filters */
        @media screen and (max-width: 782px) {
            .tablenav .alignleft.actions div {
                display: block;
                margin: 5px 0;
            }
            
            .tablenav .alignleft.actions select,
            .tablenav .alignleft.actions input[type="text"] {
                width: 100%;
                margin: 2px 0;
                display: block;
            }
        }
    </style>
</div>
