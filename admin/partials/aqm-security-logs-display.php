<?php
/**
 * Provide a admin area view for the plugin logs page
 */

// Get available dates
$dates = AQM_Security_Logger::get_log_dates();

// Get current date, defaulting to today if none specified
$current_date = isset($_GET['date']) ? sanitize_text_field($_GET['date']) : date('Y-m-d');

// Get logs for the current date
$logs = AQM_Security_Logger::get_logs($current_date);

// Check if we need pagination
$total_logs = count($logs);
$per_page = 50;
$total_pages = ceil($total_logs / $per_page);
$current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
$offset = ($current_page - 1) * $per_page;

// Get paginated logs
if ($total_logs > $per_page) {
    $logs = array_slice($logs, $offset, $per_page);
}
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
                    <select name="date">
                        <?php foreach ($dates as $date): ?>
                            <option value="<?php echo esc_attr($date); ?>" <?php selected($date, $current_date); ?>>
                                <?php echo esc_html($date); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                    <input type="submit" class="button" value="<?php echo esc_attr__('Filter', 'aqm-security'); ?>">
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
                <p><?php echo esc_html__('No visitor logs available for the selected date.', 'aqm-security'); ?></p>
            </div>
        <?php else: ?>
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
                            <td><?php echo esc_html($log['ip']); ?></td>
                            <td>
                                <?php if (!empty($log['flag_url'])): ?>
                                    <img src="<?php echo esc_url($log['flag_url']); ?>" alt="<?php echo esc_attr($log['country']); ?>" 
                                         style="width: 20px; height: auto; vertical-align: middle; margin-right: 5px;">
                                <?php endif; ?>
                                <?php echo esc_html($log['country']); ?>
                            </td>
                            <td><?php echo esc_html($log['region']); ?></td>
                            <td><?php echo esc_html($log['zipcode']); ?></td>
                            <td>
                                <?php if ($log['allowed']): ?>
                                    <span class="dashicons dashicons-yes-alt" style="color: green;" title="<?php echo esc_attr__('Allowed', 'aqm-security'); ?>"></span>
                                    <span style="color: green; font-weight: bold;"><?php echo esc_html__('Allowed', 'aqm-security'); ?></span>
                                <?php else: ?>
                                    <span class="dashicons dashicons-dismiss" style="color: red;" title="<?php echo esc_attr__('Blocked', 'aqm-security'); ?>"></span>
                                    <span style="color: red; font-weight: bold;"><?php echo esc_html__('Blocked', 'aqm-security'); ?></span>
                                <?php endif; ?>
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
                            echo paginate_links(array(
                                'base' => add_query_arg('paged', '%#%'),
                                'format' => '',
                                'prev_text' => __('&laquo;'),
                                'next_text' => __('&raquo;'),
                                'total' => $total_pages,
                                'current' => $current_page
                            ));
                            ?>
                        </span>
                    </div>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    <?php endif; ?>
</div>
