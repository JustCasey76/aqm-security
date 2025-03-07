<?php
/**
 * Provide a admin area view for the plugin settings
 */
?>
<div class="wrap">
    <h1><?php echo esc_html__('AQM Security Settings', 'aqm-security'); ?></h1>
    
    <form method="post" action="options.php">
        <?php
        // Output security fields
        settings_fields('aqm_security_options');
        // Output sections and their fields
        do_settings_sections('aqm-security');
        // Output save settings button
        submit_button();
        ?>
    </form>
</div>
