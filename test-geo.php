<?php
/**
 * Test script for AQM Security geolocation
 * This will help diagnose why the test IP is not working as expected
 */

// Bootstrap WordPress
require_once '../../../wp-load.php';

// Include necessary files
require_once 'includes/class-aqm-security-api.php';
require_once 'includes/class-aqm-security-logger.php';

// Output header
echo '<html><head><title>AQM Security Geolocation Test</title>';
echo '<style>';
echo 'body { font-family: Arial, sans-serif; margin: 2rem; line-height: 1.5; }';
echo '.container { max-width: 900px; margin: 0 auto; }';
echo '.passed { color: green; font-weight: bold; }';
echo '.failed { color: red; font-weight: bold; }';
echo '.section { margin-bottom: 2rem; border: 1px solid #ddd; padding: 1rem; border-radius: 5px; }';
echo '.code { font-family: monospace; background: #f5f5f5; padding: 0.5rem; border-radius: 3px; }';
echo '</style>';
echo '</head><body><div class="container">';
echo '<h1>AQM Security Geolocation Test</h1>';

// Function to display array nicely
function display_array($array, $indent = 0) {
    $result = '';
    foreach ($array as $key => $value) {
        if (is_array($value)) {
            $result .= str_repeat('&nbsp;', $indent * 4) . "$key => <br>";
            $result .= display_array($value, $indent + 1);
        } else {
            $result .= str_repeat('&nbsp;', $indent * 4) . "$key => $value<br>";
        }
    }
    return $result;
}

// Display test mode status
echo '<div class="section">';
echo '<h2>Test Mode Status</h2>';
$test_mode = get_option('aqm_security_test_mode', false) ? 'Enabled' : 'Disabled';
$test_ip = get_option('aqm_security_test_ip', '');
echo "<p>Test Mode: <strong>$test_mode</strong></p>";
echo "<p>Test IP: <strong>$test_ip</strong></p>";
echo '</div>';

// Display geolocation allow lists
echo '<div class="section">';
echo '<h2>Allowed Locations Configuration</h2>';

$allowed_countries = explode("\n", get_option('aqm_security_allowed_countries', ''));
$allowed_countries = array_map('trim', $allowed_countries);
$allowed_countries = array_filter($allowed_countries);

$allowed_states = explode("\n", get_option('aqm_security_allowed_states', ''));
$allowed_states = array_map('trim', $allowed_states);
$allowed_states = array_filter($allowed_states);

$allowed_zip_codes = explode("\n", get_option('aqm_security_allowed_zip_codes', ''));
$allowed_zip_codes = array_map('trim', $allowed_zip_codes);
$allowed_zip_codes = array_filter($allowed_zip_codes);

echo '<h3>Allowed Countries</h3>';
if (empty($allowed_countries)) {
    echo '<p>No countries specified (all countries allowed)</p>';
} else {
    echo '<p>Countries must match one of:</p>';
    echo '<ul>';
    foreach ($allowed_countries as $country) {
        echo "<li><span class='code'>$country</span></li>";
    }
    echo '</ul>';
}

echo '<h3>Allowed States/Regions</h3>';
if (empty($allowed_states)) {
    echo '<p>No states/regions specified (all states/regions allowed)</p>';
} else {
    echo '<p>States must match one of:</p>';
    echo '<ul>';
    foreach ($allowed_states as $state) {
        echo "<li><span class='code'>$state</span></li>";
    }
    echo '</ul>';
}

echo '<h3>Allowed ZIP Codes</h3>';
if (empty($allowed_zip_codes)) {
    echo '<p>No ZIP codes specified (all ZIP codes allowed)</p>';
} else {
    echo '<p>ZIP codes must match one of:</p>';
    echo '<ul>';
    foreach ($allowed_zip_codes as $zip) {
        echo "<li><span class='code'>$zip</span></li>";
    }
    echo '</ul>';
}
echo '</div>';

// Get geolocation data for test IP
echo '<div class="section">';
echo '<h2>Geolocation Test</h2>';

// Force using the test IP
if (!empty($test_ip)) {
    // Override the get_client_ip method temporarily
    function override_get_client_ip() {
        return get_option('aqm_security_test_ip', '');
    }
    
    // Add a filter to override the get_client_ip method
    add_filter('pre_option_aqm_security_test_mode', function() { return true; }, 999);
    
    echo "<p>Testing with IP: <strong>$test_ip</strong></p>";
    
    // Get geolocation data
    $geo_data = AQM_Security_API::get_geolocation_data();
    
    if (is_wp_error($geo_data)) {
        echo '<p class="failed">Error getting geolocation data: ' . $geo_data->get_error_message() . '</p>';
    } else {
        echo '<h3>Geolocation Data</h3>';
        echo '<div class="code">';
        
        // Extract key fields
        $important_fields = [
            'ip' => $geo_data['ip'] ?? 'Unknown',
            'country_code' => $geo_data['country_code'] ?? 'Unknown',
            'country_name' => $geo_data['country_name'] ?? 'Unknown',
            'region_code' => $geo_data['region_code'] ?? 'Unknown',
            'region_name' => $geo_data['region_name'] ?? 'Unknown',
            'city' => $geo_data['city'] ?? 'Unknown',
            'zip' => $geo_data['zip'] ?? 'Unknown',
        ];
        
        echo display_array($important_fields);
        echo '</div>';
        
        // Check if allowed
        $is_allowed = AQM_Security_API::is_visitor_allowed($geo_data);
        
        echo '<h3>Access Check</h3>';
        
        // Country check
        $visitor_country = strtoupper($geo_data['country_code'] ?? '');
        $allowed_countries_upper = array_map('strtoupper', $allowed_countries);
        $country_check = empty($allowed_countries) ? true : in_array($visitor_country, $allowed_countries_upper);
        
        // State check
        $visitor_region = strtoupper($geo_data['region_code'] ?? '');
        $allowed_states_upper = array_map('strtoupper', $allowed_states);
        $state_check = empty($allowed_states) ? true : in_array($visitor_region, $allowed_states_upper);
        
        // ZIP check
        $visitor_zip = $geo_data['zip'] ?? '';
        $zip_check = empty($allowed_zip_codes) ? true : in_array($visitor_zip, $allowed_zip_codes);
        
        echo '<table border="1" cellpadding="5" cellspacing="0" width="100%">';
        echo '<tr><th>Check</th><th>Visitor Value</th><th>Allowed Values</th><th>Result</th></tr>';
        
        // Country row
        echo '<tr>';
        echo '<td>Country</td>';
        echo "<td>{$visitor_country}</td>";
        echo '<td>' . (empty($allowed_countries) ? 'Any (not restricted)' : implode(', ', $allowed_countries_upper)) . '</td>';
        echo '<td class="' . ($country_check ? 'passed' : 'failed') . '">' . ($country_check ? 'PASS' : 'FAIL') . '</td>';
        echo '</tr>';
        
        // State row
        echo '<tr>';
        echo '<td>State/Region</td>';
        echo "<td>{$visitor_region}</td>";
        echo '<td>' . (empty($allowed_states) ? 'Any (not restricted)' : implode(', ', $allowed_states_upper)) . '</td>';
        echo '<td class="' . ($state_check ? 'passed' : 'failed') . '">' . ($state_check ? 'PASS' : 'FAIL') . '</td>';
        echo '</tr>';
        
        // ZIP row
        echo '<tr>';
        echo '<td>ZIP/Postal Code</td>';
        echo "<td>{$visitor_zip}</td>";
        echo '<td>' . (empty($allowed_zip_codes) ? 'Any (not restricted)' : implode(', ', $allowed_zip_codes)) . '</td>';
        echo '<td class="' . ($zip_check ? 'passed' : 'failed') . '">' . ($zip_check ? 'PASS' : 'FAIL') . '</td>';
        echo '</tr>';
        
        // Overall
        echo '<tr>';
        echo '<td colspan="3"><strong>Overall Access</strong> (all checks must pass)</td>';
        echo '<td class="' . ($is_allowed ? 'passed' : 'failed') . '">' . ($is_allowed ? 'ALLOWED' : 'BLOCKED') . '</td>';
        echo '</tr>';
        
        echo '</table>';
        
        echo '<p><strong>Note:</strong> Each check that has restrictions must pass. If all checks are empty, access is allowed by default.</p>';
    }
} else {
    echo '<p class="failed">No test IP configured. Please set a test IP in the plugin settings.</p>';
}

echo '</div>';

// Troubleshooting tips
echo '<div class="section">';
echo '<h2>Troubleshooting Tips</h2>';
echo '<ul>';
echo '<li>Make sure your allowed country codes are in the format "US", not "United States"</li>';
echo '<li>Make sure your allowed state/region codes are in the format "MA", not "Massachusetts"</li>';
echo '<li>Ensure there are no extra spaces or blank lines in your allowed location lists</li>';
echo '<li>If you want to allow all visitors, leave all allowed lists empty</li>';
echo '<li>Check that your test IP is resolving to the correct location</li>';
echo '<li>Remember that a visitor must pass ALL checks that are configured (country AND state AND zip if all are specified)</li>';
echo '</ul>';
echo '</div>';

echo '</div></body></html>';
?>
