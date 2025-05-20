/**
 * Admin JavaScript for AQM Security
 */
(function($) {
    'use strict';

    $(document).ready(function() {
        // Handle API key test
        $('#aqm_security_test_api').on('click', function(e) {
            e.preventDefault();
            
            var $button = $(this);
            var $resultDiv = $('#aqm_security_api_test_result');
            var apiKey = $('#aqm_security_api_key').val();
            
            // Check if API key is empty
            if (!apiKey) {
                $resultDiv.removeClass('success').addClass('error')
                    .html('Please enter an API key first.');
                return;
            }
            
            // Disable button and show loading
            $button.prop('disabled', true).text('Testing...');
            $resultDiv.html('Testing API connection...').removeClass('success error');
            
            // Make AJAX request
            $.ajax({
                url: aqmSecurityAdmin.ajaxurl,
                type: 'POST',
                data: {
                    action: 'aqm_security_test_api',
                    nonce: aqmSecurityAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        var data = response.data.data;
                        
                        // Build result HTML - displaying the complete response
                        var html = '<strong>' + response.data.message + '</strong><br>';
                        html += '<pre style="max-height: 300px; overflow: auto; padding: 10px; background: #f5f5f5; margin-top: 10px; border: 1px solid #ddd; border-radius: 4px;">';
                        html += JSON.stringify(data, null, 2);
                        html += '</pre>';
                        
                        $resultDiv.removeClass('error').addClass('success').html(html);
                    } else {
                        $resultDiv.removeClass('success').addClass('error')
                            .html('<strong>Error:</strong> ' + response.data.message);
                    }
                },
                error: function(xhr, status, error) {
                    $resultDiv.removeClass('success').addClass('error')
                        .html('<strong>Error:</strong> Failed to connect to server.');
                },
                complete: function() {
                    // Re-enable button
                    $button.prop('disabled', false).text('Test API');
                }
            });
        });
        
        // Handle clearing visitor cache
        $('#aqm_security_clear_cache').on('click', function(e) {
            e.preventDefault();
            
            if (!confirm(aqmSecurityAdmin.confirmClearCache)) {
                return;
            }
            
            var $button = $(this);
            var $result = $('#aqm_security_cache_result');
            var originalText = $button.html();
            
            // Disable button and show loading
            $button.prop('disabled', true);
            $button.html('<span class="dashicons dashicons-update dashicons-spin" style="vertical-align: text-bottom;"></span> Clearing...');
            
            // Make AJAX request
            $.ajax({
                url: aqmSecurityAdmin.ajaxurl,
                type: 'POST',
                data: {
                    action: 'aqm_security_clear_cache',
                    nonce: aqmSecurityAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        $result.html('<span class="success" style="color:green;"><strong>' + response.data.message + '</strong></span>');
                        
                        // Reset button after 3 seconds
                        setTimeout(function() {
                            $result.fadeOut(500, function() {
                                $result.html('').show();
                            });
                        }, 3000);
                    } else {
                        $result.html('<span class="error" style="color:red;"><strong>Error: </strong>' + response.data.message + '</span>');
                    }
                },
                error: function() {
                    $result.html('<span class="error" style="color:red;"><strong>Error: </strong>Failed to connect to server.</span>');
                },
                complete: function() {
                    // Re-enable button and restore original text
                    $button.prop('disabled', false);
                    $button.html(originalText);
                }
            });
        });
        
        // Handle clearing debug log files
        $('#aqm_security_clear_logs').on('click', function(e) {
            e.preventDefault();
            
            var $button = $(this);
            
            // Disable button and show loading
            $button.prop('disabled', true).text('Clearing...');
            
            // Make AJAX request
            $.ajax({
                url: aqmSecurityAdmin.ajaxurl,
                type: 'POST',
                data: {
                    action: 'aqm_security_clear_logs',
                    nonce: aqmSecurityAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        $button.text('Log Cleared!');
                        
                        setTimeout(function() {
                            $button.text('Clear Debug Log');
                            $button.prop('disabled', false);
                        }, 2000);
                    } else {
                        $button.text('Error!');
                        setTimeout(function() {
                            $button.text('Clear Debug Log');
                            $button.prop('disabled', false);
                        }, 2000);
                    }
                },
                error: function() {
                    $button.text('Error!');
                    setTimeout(function() {
                        $button.text('Clear Debug Log');
                        $button.prop('disabled', false);
                    }, 2000);
                }
            });
        });
        
        // Handle clearing visitor logs for a specific date
        $('#aqm_security_clear_visitor_logs').on('click', function(e) {
            e.preventDefault();
            
            if (!confirm(aqmSecurityAdmin.confirmClearLogs)) {
                return;
            }
            
            var $button = $(this);
            var date = $button.data('date') || '';
            var nonce = $button.data('nonce') || aqmSecurityAdmin.nonce;
            
            // Disable button and show loading
            $button.prop('disabled', true).text('Clearing...');
            
            // Make AJAX request
            $.ajax({
                url: aqmSecurityAdmin.ajaxurl,
                type: 'POST',
                data: {
                    action: 'aqm_security_clear_visitor_logs',
                    nonce: nonce,
                    date: date
                },
                success: function(response) {
                    if (response.success) {
                        alert(response.data.message);
                        // Reload the page to show updated logs
                        window.location.reload();
                    } else {
                        alert(response.data.message);
                        $button.prop('disabled', false).text('Clear Logs');
                    }
                },
                error: function() {
                    alert('Failed to connect to server.');
                    $button.prop('disabled', false).text('Clear Logs');
                }
            });
        });
        
        // Handle clearing ALL visitor logs
        $('#aqm_security_clear_all_visitor_logs').on('click', function(e) {
            e.preventDefault();
            console.log('Clear All Logs button clicked');
            
            if (!confirm(aqmSecurityAdmin.confirmClearAllLogs)) {
                return;
            }
            
            var $button = $(this);
            var nonce = $button.data('nonce') || aqmSecurityAdmin.nonce;
            
            console.log('Clearing all logs with nonce:', nonce);
            
            // Disable button and show loading
            $button.prop('disabled', true).text('Clearing All Logs...');
            
            // Make AJAX request to the dedicated endpoint for clearing all logs
            $.ajax({
                url: aqmSecurityAdmin.ajaxurl,
                type: 'POST',
                data: {
                    action: 'aqm_security_clear_all_visitor_logs',
                    nonce: nonce
                },
                success: function(response) {
                    console.log('Clear all logs response:', response);
                    if (response.success) {
                        alert(response.data.message);
                        // Reload the page to show updated logs
                        window.location.reload();
                    } else {
                        alert(response.data.message);
                        $button.prop('disabled', false).text('Clear All Logs');
                    }
                },
                error: function(xhr, status, error) {
                    console.error('AJAX error:', status, error);
                    console.log('Response text:', xhr.responseText);
                    alert('Failed to connect to server.');
                    $button.prop('disabled', false).text('Clear All Logs');
                }
            });
        });
        // Auto-submit form when date selector changes on the logs page
        $('#date-selector').on('change', function() {
            $(this).closest('form').submit();
        });
        
        // Handle running form tests
        $('#aqm_run_form_tests').on('click', function(e) {
            e.preventDefault();
            
            var $button = $(this);
            var $spinner = $button.next('.spinner');
            var $results = $('#aqm_form_test_results');
            
            // Disable button and show spinner
            $button.prop('disabled', true);
            $spinner.addClass('is-active');
            
            // Make AJAX request
            $.ajax({
                url: aqmSecurityAdmin.ajaxurl,
                type: 'POST',
                data: {
                    action: 'aqm_security_run_form_tests',
                    nonce: aqmSecurityAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        var data = response.data;
                        var resultsHtml = '';
                        
                        // Add overall status message
                        resultsHtml += '<div class="notice notice-' + (data.status === 'success' ? 'success' : 'error') + ' inline"><p><strong>' + data.message + '</strong></p></div>';
                        
                        // Add detailed messages
                        if (data.messages && data.messages.length) {
                            resultsHtml += '<ul class="test-results-list">';
                            for (var i = 0; i < data.messages.length; i++) {
                                var msg = data.messages[i];
                                resultsHtml += '<li class="' + msg.status + '">' + msg.message + '</li>';
                            }
                            resultsHtml += '</ul>';
                        }
                        
                        // Add detailed test information
                        if (data.details) {
                            resultsHtml += '<h4>Test Details</h4>';
                            resultsHtml += '<table class="widefat" style="margin-top: 10px;">';
                            resultsHtml += '<thead><tr><th>Location</th><th>Expected</th><th>Actual</th><th>Form Submission</th><th>Result</th></tr></thead><tbody>';
                            
                            for (var state in data.details) {
                                var detail = data.details[state];
                                resultsHtml += '<tr>';
                                resultsHtml += '<td>' + detail.state + '</td>';
                                resultsHtml += '<td>' + detail.should_be + '</td>';
                                resultsHtml += '<td>' + detail.actual + '</td>';
                                resultsHtml += '<td>' + detail.form_submission + '</td>';
                                resultsHtml += '<td><span class="' + (detail.passed ? 'success' : 'error') + '">' + (detail.passed ? 'PASSED' : 'FAILED') + '</span></td>';
                                resultsHtml += '</tr>';
                            }
                            
                            resultsHtml += '</tbody></table>';
                        }
                        
                        // Display results
                        $results.find('.test-content').html(resultsHtml);
                        $results.show();
                    } else {
                        // Error
                        var errorMsg = response.data.message || 'Unknown error';
                        var errorDetails = response.data.details || '';
                        var errorHtml = '<div class="notice notice-error inline"><p><strong>' + errorMsg + '</strong></p>';
                        
                        // Add details if available
                        if (errorDetails) {
                            errorHtml += '<p>Details: ' + errorDetails + '</p>';
                        }
                        
                        errorHtml += '</div>';
                        $results.find('.test-content').html(errorHtml);
                        $results.show();
                    }
                },
                error: function(xhr, status, error) {
                    $results.find('.test-content').html('<div class="notice notice-error inline"><p>Error running tests: ' + error + '</p></div>');
                    $results.show();
                },
                complete: function() {
                    // Re-enable button and hide spinner
                    $button.prop('disabled', false);
                    $spinner.removeClass('is-active');
                }
            });
        });
        
        // Toggle test IP field visibility based on test mode checkbox
        $('#aqm_security_test_mode').on('change', function() {
            var isChecked = $(this).is(':checked');
            $('#aqm_security_auto_test_forms').prop('disabled', !isChecked);
            $('#aqm_run_form_tests').prop('disabled', !isChecked);
            
            if (!isChecked) {
                $('#aqm_security_auto_test_forms').prop('checked', false);
            }
        });
    });
})(jQuery);
