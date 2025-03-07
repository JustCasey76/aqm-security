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
        
        // Handle clearing visitor logs
        $('#aqm_security_clear_visitor_logs').on('click', function(e) {
            e.preventDefault();
            
            if (!confirm(aqmSecurityAdmin.confirmClearLogs)) {
                return;
            }
            
            var $button = $(this);
            var date = $button.data('date') || '';
            
            // Disable button and show loading
            $button.prop('disabled', true).text('Clearing...');
            
            // Make AJAX request
            $.ajax({
                url: aqmSecurityAdmin.ajaxurl,
                type: 'POST',
                data: {
                    action: 'aqm_security_clear_visitor_logs',
                    nonce: aqmSecurityAdmin.nonce,
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
        
        // Auto-submit form when date selector changes on the logs page
        $('#date-selector').on('change', function() {
            $(this).closest('form').submit();
        });
    });

})(jQuery);
