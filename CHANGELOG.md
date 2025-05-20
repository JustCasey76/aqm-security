# AQM Security Plugin Changelog

## 2.2.3 - May 20, 2025
- Improved error reporting in form testing feature
- Added detailed error messages to show the specific reason for test failures
- Enhanced JavaScript to display error details in the admin interface
- Fixed structure of the AJAX handler function

## 2.2.2 - May 20, 2025
- Fixed missing render_auto_test_forms_field method
- Resolved PHP error in settings page

## 2.2.1 - May 20, 2025
- Simplified form testing by using the test IP address for location detection
- Removed separate test location dropdown
- Enhanced test IP field with more information about allowed states
- Improved form testing with automatic detection of contrasting test locations

## 2.2.0 - May 20, 2025
- Added enhanced debugging for form testing feature
- Implemented a direct test method as a fallback for form testing
- Improved error handling and logging throughout the testing process
- Added detailed state checking to ensure proper form blocking

## 2.1.9 - May 20, 2025
- Improved error handling in form testing feature
- Added detailed error logging for form tests
- Fixed issue with allowed states not being properly detected in test mode
- Enhanced compatibility with different WordPress configurations

## 2.1.8 - May 20, 2025
- Added automated form testing feature to test form submission blocking
- Added test location selector to simulate visitors from different states
- Fixed handling of allowed states option to ensure it's always treated as an array
- Enhanced test mode with visual feedback for test results

## 2.1.7 - May 20, 2025
- Version bump for testing GitHub Updater functionality

## 2.1.6 - May 20, 2025
- Fixed PHP fatal error: Cannot redeclare AQM_Security_Public::catch_and_replace_forms()
- Removed duplicate method declaration to prevent PHP errors

## 2.1.5 - May 20, 2025
- CRITICAL FIX: Enhanced form submission blocking to prevent form submissions from blocked locations
- Added multiple server-side checks to catch all form submission methods including AJAX
- Added robust validation to prevent form submissions even if the form is visible
- Fixed issue where visitors from blocked locations could still submit forms in some cases

## 2.1.4 - May 20, 2025
- CRITICAL FIX: Fixed issue where geolocation restrictions were incorrectly applied to WordPress admin area
- Added proper admin page exclusion in the check_geolocation method to ensure admins can access the backend regardless of location
- Ensures plugin only restricts access to Formidable Forms on the front-end as intended

## 2.1.3 - May 20, 2025
- Fixed PHP 8.2+ deprecation warnings about dynamic property creation
- Added proper property declarations in AQM_Security and AQM_Security_Public classes
- Fixed undefined variable warnings in AQM_Security_Logger and AQM_Security_API classes
- Improved code quality and compatibility with PHP 8.2+

## 2.1.2 - May 19, 2025
- Maintenance release
- Version number update for WordPress update system compatibility

## 2.1.1 - May 19, 2025
- Enhanced admin bar to always show location and status information for administrators, including in the admin area
- Added admin_head hook to ensure admin bar styles are properly loaded in the WordPress admin dashboard

## 2.1.0 - May 19, 2025
- Implemented personalized location-based blocked messages
- Removed configurable blocked message from settings page
- Enhanced message display with better styling and clarity
- US visitors now see their state name in blocked messages
- International visitors now see their country name in blocked messages

## 2.0.8 - May 16, 2025
- Fixed GitHub updater to properly detect and sort version tags
- Enhanced version comparison logic to handle 'v' prefix in tag names
- Added detailed debug logging for update process

## 2.0.7 - May 16, 2025
- Removed ZIP code filtering functionality as it's no longer needed
- Updated GitHub updater implementation to match other AQM plugins
- Removed old GitHub updater class
- Fixed PHP 8.2+ compatibility issues

## 2.0.6 - April 15, 2025
- Fixed Visitor Logging Throttle dropdown default to 24 hours instead of 15 minutes
- Fixed settings page to properly save all settings
- Standardized settings page and section names for consistency

## 2.0.5 - April 15, 2025
- Fixed issue with Visitor Logging Throttle dropdown not saving settings
- Standardized settings registration to use consistent option group

## 2.0.4 - April 15, 2025
- Removed non-functioning "Clear All Logs" button
- Improved release package by excluding development files
- Fixed additional PHP 8.2+ compatibility issues

## 2.0.3 - April 15, 2025
- Added session-based visitor logging throttle to prevent multiple log entries for the same IP
- Default throttle interval set to 24 hours to reduce database load
- Added admin setting to control the throttle interval
- Fixed PHP 8.2+ deprecation warnings about dynamic property creation
- Improved error handling and debugging for visitor logging

## 2.0.2 - Previous Version
- Updated theme version to 1.0.7
- Removed logo from header
- Various bug fixes and improvements

## 2.0.1 - Initial Release
- Geolocation-based security using ipapi.com
- Control access to Formidable Forms based on location
- Visitor logging and analytics
- Admin interface for managing security rules
