# AQM Security Plugin Changelog

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
