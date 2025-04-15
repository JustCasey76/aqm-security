# AQM Security Plugin Changelog

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
