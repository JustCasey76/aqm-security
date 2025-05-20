# AQM Security

A WordPress plugin that provides geolocation-based security to control access to Formidable Forms.

## Features

- IP-based access control
- Geolocation detection and state-based restrictions
- Form blocking for visitors from restricted locations
- Test mode for easy configuration and testing
- Visitor logging for security analysis
- Support for both IPv4 and IPv6 addresses

## Requirements

- WordPress 5.6 or higher
- PHP 7.3 or higher
- Formidable Forms plugin

## Installation

1. Upload the `aqm-security` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Configure your location restrictions and blocked IPs in the plugin settings

## Changelog

### 2.2.7
- Enhanced security to prevent API-based form submission bypasses
- Added protection for REST API endpoints
- Added protection for admin-ajax.php endpoints
- Added protection against direct database entry creation
- Improved form testing functionality to create actual test entries
- Fixed PHP fatal error in visitor data initialization

### 1.0.1
- Added GitHub-based update functionality
- Improved IP detection for local environments
- Fixed test mode to properly respect blocked IP rules
- Enhanced form blocking to ensure forms are completely hidden

### 1.0.0
- Initial release

## License

This plugin is proprietary software. Unauthorized distribution is prohibited.
