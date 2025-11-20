# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-11-20

### Added
- Comprehensive configuration system with 20+ options matching Scrubber JavaScript
- Support for custom elements via ADD_TAGS configuration
- URI safe attribute support via ADD_URI_SAFE_ATTR
- Data URI handling via ALLOW_DATA_URI option
- RETURN_DOM and RETURN_DOM_FRAGMENT support for Nokogiri documents
- Enhanced security features including namespace attack prevention
- CSS-based attack detection in style attributes
- DOM clobbering protection for dangerous id values
- Comprehensive test suite with 1000+ lines covering XSS vectors and edge cases
- Performance benchmarking suite

### Fixed
- **Major**: Config.apply_config method - fixed key conversion from UPPER_CASE to snake_case
- **Major**: Attribute validation logic - reordered checks and added data URI handling
- **Major**: State retention issue - configuration now persists correctly between calls
- **Major**: Document vs Fragment handling - RETURN_DOM vs RETURN_DOM_FRAGMENT return correct types
- **Critical**: ALLOWED_TAGS, FORBIDDEN_TAGS, ALLOWED_ATTR, FORBIDDEN_ATTR configurations
- **Critical**: ADD_TAGS, ADD_ATTR configurations for custom elements and attributes
- **Security**: Enhanced dangerous value detection with proper data URI support
- **Security**: Fixed URL decoding and namespace attack prevention
- **Security**: Improved CSS injection detection in style attributes
- **Performance**: Optimized configuration switching and memory usage

### Changed
- Improved error handling for invalid configurations
- Enhanced HTML entity encoding support
- Better SVG profile handling with proper attribute preservation
- More robust HTML parsing with fragment support

### Security
- Fixed multiple XSS bypass vectors in script and event handler handling
- Enhanced protection against CSS-based attacks
- Improved attribute validation for dangerous protocols
- Added protection against namespace-based attacks
- Enhanced DOM clobbering attack prevention

## [0.1.0] - 2025-11-19

### Added
- Initial Ruby implementation of Scrubber
- Basic HTML sanitization functionality
- Nokogiri-based HTML parsing and manipulation
- Core XSS protection features
- Basic configuration support

### Security
- Initial XSS protection for common attack vectors
- Script tag removal
- Event handler sanitization
- Basic attribute filtering