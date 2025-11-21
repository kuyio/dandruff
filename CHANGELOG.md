# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Specs covering metadata tag stripping, data/file URI enforcement, obfuscated CSS payloads, expanded DOM clobbering identifiers, attribute hook execution, SVG/MathML hardening, mutation-XSS stabilization, and DOM clobbering canonical parity.
- Canonical DOM clobbering denylist test to track parity with DOMPurify.
- Performance section in README with benchmark stats from local Apple M1 Max runs.

### Changed
- Default forbidden tags now include `base`, `link`, `meta`, and `style`; removed these from the default allowlist to mirror DOMPurify defaults.
- Tightened URI allowlist to http/https/mailto/ftp/tel or relative; `data:`/`file:` are blocked unless explicitly allowed via `allow_data_uri`.
- Media/link data URIs now honor `allow_data_uri` across tags; inline styles are scanned for escaped/scripted payloads and stripped when unsafe.
- Broadened DOM clobbering protection and now invoke `upon_sanitize_attribute` hooks during attribute processing.
- Optional `allow_style_tags` opt-in drops entire style blocks on detection of dangerous patterns; default remains to deny `<style>`.
- Added optional mutation-XSS stability pass (`sanitize_until_stable` with `mutation_max_passes`) to re-sanitize until output stabilizes and reduce mXSS risk.
- Expanded URI-safe recognition to SVG `filter` attributes and extended DOM-clobbering denylist; added SVG filter/data-URI and extra clobbering specs.
- Added SVG animateMotion/feImage data-URI blocking tests to harden remaining SVG vectors.
- Annotation-XML now forbidden by default; added MathML coverage/tests for maction/annotation-xml and malicious MathML URIs.
- Added mutation XSS stability test and baseProfile SVG trap coverage.
- Inline style filtering hardened to catch behavior/binding directives and data SVG URLs; style opt-in drops blocks containing these payloads.
- `sanitize_until_stable` defaults to 2 passes (bounded), with `pass_limit` to disable or increase passes.
- Removed `return_trusted_type` flag to avoid implying browser Trusted Types; always return String unless `return_dom`/`return_dom_fragment`.
- Added `minimal_profile` option to use an HTML-only allowlist (SVG/MathML off by default when enabled) and drop document wrappers unless explicitly allowed.
- CSS tests expanded for nested/escaped `@import`; URI parsing tightened to reject leading whitespace/control characters.
- Inline styles now parsed into allowed declarations with protocol checks; unsafe values drop the entire attribute.

## [0.4.0] - 2025-11-20

### Added
- Initial release of Scrubber
