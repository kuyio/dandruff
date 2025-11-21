## [Unreleased]

## [0.6.0] - 2025-11-22

### Fixed
- Refined CSS validation to allow safe CSS (behavior:, binding:, data:image/svg+xml) while blocking dangerous patterns.
- Updated HTML email profile: enabled style tags, preserved document elements, disabled DOM clobbering, allowed data attributes.
- Fixed namespace handling: preserve text content when removing unknown namespaces.
- Updated SVG attribute handling: safe handling of filter, data URIs, feImage.
- Updated configuration handling: added explicit allow_data_attributes flag for strict attribute lists.
- Updated tests to reflect new behavior.

## [0.5.0] - 2025-11-21

### Added
- Specs covering metadata tag stripping, data/file URI enforcement, obfuscated CSS payloads, expanded DOM clobbering identifiers, attribute hook execution, SVG/MathML hardening, mutation-XSS stabilization, and DOM clobbering canonical parity.
- Canonical DOM clobbering denylist test to track parity with DOMPurify.
- Performance section in README with benchmark stats from local Apple M1 Max runs.
- `html_email` profile to support safe rendering of HTML emails (allows `head`, `meta`, `style` tags and email-specific attributes while stripping scripts and forms).
- **Per-tag attribute control** via `allowed_attributes_per_tag` configuration option, enabling fine-grained attribute allow lists per HTML tag (e.g., allow `href` only on `<a>` tags). Includes comprehensive documentation and test coverage.
- **Optimized `html_email` profile** to use per-tag attribute restrictions instead of global attribute allowlisting, improving security by preventing attribute confusion attacks while maintaining full email compatibility.
- Hook-based per-tag attribute control documentation showing how to use `upon_sanitize_attribute` hook for custom per-tag validation logic.
- Additional HTML email profile regression specs to preserve `<html lang>`, head/meta/style content, legacy body margins/padding, table layout attributes, and enforced `alt` on `<img>` while stripping dangerous handlers/URIs.

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
- Scrubber now uses instance-based configuration (`Scrubber.new(config)`) instead of module-level global state; the module-level `Scrubber.sanitize` is a convenience wrapper that builds a fresh instance per call.
- `use_profiles=` now resets and reapplies profile-derived config, fixing block-style configuration for `html_email` (preserves document elements/attributes even with `return_dom`).
- HTML email profile now forces full-document parsing and preserves legacy margin attributes and backgrounds on row/table elements to improve email fidelity.

## [Unreleased]

## [0.4.0] - 2025-11-20

### Added
- Initial release of Scrubber
