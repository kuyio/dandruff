## [Unreleased]

## [0.9.0] - 2026-11-26

### Security
- `<style>` elements now go through the normal element/attribute pipeline. Previously they skipped
  `sanitize_element`, so event handlers on `<style>` (e.g. `<div><style onload=...>`) survived with the default
  config and anywhere in the `html_email` profile. Also, `forbidden_tags`/`allowed_tags`, hooks and the
  SVG/MathML mXSS check never applied to `<style>`.
- `<style>` content is now sanitized (it was passed through unchanged even though the docs said otherwise):
  `@import` rules, `expression()`, `behavior`/`-moz-binding`, `javascript:`/`vbscript:` and `url()`/`src()`/
  `image-set()` URLs that fail the URI rules are removed per declaration/rule, after decoding CSS escapes and
  ignoring comments. The rest of the stylesheet is kept.
- Disallowed elements whose children were hoisted (`keep_content`) are now always removed. Before, the emptied
  element stayed in the output with unchecked attributes whenever only a single pass ran
  (`mutation_max_passes`/`pass_limit` = 1 or `sanitize_until_stable = false`).
- `upon_sanitize_attribute` hooks: `data[:keep_attr]` and changes to `data[:value]` are now honoured. Rewritten
  values are validated, and `keep_attr = true` never keeps `on*` handlers, `forbidden_attributes` or values that
  fail URI/style checks.
- `srcset` is validated per candidate URL (including `allowed_uri_regexp`) instead of as a single URI.
- `IS_ALLOWED_URI` now matches DOMPurify: it adds `cid:`, `ftps:`, `sms:`, `callto:`, `xmpp:` and `matrix:`,
  fixes an unescaped `-` that created the character range `.-:` (so relative URLs such as `images/logo.png` or
  `img2.png` were rejected), and anchors with `\A`/`\z` instead of line anchors.

### Added
- `allow_remote_style_urls` (default `true`): set to `false` to remove remote (`http(s)`, `ftp(s)`, `//host`) CSS URLs
  from `<style>` content and `style` attributes, e.g. to block tracking or CSS data exfiltration in HTML email.

### Changed
- `<style>` is only kept where the tag rules allow it: the `html` profile (whose allowlist has no `style`) and
  explicit `allowed_tags` lists without `style` now remove `<style>`. `html_email` and the default config still keep it.
- `<style>` inside SVG/MathML is now removed, like `<title>` and `<mglyph>` (stricter than DOMPurify).
- Options passed as a hash now apply `use_profiles` first, whatever the key order. Previously
  `Dandruff.sanitize(html, forbidden_tags: ['b'], use_profiles: { html_email: true })` dropped `forbidden_tags`.
- `html`/`head`/`body` are implicitly allowed when parsing whole documents (`whole_document`, `return_dom`,
  `allow_document_elements`), as with DOMPurify's `WHOLE_DOCUMENT`.
- Removed the unused `sanitize_style_value`/`unsafe_style_block?` private methods.

### Fixed
- `html_email` (or any whole-document mode) combined with an `allowed_tags` list lacking `html`/`body` no longer
  raises `ArgumentError: A document may not have multiple root nodes`.
- A value written by a hook directly to the attribute node is no longer reverted, and assigning a frozen string to
  `data[:value]` no longer raises.
- README: corrected the hook example (it raised `NoMethodError`), replaced the non-existent `scrub_until_stable`
  option with `sanitize_until_stable`, and stopped recommending a single pass for performance.

## [0.8.1] - 2025-11-27

### Fixed
- Fixed empty string handling with `return_dom: true` and `return_dom_fragment: true` configurations to return proper Nokogiri document objects instead of empty strings.

## [0.8.0] - 2025-11-24

### Changed
- **BREAKING**: Renamed library from `scrubber` to `dandruff`.
- **BREAKING**: Renamed main module from `Scrubber` to `Dandruff`.
- **BREAKING**: Renamed all files and directories to match new namespace.
- Added `Dandruff.scrub` alias for `Dandruff.sanitize`.
- Full YARD documentation
- Expanded README with more examples and documentation

## [0.7.0] - 2025-11-23

### Fixed
- Removed duplicate `describe 'namespace configuration'` block, reducing example count to 414.
- Excluded `spec/fixtures/examples.rb` from RuboCop to avoid infinite loops.
- Fixed unused method argument in `valid_uri_attribute?`.
- Added `MATH_SVG_TAGS` constant and used safe navigation.
- Disabled cyclomatic complexity and perceived complexity metrics for several methods.
- Updated RSpec example titles for uniqueness.
- Re-enabled RSpec/RepeatedExample cop after fixing duplicates.
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
- Dandruff now uses instance-based configuration (`Dandruff.new(config)`) instead of module-level global state; the module-level `Dandruff.sanitize` is a convenience wrapper that builds a fresh instance per call.
- `use_profiles=` now resets and reapplies profile-derived config, fixing block-style configuration for `html_email` (preserves document elements/attributes even with `return_dom`).
- HTML email profile now forces full-document parsing and preserves legacy margin attributes and backgrounds on row/table elements to improve email fidelity.

## [0.4.0] - 2025-11-20

### Added
- Initial public release of Scrubber
