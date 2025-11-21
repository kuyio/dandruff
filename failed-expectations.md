# Root Causes for Scrubber vs DOMPurify Expectation Failures

This document analyzes the root causes of why the Scrubber library produces different outputs compared to the expected DOMPurify behaviors in the test suite.

## Summary

The Scrubber library's default configuration is more restrictive than DOMPurify's in several areas:
- Data URIs are blocked by default
- Certain HTML attributes (e.g., `checked`, `selected`) are not allowed by default
- SVG and MathML attribute handling differs
- DOM clobbering protection is more aggressive
- Some attributes expected to be preserved are removed

## Detailed Root Causes by Failure

### 1. Data URI Handling
**Failures:** Don't remove data URIs from SVG images, Don't remove data URIs from SVG images with href attribute, src Attributes for IMG, AUDIO, VIDEO and SOURCE, Image with data URI src, Image with data URI src with whitespace

**Root Cause:** Scrubber blocks data URIs by default (`allow_data_uri = false`), while DOMPurify allows data URIs for specific attributes on specific tags (img src, audio src, video src, source src, SVG image xlink:href/href). The URI validation regex `IS_ALLOWED_URI` does not include `data:` protocol, and the special case for data URIs requires `allow_data_uri = true` or tag-specific allowances.

**Remediation Recommendation:** Implement via `dompurify` profile to allow data URIs for specific safe tags. Keep default restrictive for security. Security implications: Data URIs can contain embedded scripts or large payloads that could cause performance issues, but restricting to specific tags and validating content types mitigates most risks.

**Code Location:** `lib/scrubber.rb` `valid_attribute?` method, `lib/scrubber/expressions.rb` `IS_ALLOWED_URI`

### 2. ARIA Attributes
**Failures:** Don't remove ARIA attributes if not prohibited

**Root Cause:** Despite `allow_aria_attributes = true` in default config, ARIA attributes are being removed. This may be due to the attribute validation logic not properly applying the permissive checks, or a bug in the order of validation.

**Remediation Recommendation:** Fix the bug in `valid_attribute?` to properly apply `allow_aria_attributes` logic. Alternatively, ensure ARIA attributes are included in the `dompurify` profile's allowed attributes. Keep the default as allowing ARIA attributes since they are essential for accessibility and pose no security risk.

**Code Location:** `lib/scrubber.rb` `valid_attribute?` method, config `allow_aria_attributes`

### 3. Binary Attributes
**Failures:** Don't remove binary attributes if considered safe

**Root Cause:** Attributes like `checked` are not included in the default allowed attributes list. DOMPurify allows these HTML boolean attributes by default, but Scrubber requires them to be explicitly allowed.

**Remediation Recommendation:** Implement via `dompurify` profile by expanding the allowed attributes list to include common HTML boolean attributes. Keep defaults restrictive for security. Security implications: These attributes are safe and commonly used in HTML forms; they don't introduce XSS risks.

**Code Location:** `lib/scrubber/attributes.rb` `HTML` list, `lib/scrubber.rb` `valid_attribute?` default checks

### 4. SVG Filter Elements
**Failures:** Avoid over-zealous stripping of SVG filter elements

**Root Cause:** SVG filter elements and their attributes are not fully supported in the default allowed tags/attributes. The `feGaussianBlur` element and its `in` and `stdDeviation` attributes are being removed.

**Remediation Recommendation:** Relax restrictions by ensuring all SVG filter elements and their standard attributes are included in the default allowed lists. Security implications: SVG filters are generally safe for display purposes and are commonly used in web graphics; they don't execute scripts.

**Code Location:** `lib/scrubber/tags.rb` `SVG_FILTERS`, `lib/scrubber/attributes.rb` `SVG`

### 5. URI-like Attributes
**Failures:** safe usage of URI-like attribute values

**Root Cause:** The `href` attribute is removed when it contains `javascript:`, but `title` is kept. This is correct behavior for security, but the test expects both to be handled differently.

**Remediation Recommendation:** Keep the more restrictive mode for URI attributes like `href` to prevent XSS, while allowing non-URI attributes like `title` to contain URI-like strings. Security implications: This is actually a security feature - blocking `javascript:` in navigation attributes prevents XSS attacks.

**Code Location:** `lib/scrubber.rb` `valid_attribute?` URI validation

### 6. DOM Clobbering Protection
**Failures:** Multiple DOM clobbering related failures (cookie, getElementById, nodeName, etc.)

**Root Cause:** Scrubber's DOM clobbering protection is more aggressive than DOMPurify's. Attributes with names that could shadow DOM properties are removed, even when DOMPurify allows them.

**Remediation Recommendation:** Keep the more restrictive mode for DOM clobbering protection as it provides better security. The `dompurify` profile could optionally disable this for compatibility. Security implications: DOM clobbering can be used to manipulate JavaScript code execution; being more restrictive prevents potential security vulnerabilities at the cost of some compatibility.

**Code Location:** `lib/scrubber.rb` `valid_attribute?` DOM clobbering check, `lib/scrubber/attributes.rb` `DOM_CLOBBERING`

### 7. MathML Handling
**Failures:** MathML example

**Root Cause:** MathML elements and attributes are not properly supported or the serialization differs from DOMPurify's output.

**Remediation Recommendation:** Relax restrictions by improving MathML support to match DOMPurify's handling. Security implications: MathML is generally safe for mathematical content display and doesn't execute scripts; better support improves compatibility without significant security risks.

**Code Location:** `lib/scrubber/tags.rb` `MATH_ML`, `lib/scrubber/attributes.rb` `MATH_ML`

### 8. Template and Shadow DOM
**Failures:** Img element inside shadow DOM template

**Root Cause:** Template elements and their contents are not handled the same way as DOMPurify.

**Remediation Recommendation:** Keep the more restrictive mode for template elements as they can contain executable content. Security implications: Template elements can be used to inject scripts that execute when the template is instantiated; being restrictive prevents potential XSS through template injection.

**Code Location:** `lib/scrubber.rb` `sanitize_document` forbidden tags

### 9. Style Attributes
**Failures:** Multiple style-related failures (p[foo=bar], @import, etc.)

**Root Cause:** CSS sanitization is more restrictive, removing valid CSS that DOMPurify allows.

**Remediation Recommendation:** Partially relax restrictions for safe CSS properties while keeping restrictions on dangerous ones like `@import` with external URLs. Security implications: CSS can be used for XSS (e.g., `expression()` in IE, `url()` with javascript), so selective relaxation is needed to balance security and functionality.

**Code Location:** `lib/scrubber.rb` `sanitize_style_value`, `unsafe_inline_style?`

### 10. Form and Input Handling
**Failures:** Various form and input attribute failures (type, method, etc.)

**Root Cause:** Form-related attributes are not all allowed by default.

**Remediation Recommendation:** Relax restrictions by adding common form attributes to the default allowed list. Security implications: Form attributes are generally safe and necessary for HTML forms; they don't introduce XSS risks when properly validated.

**Code Location:** `lib/scrubber/attributes.rb` `HTML`

### 11. SVG and XML Namespaces
**Failures:** SVG namespace handling

**Root Cause:** XML namespace attributes and SVG-specific handling differs.

**Remediation Recommendation:** Relax restrictions to properly support SVG namespaces. Security implications: Namespaces are metadata and don't execute code; proper support improves SVG compatibility without security risks.

**Code Location:** `lib/scrubber.rb` `sanitize_element` namespace check

### 12. Comment and Script Handling
**Failures:** Noscript content handling

**Root Cause:** Comment and script content sanitization differs.

**Remediation Recommendation:** Keep the more restrictive mode for comments and scripts. Security implications: Comments can contain sensitive information, and scripts are inherently dangerous; removing them prevents information leakage and script injection.

**Code Location:** `lib/scrubber.rb` `sanitize_comment_node`

### 13. CDATA and Special Content
**Failures:** SVG with CDATA

**Root Cause:** CDATA sections and special HTML constructs are handled differently.

**Remediation Recommendation:** Adjust serialization to match DOMPurify's handling of CDATA and special content. Security implications: CDATA sections can contain script-like content, so careful validation is needed, but matching DOMPurify's behavior improves compatibility.

**Code Location:** `lib/scrubber.rb` `serialize_html`

### 14. Attribute Value Sanitization
**Failures:** Various attribute value transformations

**Root Cause:** Attribute value processing (encoding, decoding, validation) differs from DOMPurify.

**Remediation Recommendation:** Adjust value processing to match DOMPurify's behavior while maintaining security. Security implications: Proper value sanitization prevents XSS through attribute injection; changes should preserve security guarantees.

**Code Location:** `lib/scrubber.rb` `valid_attribute?` value processing

### 15. Element Content Preservation
**Failures:** Content preservation in certain elements

**Root Cause:** The `keep_content` logic differs for certain forbidden elements.

**Remediation Recommendation:** Keep the more restrictive mode for content preservation. Security implications: Preserving content from forbidden elements can lead to information leakage or script execution; being restrictive prevents these issues.

**Code Location:** `lib/scrubber.rb` `sanitize_element`

## Alternative Solution: DOMPurify Profile

Most of these discrepancies could be addressed by adding a `dompurify` profile that configures Scrubber to match DOMPurify's more permissive behavior. This would allow users to opt into DOMPurify-compatible sanitization while maintaining Scrubber's secure defaults.

### Profile Implementation

Add a `dompurify` profile to `process_profiles` in `lib/scrubber/config.rb`:

```ruby
if @use_profiles[:dompurify]
  @allowed_tags += Tags::HTML + Tags::SVG + Tags::SVG_FILTERS + Tags::MATH_ML
  @allowed_attributes += Attributes::HTML + Attributes::SVG + Attributes::MATH_ML + Attributes::XML
  @allow_data_uri = true  # Allow data URIs for compatible tags
  @allow_unknown_protocols = true  # More permissive protocol handling
  @sanitize_dom = false  # Less aggressive DOM clobbering protection
  @allow_style_tags = true  # Allow style tags
  # Add more permissive settings as needed
end
```

### Usage

```ruby
Scrubber.new(dompurify: true).sanitize(html)
# or
Scrubber.new(use_profiles: { dompurify: true }).sanitize(html)
```

### Benefits

- **Maintains Security by Default:** Keeps Scrubber's restrictive defaults for security-conscious users
- **Provides Compatibility:** Offers DOMPurify-like behavior when needed
- **Selective Relaxation:** Only relaxes restrictions where DOMPurify differs, maintaining security where possible
- **Backward Compatible:** Doesn't break existing code

### Security Considerations

The `dompurify` profile would be less secure than Scrubber's defaults but more compatible with DOMPurify. Users should understand the trade-offs when enabling this profile.

### Implementation Priority

Most root causes (1-4, 7, 9-11, 13-14) could be addressed through the `dompurify` profile, while security-critical areas (5-6, 8, 12, 15) should remain restrictive by default with optional relaxation in the profile.