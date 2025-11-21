# Scrubber

[![Gem Version](https://badge.fury.io/rb/scrubber.svg)](https://badge.fury.io/rb/scrubber)
[![Build Status](https://github.com/kuyio/scrubber/workflows/CI/badge.svg)](https://github.com/kuyio/scrubber/actions)

A robust Ruby HTML sanitizer providing comprehensive XSS protection with an idiomatic, developer-friendly API. Built on the battle-tested security foundations of [DOMPurify](https://github.com/cure53/DOMPurify).

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [Basic Configuration](#basic-configuration)
  - [Tag Control](#tag-control)
  - [Attribute Control](#attribute-control)
  - [URI & Protocol Control](#uri--protocol-control)
  - [Output Control](#output-control)
  - [Content Control](#content-control)
  - [Special Features](#special-features)
- [Advanced Features](#advanced-features)
  - [Profiles](#profiles)
  - [Hooks](#hooks)
- [Security](#security)
  - [Recommended Configurations](#recommended-configurations)
  - [Security Best Practices](#security-best-practices)
- [API Reference](#api-reference)
- [Performance](#performance)
- [Migration Guide](#migration-guide)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'scrubber'
```

And then execute:

```bash
$ bundle install
```

Or install it yourself:

```bash
$ gem install scrubber
```

## Quick Start

```ruby
require 'scrubber'

# Basic sanitization - removes XSS attacks
dirty_html = '<script>alert("xss")</script><p>Safe content</p>'
clean_html = Scrubber.sanitize(dirty_html)
# => "<p>Safe content</p>"

# Configure for your use case
Scrubber.configure do |config|
  config.allowed_attributes = ['p', 'strong', 'em', 'a']
  config.allowed_attributes = ['href', 'title', 'class']
end

# Now sanitize with your custom rules
html = '<p class="intro"><strong>Important:</strong> <a href="/about">Learn more</a></p>'
clean = Scrubber.sanitize(html)
# => '<p class="intro"><strong>Important:</strong> <a href="/about">Learn more</a></p>'
```

## Configuration

Scrubber offers flexible configuration through a block-based API or direct method calls. All configuration options use `snake_case` naming for Ruby idiomatics.

### Basic Configuration

```ruby
# Block-based configuration (recommended)
Scrubber.configure do |config|
  config.allowed_tags = ['p', 'strong', 'em']
  config.allowed_attributes = ['class', 'href']
end

# Direct configuration
Scrubber.set_config(
  allowed_tags: ['p', 'strong', 'em'],
  allowed_attributes: ['class', 'href']
)

# Per-call configuration
clean = Scrubber.sanitize(dirty_html,
  allowed_tags: ['p', 'strong'],
  allowed_attributes: ['class']
)
```

### Profiles

Use predefined profiles for common content types:

```ruby
# HTML content
Scrubber.set_config(use_profiles: { html: true })

# SVG support
Scrubber.set_config(use_profiles: { svg: true })

# MathML for mathematical content
Scrubber.set_config(use_profiles: { math_ml: true })

# Multiple profiles
Scrubber.set_config(use_profiles: { html: true, svg: true })

# SVG filters
Scrubber.set_config(use_profiles: { svg_filters: true })

# HTML Email support (allows head, meta, style, etc.)
Scrubber.set_config(use_profiles: { html_email: true })
```

### Controlling which HTML Tags are allowed

Scrubber given you fine-grained control over which HTML tags are allowed in sanitized output. You can you use the following config options to allow or deny specific tags.

#### `allowed_tags`
**Type:** `Array<String>` | **Default:** Comprehensive list of safe HTML tags (see default allow lists below)

Specify exactly which tags to allow. When set, **only these tags** will be permitted:

```ruby
Scrubber.configure do |config|
  config.allowed_tags = ['p', 'strong', 'em', 'a', 'ul', 'li']
  # Only these 6 tags will be allowed
end
```

#### `forbidden_tags`
**Type:** `Array<String>` | **Default:** `[]`

Tags that are always removed, even if in `allowed_tags`:

```ruby
Scrubber.configure do |config|
  config.forbidden_tags = ['script', 'iframe', 'object']
end
```

#### `additional_tags`
**Type:** `Array<String>` | **Default:** `[]`

Additional tags to allow **beyond the defaults**. Use this to extend the default safe tag list:

```ruby
Scrubber.configure do |config|
  config.additional_tags = ['custom-element', 'web-component']
  # Allows all default tags PLUS these custom ones
end
```
---

### Controlling which Attributes are allowed

In addition to controlling the allowed set of HTML attributes, Scrubber also let's you specify which attributes are allowed in those tags.

#### `allowed_attributes`
**Type:** `Array<String>` | **Default:** Safe attributes like `href`, `title`, `class`

Specify exactly which attributes to allow. When set, **only these attributes** will be permitted:

```ruby
Scrubber.configure do |config|
  config.allowed_attributes = ['href', 'title', 'class', 'id']
  # Only these 4 attributes will be allowed on any tag
end
```

#### `forbidden_attributes`
**Type:** `Array<String>` | **Default:** `[]`

Attributes that are always removed:

```ruby
Scrubber.configure do |config|
  config.forbidden_attributes = ['onclick', 'onerror', 'onload']
end
```

#### `additional_attributes`
**Type:** `Array<String>` | **Default:** `[]`

Additional attributes to allow **beyond the defaults**. Use this to extend the default safe attribute list:

```ruby
Scrubber.configure do |config|
  config.additional_attributes = ['data-toggle', 'aria-label']
  # Allows all default attributes PLUS these custom ones
end
```

#### `additional_uri_safe_attributes`
**Type:** `Array<String>` | **Default:** `[]`

Attributes that can contain URIs and should be validated:

```ruby
Scrubber.configure do |config|
  config.additional_uri_safe_attributes = ['poster', 'srcset']
end
```

#### `allowed_attributes_per_tag`
**Type:** `Hash<String, Array<String>>` | **Default:** `nil`

Specify which attributes are allowed on specific HTML tags. This provides fine-grained control beyond global attribute allow/deny lists. When configured, per-tag rules take precedence over global `allowed_attributes` for the specified tags.

**Format:** `{ 'tag_name' => ['attr1', 'attr2', ...] }`

```ruby
Scrubber.configure do |config|
  config.allowed_attributes_per_tag = {
    'a' => ['href', 'title', 'target'],
    'img' => ['src', 'alt', 'width', 'height'],
    'td' => ['colspan', 'rowspan'],
    'th' => ['colspan', 'rowspan', 'scope']
  }
end

# Now only specified attributes are allowed on each tag
html = '<a href="/page" onclick="alert()">Link</a>'
Scrubber.sanitize(html)
# => '<a href="/page">Link</a>' (onclick removed, href kept)

html = '<img src="pic.jpg" href="/bad">'
Scrubber.sanitize(html)
# => '<img src="pic.jpg">' (href removed from img tag)
```

**Security use case:**

```ruby
# Restrict link targets and prevent attribute confusion attacks
Scrubber.configure do |config|
  config.allowed_attributes_per_tag = {
    'a' => ['href', 'title'],           # No target attribute
    'img' => ['src', 'alt'],            # No href on images
    'form' => ['action', 'method'],     # Only form-specific attrs
    'input' => ['type', 'name', 'value'] # No onclick, etc.
  }
end
```

**Interaction with global settings:**
- `forbidden_attributes` always takes precedence (attributes are removed even if in per-tag list)
- If a tag has per-tag rules, those rules are used instead of `allowed_attributes` for that tag
- Tags without per-tag rules fall back to global `allowed_attributes` behavior
- `additional_attributes` is ignored for tags with per-tag rules

```ruby
Scrubber.configure do |config|
  config.allowed_attributes_per_tag = {
    'a' => ['href', 'onclick']  # onclick specified here
  }
  config.forbidden_attributes = ['onclick']  # But forbidden globally
end

html = '<a href="/page" onclick="alert()">Link</a>'
Scrubber.sanitize(html)
# => '<a href="/page">Link</a>' (onclick removed by forbidden_attributes)
```


---
### Allowed vs Additional
When deciding between `allowed_` and `additional_` use the following guiding principles:
- Use `allowed_tags`/`allowed_attributes` to specify an **exact whitelist** (restrictive)
- Use `additional_tags`/`additional_attributes` to **extend** the default safe lists (permissive)
- `forbidden_*` always takes precedence and removes tags/attributes regardless of other settings

---

### URI & Protocol Control

Scrubber let's you control separately how URIs and protocols are handled.

#### `allow_data_uri`
**Type:** `Boolean` | **Default:** `false`

Allow `data:` URIs in attributes:

```ruby
Scrubber.configure do |config|
  config.allow_data_uri = true
end

# Now this works
Scrubber.sanitize('<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUg...">')
```

#### `allowed_uri_regexp`
**Type:** `Regexp` | **Default:** Allows common safe protocols

Customize allowed URI patterns:

```ruby
Scrubber.configure do |config|
  # Only allow HTTPS and relative URLs
  config.allowed_uri_regexp = /^(?:https?:|\/[^\/])/
end
```

### Controlling the Format and Structure of the Output

Use the following configuration options to control the format and structure of sanitized output.

#### `return_dom`
**Type:** `Boolean` | **Default:** `false`

Return a Nokogiri document instead of HTML string:

```ruby
Scrubber.configure do |config|
  config.return_dom = true
end

doc = Scrubber.sanitize(html)
puts doc.class  # Nokogiri::HTML::Document
```

#### `return_dom_fragment`
**Type:** `Boolean` | **Default:** `false`

Return a Nokogiri document fragment:

```ruby
Scrubber.configure do |config|
  config.return_dom_fragment = true
end

fragment = Scrubber.sanitize(html)
puts fragment.class  # Nokogiri::HTML::DocumentFragment
```

#### `whole_document`
**Type:** `Boolean` | **Default:** `false`

Treat input as complete HTML document:

```ruby
Scrubber.configure do |config|
  config.whole_document = true
end

Scrubber.sanitize('<html><body><p>Content</p></body></html>')
```

### Content Control

#### `keep_content`
**Type:** `Boolean` | **Default:** `true`

Whether to preserve text content from removed tags:

```ruby
# With keep_content: true (default)
Scrubber.sanitize('<script>alert("xss")</script>safe text')
# => "safe text"

# With keep_content: false
Scrubber.configure do |config|
  config.keep_content = false
end
Scrubber.sanitize('<script>alert("xss")</script>safe text')
# => ""
```

### Special Features

#### `safe_for_templates`
**Type:** `Boolean` | **Default:** `false`

Remove template expressions (`{{ }}`, `<%= %>`, `${ }`) for template safety:

```ruby
Scrubber.configure do |config|
  config.safe_for_templates = true
end

Scrubber.sanitize('<div>{{user.input}}</div>')
# => "<div>  </div>"  # Expressions removed
```

#### `safe_for_xml`
**Type:** `Boolean` | **Default:** `true`

Remove comments that could be risky in XML contexts:

```ruby
Scrubber.configure do |config|
  config.safe_for_xml = false  # Allow comments
end
```

#### `sanitize_dom`
**Type:** `Boolean` | **Default:** `true`

Enable DOM-based sanitization (recommended to keep enabled for security).

## Default Allow Lists

When no specific `allowed_tags` or `allowed_attributes` are configured, Scrubber uses comprehensive default allow lists that balance functionality with security.

### Default Allowed Tags
**Includes:** All standard HTML5 tags, SVG tags, MathML tags, and custom elements

The default tag list includes:
- **HTML5 semantic elements**: `article`, `section`, `header`, `footer`, `nav`, `aside`, `main`
- **Interactive elements**: `button`, `input`, `select`, `textarea`, `form` (but attributes are sanitized)
- **Media elements**: `audio`, `video`, `img`, `canvas`, `svg`
- **Table elements**: `table`, `thead`, `tbody`, `tr`, `th`, `td`
- **Typography**: `p`, `h1-h6`, `strong`, `em`, `blockquote`, `code`, `pre`
- **Links and navigation**: `a`, `area`, `link`
- **Metadata**: `meta`, `title`, `head`, `html`
- **SVG and MathML**: Full support for vector graphics and mathematical notation
- **Custom elements**: Any tag containing `-` (web components)

**Security rationale:**
- Excludes inherently dangerous tags like `<script>`, `<object>`, `<embed>`, `<iframe>`
- Allows rich content while preventing script execution
- Supports modern web standards (HTML5, SVG, MathML)
- Permits custom elements for modern web development

### Default Allowed Attributes
**Includes:** Safe attributes for layout, styling, accessibility, and functionality

The default attribute list includes:
- **Layout and positioning**: `width`, `height`, `align`, `valign`, `colspan`, `rowspan`
- **Styling**: `class`, `style`, `color`, `face`, `size` (but `style` content is sanitized)
- **Accessibility**: `alt`, `title`, `lang`, `dir`, `tabindex`, `role`
- **Forms**: `type`, `name`, `value`, `placeholder`, `required`, `disabled`
- **Links**: `href`, `rel`, `target`, `download`
- **Media**: `src`, `poster`, `controls`, `autoplay`, `loop`
- **Metadata**: `id`, `data-*`, `aria-*` (when enabled)
- **SVG/MathML**: Comprehensive attribute support for these namespaces

**Security rationale:**
- Automatically blocks dangerous attributes: `onclick`, `onload`, `javascript:`, `vbscript:`
- Sanitizes URI attributes to prevent XSS via links
- Validates `style` attributes to prevent CSS-based attacks
- Allows rich interactivity while blocking script execution
- Supports modern accessibility standards

**Why these defaults:**
- Based on DOMPurify's battle-tested allow lists
- Comprehensive coverage prevents bypass attempts
- Conservative approach: allow functionality, block danger
- Regular updates ensure compatibility with web standards

## Advanced Features

### Hooks

You can further extend Scrubber's sanitization behavior with hooks:

```ruby
# Before sanitizing elements
Scrubber.add_hook(:before_sanitize_elements) do |node, data, config|
  puts "Processing: #{node.name}"
end

# During attribute sanitization
Scrubber.add_hook(:upon_sanitize_attribute) do |node, data, config|
  if data[:attr_name] == 'data-custom'
    # Force keep this attribute
    data[:keep_attr] = true
  end
end

# After sanitizing elements
Scrubber.add_hook(:after_sanitize_elements) do |node, data, config|
  # Custom post-processing
end

# Remove hooks
Scrubber.remove_hook(:before_sanitize_elements, my_hook_function)
Scrubber.remove_all_hooks
```

#### Per-Tag Attribute Control with Hooks

Hooks provide powerful per-tag attribute control, allowing you to specify which attributes are allowed on specific HTML tags. This is useful for enforcing strict security policies or implementing custom sanitization rules.

**Example: Allow specific attributes only on certain tags**

```ruby
Scrubber.add_hook(:upon_sanitize_attribute) do |node, data, config|
  tag_name = data[:tag_name]
  attr_name = data[:attr_name]
  
  # Allow href only on <a> tags
  if attr_name == 'href' && tag_name == 'a'
    data[:keep_attr] = true
  end
  
  # Allow src only on <img>, <video>, and <audio> tags
  if attr_name == 'src' && ['img', 'video', 'audio'].include?(tag_name)
    data[:keep_attr] = true
  end
  
  # Allow colspan and rowspan only on table cells
  if ['colspan', 'rowspan'].include?(attr_name) && ['td', 'th'].include?(tag_name)
    data[:keep_attr] = true
  end
end
```

**Example: Custom data attributes per component**

```ruby
# Allow specific data attributes only on certain custom elements
Scrubber.add_hook(:upon_sanitize_attribute) do |node, data, config|
  tag_name = data[:tag_name]
  attr_name = data[:attr_name]
  
  case tag_name
  when 'user-profile'
    # Allow data-user-id only on <user-profile> elements
    data[:keep_attr] = true if attr_name == 'data-user-id'
  when 'product-card'
    # Allow data-product-id and data-price only on <product-card> elements
    data[:keep_attr] = true if ['data-product-id', 'data-price'].include?(attr_name)
  end
end
```

**Available hook data:**
- `data[:tag_name]` - The element's tag name (lowercase)
- `data[:attr_name]` - The attribute name (lowercase)
- `data[:value]` - The attribute value
- `data[:keep_attr]` - Set to `true` to force keeping the attribute

## Security

Scrubber provides comprehensive XSS protection based on DOMPurify's battle-tested security model.

### Recommended Configurations

#### Maximum Security (User-Generated Content)
```ruby
Scrubber.configure do |config|
  config.allowed_tags = ['p', 'strong', 'em', 'a', 'br']
  config.allowed_attributes = ['href']
  config.forbidden_attributes = ['onclick', 'onerror', 'onload', 'onmouseover', 'style']
  config.allow_data_uri = false
  config.keep_content = false
end
```

#### Content Management System
```ruby
Scrubber.configure do |config|
  config.allowed_tags = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'strong', 'em', 'a', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'br', 'div', 'span']
  config.allowed_attributes = ['href', 'title', 'class', 'id']
  config.additional_attributes = ['data-*']  # Allow data attributes
  config.allow_data_uri = true
  config.keep_content = true
end
```

#### Rich Text Editor
```ruby
Scrubber.configure do |config|
  config.allowed_tags = ['p', 'strong', 'em', 'a', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'br', 'h1', 'h2', 'h3', 'table', 'thead', 'tbody', 'tr', 'th', 'td']
  config.allowed_attributes = ['href', 'title', 'class', 'colspan', 'rowspan']
  config.forbidden_attributes = ['style']  # Prevent CSS injection
end
```

### Best Practices

1. **Use allowlists, not blocklists** - Only allow known safe tags/attributes
2. **Validate URIs** - Use `allowed_uri_regexp` to restrict protocols
3. **Disable data URIs** - Unless you specifically need them
4. **Remove event handlers** - Block `on*` attributes
5. **Keep DOM sanitization enabled** - Don't disable `sanitize_dom`
6. **Regular updates** - Keep Scrubber updated for latest security fixes

## API Reference

### Core Methods

#### `Scrubber.sanitize(dirty_html, config = {})`
Sanitize HTML string or Nokogiri node.

**Parameters:**
- `dirty_html` (String|Nokogiri::XML::Node): Input to sanitize
- `config` (Hash): Optional configuration override

**Returns:** Sanitized HTML string or Nokogiri document

#### `Scrubber.configure { |config| ... }`
Configure Scrubber globally using a block.

#### `Scrubber.set_config(config_hash)`
Set configuration directly with a hash.

#### `Scrubber.clear_config`
Reset to default configuration.

#### `Scrubber.is_supported?`
Check if required dependencies (Nokogiri) are available.

**Returns:** Boolean

#### `Scrubber.removed`
Get list of elements/attributes that were removed during last sanitization.

**Returns:** Array of removal records

### Hook Methods

#### `Scrubber.add_hook(entry_point, &block)`
Add a hook function.

**Parameters:**
- `entry_point` (Symbol): `:before_sanitize_elements`, `:after_sanitize_elements`, `:upon_sanitize_attribute`, etc.
- `block` (Proc): Hook function

#### `Scrubber.remove_hook(entry_point, hook_function = nil)`
Remove specific hook or all hooks for an entry point.

#### `Scrubber.remove_all_hooks`
Remove all hooks.

### Configuration Attributes (defaults and security notes)

All options accept `snake_case` keys. Defaults are chosen for safety and DOMPurify parity. Changing them can reduce security—notes per option below.

| Option | Default | Description & Security Implications |
| --- | --- | --- |
| `allowed_tags` | `nil` (use default safe set) | Exact allowlist of elements. When set, only these tags pass. Use to restrict surface. |
| `additional_tags` | `[]` | Extends default safe set. Increases surface; ensure tags are non-scriptable. |
| `forbidden_tags` | `['base','link','meta','style','annotation-xml']` | Always removed even if allowed elsewhere. Removing entries can reintroduce navigation/XSS vectors. |
| `allowed_attributes` | `nil` (default safe set) | Exact allowlist of attributes. Restrictive; disables defaults. |
| `allowed_attributes_per_tag` | `nil` | Hash mapping tag names to allowed attributes for that tag. Provides fine-grained per-tag control. Takes precedence over `allowed_attributes` for specified tags. |
| `additional_attributes` | `[]` | Extends default safe attributes. Expands surface; review risk. |
| `forbidden_attributes` | `nil` | Attributes always removed. Use to hard-block specific attrs. |
| `allow_data_attributes` | `true` | Controls `data-*`. Turning off removes all `data-*`. |
| `allow_aria_attributes` | `true` | Controls `aria-*`. Turning off removes accessibility attrs. |
| `allow_data_uri` | `false` | Blocks `data:` URIs by default. Enabling allows data URLs (safe only for vetted content). |
| `allow_unknown_protocols` | `false` | If true, permits non-standard schemes (higher XSS/phishing risk). |
| `allowed_uri_regexp` | `nil` | Custom regexp to validate URI attributes. Set to constrain destinations. |
| `additional_uri_safe_attributes` | `[]` | Extra attributes treated as URI-like (e.g., `['filter']`). Ensure they are safe. |
| `allow_style_tags` | `false` | `<style>` tags dropped by default. Enabling scans and drops blocks on unsafe content but remains heuristic. |
| `sanitize_dom` | `true` | Removes clobbering `id`/`name` values. Disabling reopens DOM clobbering vectors. |
| `safe_for_templates` | `false` | If true, strips template expressions (e.g., `{{ }}`, `${ }`, ERB). |
| `safe_for_xml` | `true` | If true, removes comments/PI in XML-ish content. |
| `whole_document` | `false` | Parse as full document instead of fragment. |
| `allow_document_elements` | `false` | When `whole_document` is false, drop `html/head/body`. Set true to retain them (slightly larger surface). |
| `minimal_profile` | `false` | Use a smaller HTML-only allowlist (no SVG/MathML). |
| `force_body` | `false` | Forces body context when parsing fragments. |
| `return_dom` | `false` | Return Nokogiri DOM instead of string. |
| `return_dom_fragment` | `false` | Return Nokogiri fragment instead of string. |
| `sanitize_until_stable` | `true` | Re-sanitize until stable to mitigate mutation-XSS. |
| `mutation_max_passes` / `pass_limit` | `2` | Max passes for stabilization. Set to `0` to disable; higher increases cost. |
| `keep_content` | `true` | If false, removes contents of stripped elements. |
| `in_place` | `false` | If true, attempts to sanitize in place; use with care. |
| `use_profiles` | `{}` | Enable `html`, `svg`, `svg_filters`, `math_ml` profiles to build allowlists. |
| `namespace` | `'http://www.w3.org/1999/xhtml'` | Namespace for XHTML handling. |
| `parser_media_type` | `'text/html'` | Parser media type; set to `application/xhtml+xml` for XHTML parsing. |
| `custom_element_handling` | `nil` | Optional handling for custom elements. |

#### CSS sanitization
- Inline `style` attributes are parsed into declarations and only allowed properties are retained; any dangerous value (javascript: / expression / @import / behavior / binding / data:* (including SVG) or escaped variants) drops the whole attribute.
- `<style>` tags remain default-deny; opt-in `allow_style_tags` still drops blocks containing unsafe content. |

Usage examples:

```ruby
# Lock down to basic tags/attrs
Scrubber.sanitize(html,
  allowed_tags: %w[p strong em a],
  allowed_attributes: %w[href title],
  mutation_max_passes: 2
)

# Extend defaults with a custom element and allow data URIs for images only
Scrubber.configure do |config|
  config.additional_tags = ['my-widget']
  config.allow_data_uri = true
  config.allowed_uri_regexp = %r{^https?://example\\.com/}
end

# Enable style tags with heuristic scanning (use cautiously)
Scrubber.sanitize(html, allow_style_tags: true)
```

## Performance

Scrubber is optimized for performance while maintaining security:

### Tips for Better Performance

1. **Use strict configurations** - Fewer allowed tags/attributes = faster processing
2. **Reuse configurations** - Set once, use many times
3. **Batch processing** - Process multiple documents together
4. **Consider DOM return** - For multiple operations on same document

```ruby
# Good: Reuse configuration
Scrubber.configure do |config|
  config.allowed_tags = ['p', 'strong', 'em']
end

documents.each do |doc|
  clean = Scrubber.sanitize(doc)  # Fast - config already set
end

# Less optimal: New config each time
documents.each do |doc|
  clean = Scrubber.sanitize(doc, allowed_tags: ['p', 'strong', 'em'])
end
```

### Benchmarks (Apple M1 Max, local run)

Executed via `ruby spec/scrubber_performance_spec.rb` (multi-pass sanitization enabled by default):

- 1KB HTML (10 iters): Default ~3.3ms avg; Strict ~0.3ms avg
- 10KB HTML (10 iters): Default ~31ms avg; Strict ~3.3ms avg
- 50KB HTML (10 iters): Default ~154–161ms avg; Strict ~16ms avg
- 100KB HTML (10 iters): Default ~320–350ms avg; Strict ~31ms avg
- 500KB HTML (10 iters): Default ~1.7–1.8s avg; Strict ~0.16–0.17s avg
- Throughput ranges: ~280–325 KB/s (default), ~3,100 KB/s (strict) across sizes

Stress scenarios (from `spec/scrubber_performance_stress_spec.rb` fallback runner):
- 1,000 small docs: ~0.40s total (~2,450 docs/sec)
- Deep nesting (100 levels): <5s target met
- Memory growth check: <50k object growth over 100 iterations


## Development

### Setup

```bash
git clone https://github.com/kuyio/scrubber.git
cd scrubber
bundle install
```

### Testing

```bash
# Run all tests
make test

# Run test suite with coverage
COVERAGE=true rake spec

# Run specific test file
rspec spec/basic_sanitization_spec.rb
```

### Console

```bash
bin/console
```

### Building

```bash
# Build gem
make build

# Install locally
make install
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`rake spec`)
5. Update documentation as needed
6. Commit your changes (`git commit -am 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Guidelines

- **Security First**: All changes must maintain or improve security
- **Backward Compatibility**: Avoid breaking changes when possible
- **Comprehensive Tests**: New features need full test coverage
- **Documentation**: Update README and inline docs for API changes
- **Performance**: Consider performance impact of changes

## License

This gem is available as open source under the terms of the **Apache License 2.0** and **Mozilla Public License 2.0**.

## Acknowledgments

Originally inspired by the excellent [DOMPurify](https://github.com/cure53/DOMPurify) JavaScript library by Cure53 and contributors. Scrubber brings DOMPurify's battle-tested security to the Ruby ecosystem with an idiomatic Ruby API.
