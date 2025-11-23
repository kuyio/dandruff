# Scrubber

**A robust Ruby HTML sanitizer providing comprehensive XSS protection with an idiomatic, developer-friendly API.**

Scrubber is built on the battle-tested security foundations of [DOMPurify](https://github.com/cure53/DOMPurify), bringing proven XSS defense to the Ruby ecosystem. Whether you're sanitizing user comments, rendering rich content, or processing HTML emails, Scrubber provides the security and flexibility you need.

## ✨ Key Features

- 🛡️ **Comprehensive XSS Protection** - Defends against XSS, mXSS, DOM clobbering, and protocol injection
- ⚙️ **Flexible Configuration** - Fine-grained control over tags, attributes, and sanitization behavior  
- 📦 **Content Type Profiles** - Pre-configured settings for HTML, SVG, MathML, and HTML email
- 🎣 **Hook System** - Extend sanitization with custom processing logic
- 💎 **Developer-Friendly API** - Intuitive Ruby idioms with block-based configuration
- ⚡ **Performance Optimized** - Efficient multi-pass sanitization with configurable limits
- 🔒 **Battle-Tested** - Based on DOMPurify's proven security model

## 🚀 Quickstart

Get up and running in 60 seconds:

```ruby
# 1. Add scrubber to your Gemfile
gem 'scrubber', github: 'kuyio/scrubber'

# 2. Run bundle install
bundle install

# 3. Sanitize HTML with default configuration
scrubber = Scrubber.new
clean_html = scrubber.sanitize('<script>alert("xss")</script><p>Safe content</p>')
# => "<p>Safe content</p>"

# 4. Configure for your use case
scrubber = Scrubber.new do |config|
  config.allowed_tags = ['p', 'strong', 'em', 'a']
  config.allowed_attributes = ['href', 'class']
end

# 5. Sanitize an input string
scrubber.sanitize('<p class="intro"><strong>Hello</strong> <a href="/about">world</a>!</p>')
# => '<p class="intro"><strong>Hello</strong> <a href="/about">world</a>!</p>'
```

**That's it!** You're now protecting your application from XSS attacks. Read on to learn more about configuration and advanced usage.

## 📦 Installation

### Using Bundler (Recommended)

Add to your `Gemfile`:

```ruby
gem 'scrubber'
```

Then run:

```bash
bundle install
```

### Direct Installation

```bash
gem install scrubber
```

### Requirements

- **Ruby**: 2.7 or higher
- **Nokogiri**: 1.12 or higher (automatically installed)

## ⚙️ Configuration

Scrubber offers three ways to configure sanitization: block-based, direct configuration, and per-call options.

### Configuration Styles

```ruby
# 1. Block-based configuration (recommended for instances)
scrubber = Scrubber.new do |config|
  config.allowed_tags = ['p', 'strong', 'em']
  config.allowed_attributes = ['class', 'href']
end

# 2. Direct configuration  
scrubber = Scrubber.new
scrubber.set_config(
  allowed_tags: ['p', 'strong'],
  allowed_attributes: ['class']
)

# 3. Per-call configuration
scrubber = Scrubber.new
scrubber.sanitize(html, allowed_tags: ['p'], allowed_attributes: ['class'])

# 4. Class method with configuration
clean = Scrubber.sanitize(html, allowed_tags: ['p', 'strong'])
```

### Common Configuration Patterns

#### Restrict to specific tags and attributes

```ruby
scrubber = Scrubber.new do |config|
  config.allowed_tags = ['p', 'strong', 'em', 'a']
  config.allowed_attributes = ['href', 'title']
end
```

#### Extend defaults instead of replacing

```ruby
scrubber = Scrubber.new do |config|
  config.additional_tags = ['custom-element']
  config.additional_attributes = ['data-custom-id']
end
```

#### Block specific tags or attributes

```ruby
scrubber = Scrubber.new do |config|
  config.forbidden_tags = ['script', 'iframe']
  config.forbidden_attributes = ['onclick', 'onerror']
end
```

→ See [Configuration Reference](#configuration-reference) for all available options.

## 📖 Usage

### Simple Use Cases

#### Sanitize User Comments

```ruby
# Basic text formatting only
scrubber = Scrubber.new do |config|
  config.allowed_tags = ['p', 'br', 'strong', 'em', 'a']
  config.allowed_attributes = ['href']
  config.forbidden_attributes = ['onclick', 'onerror']
end

comment = params[:comment]
safe_comment = scrubber.sanitize(comment)
```

#### Sanitize Markdown-Generated HTML

```ruby
# Allow rich formatting from Markdown
scrubber = Scrubber.new do |config|
  config.allowed_tags = [
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'p', 'br', 'strong', 'em', 'code', 'pre',
    'ul', 'ol', 'li', 'blockquote', 'a'
  ]
  config.allowed_attributes = ['href', 'title']
end

html = markdown_renderer.render(params[:content])
safe_html = scrubber.sanitize(html)
```

#### Sanitize Blog Post Content

```ruby
# Rich content with images
scrubber = Scrubber.new do |config|
  config.allowed_tags = [
    'p', 'br', 'strong', 'em', 'ul', 'ol', 'li',
    'h2', 'h3', 'blockquote', 'code', 'pre',
    'a', 'img'
  ]
  config.allowed_attributes = ['href', 'title', 'src', 'alt', 'class']
  config.allow_data_uri = false  # Block data URIs for images
end

post_html = params[:post][:content]
safe_html = scrubber.sanitize(post_html)
```

### Intermediate Use Cases

#### Using Profiles for Content Types

Profiles are pre-configured sets of tags and attributes for common content types:

```ruby
# HTML content profile
scrubber = Scrubber.new do |config|
  config.use_profiles = { html: true }
end

# SVG graphics
scrubber = Scrubber.new do |config|
  config.use_profiles = { html: true, svg: true }
end

# Mathematical content  
scrubber = Scrubber.new do |config|
  config.use_profiles = { html: true, math_ml: true }
end

# Combine multiple profiles
scrubber = Scrubber.new do |config|
  config.use_profiles = { html: true, svg: true, math_ml: true }
end
```

#### HTML Email Sanitization

HTML emails require special handling with legacy attributes:

```ruby
scrubber = Scrubber.new do |config|
  config.use_profiles = { html_email: true }
end

email_html = message.html_part.body.to_s
safe_email = scrubber.sanitize(email_html)
```

The `html_email` profile:
- Allows document structure tags (`head`, `meta`, `style`)
- Permits legacy presentation attributes (`bgcolor`, `cellpadding`, `align`, etc.)
- Uses per-tag attribute restrictions for security
- Allows style tags with content sanitization
- Excludes form elements and scripts

#### Per-Tag Attribute Control

Restrict which attributes are allowed on specific tags for maximum security:

```ruby
scrubber = Scrubber.new do |config|
  config.allowed_attributes_per_tag = {
    'a' => ['href', 'title', 'target'],
    'img' => ['src', 'alt', 'width', 'height'],
    'table' => ['border', 'cellpadding', 'cellspacing'],
    'td' => ['colspan', 'rowspan'],
    'th' => ['colspan', 'rowspan', 'scope']
  }
end

# Only specified attributes allowed on each tag
html = '<a href="/page" onclick="alert()">Link</a>'
scrubber.sanitize(html)
# => '<a href="/page">Link</a>' (onclick removed)

html = '<img src="pic.jpg" href="/bad">'
scrubber.sanitize(html)
# => '<img src="pic.jpg">' (href removed from img)
```

**Security benefit:** Prevents attribute confusion attacks where dangerous attributes appear on unexpected elements.

### Complex Use Cases

#### Custom URI Validation

```ruby
# Only allow HTTPS URLs from your domain
scrubber = Scrubber.new do |config|
  config.allowed_uri_regexp = /^https:\/\/(www\.)?example\.com\//
end

html = '<a href="https://example.com/safe">OK</a><a href="http://evil.com">Bad</a>'
scrubber.sanitize(html)  
# => '<a href="https://example.com/safe">OK</a><a>Bad</a>'
```

#### Hook-Based Customization

Hooks allow you to extend Scrubber's behavior:

```ruby
scrubber = Scrubber.new

# Custom attribute handling
scrubber.add_hook(:upon_sanitize_attribute) do |node, data, config|
  tag_name = data[:tag_name]
  attr_name = data[:attr_name]
  
  # Allow specific custom data attributes
  if attr_name.start_with?('data-safe-')
    data[:keep_attr] = true
  end
  
  # Force lowercase on certain attributes  
  if attr_name == 'id'
    node[attr_name] = node[attr_name].downcase
  end
end

# Element processing
scrubber.add_hook(:upon_sanitize_element) do |node, data, config|
  # Log removed elements
  puts "Processing #{data[:tag_name]} element"
end

html = '<div data-safe-user-id="123" DATA-KEY="ABC" id="MyID">Content</div>'
scrubber.sanitize(html)
# => '<div data-safe-user-id="123" id="myid">Content</div>'
```

Available hooks:
- `:before_sanitize_elements` - Before processing elements
- `:after_sanitize_elements` - After processing elements
- `:before_sanitize_attributes` - Before processing attributes on an element
- `:after_sanitize_attributes` - After processing attributes on an element
- `:upon_sanitize_element` - When processing each element
- `:upon_sanitize_attribute` - When processing each attribute

#### Template Safety

Remove template expressions when sanitizing user-submitted content:

```ruby
scrubber = Scrubber.new do |config|
  config.safe_for_templates = true
end

html = '<div>{{user.name}} - <%= admin_link %> - ${secret}</div>'
scrubber.sanitize(html)
# => '<div>   -    -  </div>' (template expressions removed)
```

Removes:
- Mustache/Handlebars: `{{ }}`
- ERB: `<% %>`, `<%= %>`  
- Template literals: `${ }`

#### Multi-Pass Sanitization

Protect against mutation-based XSS (mXSS):

```ruby
scrubber = Scrubber.new do |config|
  config.sanitize_until_stable = true  # default
  config.mutation_max_passes = 2       # default
end

# Scrubber will re-sanitize until output is stable
# or max passes reached, preventing mXSS attacks
```

#### Return DOM Instead of String

For further processing with Nokogiri:

```ruby
scrubber = Scrubber.new do |config|
  config.return_dom = true
end

doc = scrubber.sanitize(html)
# => Nokogiri::HTML::Document

# Or return a fragment
scrubber = Scrubber.new do |config|
  config.return_dom_fragment = true
end

fragment = scrubber.sanitize(html)
# => Nokogiri::HTML::DocumentFragment
```

## 📚 Reference

### Configuration Reference

Complete list of configuration options with defaults and security implications:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `allowed_tags` | `Array<String>` | `nil` (use defaults) | Exact allowlist of elements. When set, only these tags pass. |
| `additional_tags` | `Array<String>` | `[]` | Extends default safe set. |
| `forbidden_tags` | `Array<String>` | `['base','link','meta','annotation-xml','noscript']` | Always removed even if allowed elsewhere. |
| `allowed_attributes` | `Array<String>` | `nil` (use defaults) | Exact allowlist of attributes. |
| `allowed_attributes_per_tag` | `Hash<String, Array<String>>` | `nil` | Per-tag attribute restrictions. Takes precedence over `allowed_attributes`. |
| `additional_attributes` | `Array<String>` | `[]` | Extends default safe attributes. |
| `forbidden_attributes` | `Array<String>` | `nil` | Attributes always removed. |
| `allow_data_attributes` | `Boolean` | `true` | Controls `data-*` attributes. |
| `allow_aria_attributes` | `Boolean` | `true` | Controls `aria-*` attributes for accessibility. |
| `allow_data_uri` | `Boolean` | `true` | Blocks `data:` URIs by default for safety. |
| `allow_unknown_protocols` | `Boolean` | `false` | If true, permits non-standard schemes (⚠️ security risk). |
| `allowed_uri_regexp` | `Regexp` | `nil` | Custom regexp to validate URI attributes. |
| `additional_uri_safe_attributes` | `Array<String>` | `[]` | Extra attributes treated as URI-like. |
| `allow_style_tags` | `Boolean` | `true` | `<style>` tags with content scanning. |
| `sanitize_dom` | `Boolean` | `true` | Removes DOM clobbering `id`/`name` values. |
| `safe_for_templates` | `Boolean` | `false` | Strips template expressions (`{{ }}`, `<%= %>`, `${ }`). |
| `safe_for_xml` | `Boolean` | `true` | Removes comments/PI in XML-ish content. |
| `whole_document` | `Boolean` | `false` | Parse as full document instead of fragment. |
| `allow_document_elements` | `Boolean` | `false` | Retain `html/head/body` tags. |
| `minimal_profile` | `Boolean` | `false` | Use smaller HTML-only allowlist (no SVG/MathML). |
| `force_body` | `Boolean` | `false` | Forces body context when parsing fragments. |
| `return_dom` | `Boolean` | `false` | Return Nokogiri DOM instead of string. |
| `return_dom_fragment` | `Boolean` | `false` | Return Nokogiri fragment instead of string. |
| `sanitize_until_stable` | `Boolean` | `true` | Re-sanitize until stable to mitigate mXSS. |
| `mutation_max_passes` | `Integer` | `2` | Max passes for stabilization. Higher = more secure, slower. |
| `keep_content` | `Boolean` | `true` | If false, removes contents of stripped elements. |
| `in_place` | `Boolean` | `false` | Attempts to sanitize in place (experimental). |
| `use_profiles` | `Hash` | `{}` | Enable content type profiles: `:html`, `:svg`, `:svg_filters`, `:math_ml`, `:html_email`. |
| `namespace` | `String` | `'http://www.w3.org/1999/xhtml'` | Namespace for XHTML handling. |
| `parser_media_type` | `String` | `'text/html'` | Parser media type; set to `application/xhtml+xml` for XHTML. |

### API Reference

#### Core Methods

##### `Scrubber.new(config = nil, &block)` → `Sanitizer`

Creates a new Scrubber instance.

**Parameters:**
- `config` (Hash, Config) - Optional configuration hash or Config object
- `block` - Optional block for configuration

**Returns:** Sanitizer instance

**Example:**
```ruby
scrubber = Scrubber.new do |config|
  config.allowed_tags = ['p', 'strong']
end
```

##### `scrubber.sanitize(dirty_html, config = {})` → `String` or `Nokogiri::XML::Document`

Sanitizes HTML string or Nokogiri node.

**Parameters:**
- `dirty_html` (String, Nokogiri::XML::Node) - Input to sanitize
- `config` (Hash) - Optional configuration override

**Returns:** Sanitized HTML string or Nokogiri document (based on config)

**Example:**
```ruby
clean = scrubber.sanitize('<script>xss</script><p>Safe</p>')
# => "<p>Safe</p>"
```

##### `Scrubber.sanitize(dirty_html, config = {})` → `String`

Class method for one-off sanitization.

**Parameters:**
- `dirty_html` (String) - Input to sanitize  
- `config` (Hash) - Configuration options

**Returns:** Sanitized HTML string

**Example:**
```ruby
clean = Scrubber.sanitize(html, allowed_tags: ['p'])
```

#### Configuration Methods

##### `scrubber.configure { |config| ... }` → `Sanitizer`

Configures the scrubber instance using a block.

**Example:**
```ruby
scrubber.configure do |config|
  config.allowed_tags = ['p', 'strong']
end
```

##### `scrubber.set_config(config_hash)` → `Config`

Sets configuration directly with a hash.

**Example:**
```ruby
scrubber.set_config(allowed_tags: ['p'], allowed_attributes: ['class'])
```

##### `scrubber.clear_config` → `Config`

Resets to default configuration.

#### Hook Methods

##### `scrubber.add_hook(entry_point, &block)` → `void`

Adds a hook function.

**Parameters:**
- `entry_point` (Symbol) - Hook name (`:before_sanitize_elements`, `:upon_sanitize_attribute`, etc.)
- `block` (Proc) - Hook function receiving `(node, data, config)`

**Example:**
```ruby
scrubber.add_hook(:upon_sanitize_attribute) do |node, data, config|
  data[:keep_attr] = true if data[:attr_name] == 'data-safe'
end
```

##### `scrubber.remove_hook(entry_point, hook_function = nil)` → `Proc` or `nil`

Removes specific hook or last hook for an entry point.

##### `scrubber.remove_all_hooks` → `Hash`

Removes all hooks.

#### Utility Methods

##### `scrubber.supported?` → `Boolean`

Checks if required dependencies (Nokogiri) are available.

##### `scrubber.removed` → `Array`

Gets list of elements/attributes removed during last sanitization.

**Returns:** Array of removal records

### Profiles Reference

#### HTML Profile

**Enable:** `use_profiles: { html: true }`

**Includes:** All standard HTML5 semantic elements, media elements, form controls, and text formatting.

**Use for:** Standard web content, blog posts, documentation

```ruby
scrubber = Scrubber.new do |config|
  config.use_profiles = { html: true }
end
```

#### SVG Profile

**Enable:** `use_profiles: { svg: true }`

**Includes:** SVG elements for vector graphics (shapes, paths, gradients, basic filters)

**Use for:** Inline SVG graphics, icons, diagrams

```ruby
scrubber = Scrubber.new do |config|
  config.use_profiles = { html: true, svg: true }
end
```

#### SVG Filters Profile

**Enable:** `use_profiles: { svg_filters: true }`

**Includes:** Advanced SVG filter primitives (blur, color manipulation, lighting)

**Use for:** SVG with visual effects

```ruby
scrubber = Scrubber.new do |config|
  config.use_profiles = { svg: true, svg_filters: true }
end
```

#### MathML Profile

**Enable:** `use_profiles: { math_ml: true }`

**Includes:** MathML elements for mathematical notation

**Use for:** Scientific documents, mathematical content

```ruby
scrubber = Scrubber.new do |config|
  config.use_profiles = { html: true, math_ml: true }
end
```

#### HTML Email Profile

**Enable:** `use_profiles: { html_email: true }`

**Includes:**
- HTML elements + document structure (`head`, `meta`, `style`)
- Legacy presentation tags (`font`, `center`)
- Legacy attributes (`bgcolor`, `cellpadding`, `valign`, etc.)
- Per-tag attribute restrictions (automatic)

**Excludes:** Forms, scripts, interactive elements

**Special settings:**
- Allows style tags (required for email)
- Disables DOM clobbering protection (emails are sandboxed)
- Parses as whole document

**Use for:** HTML email rendering

```ruby
scrubber = Scrubber.new do |config|
  config.use_profiles = { html_email: true }
end
```

## 🔒 Security

### Threat Model

Scrubber defends against multiple attack vectors:

#### XSS (Cross-Site Scripting)

**Attack:** Injecting scripts via HTML tags or attributes

**Protection:**
- Removes `<script>`, `<iframe>`, `<object>`, `<embed>` tags
- Blocks event handlers (`onclick`, `onerror`, `onload`, etc.)
- Validates URI attributes to prevent `javascript:` and `vbscript:` protocols

```ruby
# Attack blocked
scrubber.sanitize('<script>alert("xss")</script>')
# => ""

scrubber.sanitize('<img src="javascript:alert(1)">')
# => "<img>"

scrubber.sanitize('<a onclick="alert(1)">Click</a>')
# => "<a>Click</a>"
```

#### mXSS (Mutation-Based XSS)

**Attack:** HTML mutations during parsing that create XSS

**Protection:**
- Multi-pass sanitization (validates output is stable)
- Namespace confusion prevention  (SVG/MathML)
- Proper HTML5 parsing

```ruby
# mXSS prevented through multi-pass sanitization
scrubber = Scrubber.new do |config|
  config.sanitize_until_stable = true  # default
  config.mutation_max_passes = 2
end
```

#### DOM Clobbering

**Attack:** Using `id`/`name` attributes to override built-in DOM properties

**Protection:**
- Blocks dangerous id/name values (`document`, `location`, `alert`, `window`, etc.)
- Can be disabled for sandboxed contexts like email

```ruby
# DOM clobbering blocked
scrubber.sanitize('<form name="document">')
# => "<form></form>" (name removed)

scrubber.sanitize('<img id="location">')
# => "<img>" (id removed)
```

#### Protocol Injection

**Attack:** Using dangerous URI protocols to execute code

**Protection:**
- Blocks `javascript:`, `vbscript:`, `data:text/html` protocols
- Validates against allowlist of safe protocols
- Custom protocol validation with `allowed_uri_regexp`

```ruby
scrubber.sanitize('<a href="javascript:alert(1)">Click</a>')
# => "<a>Click</a>"

scrubber.sanitize('<link href="vbscript:msgbox(1)">')
# => (link removed)
```

#### CSS Injection

**Attack:** Using CSS to execute code or exfiltrate data

**Protection:**
- Parses and validates inline `style` attributes
- Removes dangerous CSS properties and values
- Scans `<style>` tag content for unsafe patterns

```ruby
scrubber.sanitize('<div style="expression(alert(1))"></div>')
# => "<div></div>" (dangerous style removed)

scrubber.sanitize('<div style="background: url(javascript:alert(1))"></div>')
# => "<div></div>" (dangerous style removed)
```

### Security Best Practices

#### 1. Use Allowlists, Not Blocklists

```ruby
# ✅ Good - explicitly allow safe tags
config.allowed_tags = ['p', 'strong', 'em', 'a']

# ❌ Avoid - trying to block everything dangerous is error-prone
config.forbidden_tags = ['script', 'iframe', ...] # incomplete!
```

#### 2. Restrict URI Protocols

```ruby
# ✅ Good - only allow HTTPS  
config.allowed_uri_regexp = /^https:/

# ⚠️ Caution - allowing unknown protocols is risky
config.allow_unknown_protocols = true  # avoid unless necessary
```

#### 3. Disable Data URIs Unless Needed

```ruby
# ✅ Good for user-generated content
config.allow_data_uri = false

# ⚠️ Only enable for trusted content
config.allow_data_uri = true  # only if you need it
```

#### 4. Remove Event Handlers

```ruby
# ✅ Good - block all event handlers
config.forbidden_attributes = [
  'onclick', 'onload', 'onerror', 'onmouseover',
  'onfocus', 'onblur', 'onchange', 'onsubmit'
]
```

#### 5. Keep DOM Sanitization Enabled

```ruby
# ✅ Good - default setting
config.sanitize_dom = true

# ⚠️ Only disable for sandboxed contexts (e.g., email rendering)
config.sanitize_dom = false  # use with caution
```

#### 6. Use Per-Tag Attribute Control

```ruby
# ✅ Good - prevents attribute confusion
config.allowed_attributes_per_tag = {
  'a' => ['href', 'title'],      # no 'src' on links
  'img' => ['src', 'alt'],       # no 'href' on images
  'form' => ['action', 'method'] # only form-specific attrs
}
```

#### 7. Keep Scrubber Updated

```ruby
# Check your Gemfile.lock regularly
bundle outdated scrubber

# Update to latest version
bundle safe update scrubber
```

### Recommended Configurations

#### Maximum Security (User Comments)

```ruby
scrubber = Scrubber.new do |config|
  config.allowed_tags = ['p', 'br', 'strong', 'em', 'a']
  config.allowed_attributes = ['href']
  config.forbidden_attributes = ['onclick', 'onerror', 'onload', 'style']
  config.allow_data_uri = false
  config.keep_content = false
end
```

#### Content Management System

```ruby
scrubber = Scrubber.new do |config|
  config.allowed_tags = [
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'p', 'br', 'strong', 'em', 'ul', 'ol', 'li',
    'blockquote', 'code', 'pre', 'a', 'img',
    'div', 'span', 'table', 'tr', 'td', 'th'
  ]
  config.allowed_attributes = ['href', 'src', 'alt', 'title', 'class', 'id']
  config.allow_data_uri = true  # for embedded images
  config.allowed_uri_regexp = /^(?:https?:|\/)/  # only https and relative
end
```

#### Rich Text Editor

```ruby
scrubber = Scrubber.new do |config|
  config.use_profiles = { html: true }
  config.forbidden_tags = ['script', 'iframe', 'object', 'embed']
  config.forbidden_attributes = ['on*']  # remove all event handlers
  config.allowed_attributes_per_tag = {
    'img' => ['src', 'alt', 'width', 'height'],
    'a' => ['href', 'title']
  }
end
```

## ⚡ Performance

Scrubber is optimized for performance while maintaining security.

### Benchmarks

Executed on Apple M1 Max via `ruby spec/scrubber_performance_spec.rb`:

| Input Size | Default Config | Strict Config | Throughput (Default) | Throughput (Strict) |
|------------|----------------|---------------|----------------------|---------------------|
| 1KB | ~3.3ms | ~0.3ms | ~300 KB/s | ~3,300 KB/s |
| 10KB | ~31ms | ~3.3ms | ~320 KB/s | ~3,000 KB/s |
| 50KB | ~160ms | ~16ms | ~310 KB/s | ~3,100 KB/s |
| 100KB | ~340ms | ~31ms | ~290 KB/s | ~3,200 KB/s |
| 500KB | ~1.8s | ~170ms | ~280 KB/s | ~2,900 KB/s |

**Stress tests:**
- 1,000 small docs: ~0.40s total (~2,450 docs/sec)
- Deep nesting (100 levels): <5s
- Memory growth: <50k objects over 100 iterations

### Performance Tips

#### 1. Reuse Configurations

```ruby
# ✅ Good - reuse configuration
scrubber = Scrubber.new do |config|
  config.allowed_tags = ['p', 'strong', 'em']
end

documents.each do |doc|
  clean = scrubber.sanitize(doc)  # fast - config already set
end

# ❌ Slower - new config each time
documents.each do |doc|
  clean = Scrubber.sanitize(doc, allowed_tags: ['p', 'strong', 'em'])
end
```

#### 2. Use Strict Configurations

More restrictive configurations are faster:

```ruby
# Faster - small allowlist
config.allowed_tags = ['p', 'strong', 'em']

# Slower - large allowlist or nil (uses defaults)
config.allowed_tags = nil
```

#### 3. Batch Processing

Process multiple documents with the same instance:

```ruby
scrubber = Scrubber.new do |config|
  # ... configuration
end

cleaned_docs = documents.map { |doc| scrubber.sanitize(doc) }
```

#### 4. Adjust Multi-Pass Limit

For trusted content, you can reduce passes:

```ruby
# Faster but less secure - use only for pre-validated content
config.sanitize_until_stable = false

# Or reduce max passes
config.mutation_max_passes = 1  # default is 2
```

#### 5. Return DOM for Further Processing

If you need to process the output further:

```ruby
config.return_dom = true
doc = scrubber.sanitize(html)  # Returns Nokogiri document
# ... further processing with Nokogiri
```

## 🔄 Migration Guides

### From Rails Sanitizer

```ruby
# Before (Rails)
ActionController::Base.helpers.sanitize(html, tags: ['p', 'strong'])

# After (Scrubber)
Scrubber.sanitize(html, allowed_tags: ['p', 'strong'])

# Or create reusable instance
@scrubber = Scrubber.new do |config|
  config.allowed_tags = ['p', 'strong', 'em', 'a']
  config.allowed_attributes = ['href']
end

@scrubber.sanitize(html)
```

### From Loofah

```ruby
# Before (Loofah)
Loofah.fragment(html).scrub!(:prune).to_s

# After (Scrubber)
Scrubber.sanitize(html, keep_content: false)

# With specific tags
Loofah.fragment(html).scrub!(:strip).to_s

# Scrubber equivalent
Scrubber.sanitize(html, allowed_tags: ['p', 'strong'])
```

### From Sanitize Gem

```ruby
# Before (Sanitize)
Sanitize.fragment(html, elements: ['p', 'strong'])

# After (Scrubber)
Scrubber.sanitize(html, allowed_tags: ['p', 'strong'])

# Custom config
Sanitize.fragment(html, Sanitize::Config::RELAXED)

# Scrubber profiles
Scrubber.sanitize(html) do |config|
  config.use_profiles = { html: true }
end
```

## 🆚 Comparison

See [COMPARISON.md](COMPARISON.md) for a detailed comparison with other Ruby HTML sanitization libraries:

- Rails' built-in sanitizer
- Loofah
- Sanitize gem

**Key differentiators:**
- Based on DOMPurify's proven security model
- Protection against mXSS attacks
- DOM clobbering prevention
- Per-tag attribute control  
- Hook system for extensibility
- HTML email support with per-tag restrictions

## ❓ FAQ

### How is Scrubber different from other sanitizers?

Scrubber brings DOMPurify's battle-tested security model to Ruby, with specific defenses against mXSS, DOM clobbering, and protocol injection that other Ruby sanitizers may not provide. It also offers per-tag attribute control and an extensible hook system.

### Is Scrubber safe for user-generated content?

Yes! Scrubber is specifically designed for sanitizing untrusted user input. Use restrictive configurations for maximum security (see [Recommended Configurations](#recommended-configurations)).

### Can I use Scrubber with Rails?

Absolutely! Scrubber works great with Rails:

```ruby
# In your helper
def sanitize_user_content(html)
  @scrubber ||= Scrubber.new do |config|
    config.allowed_tags = ['p', 'strong', 'em', 'a']
    config.allowed_attributes = ['href']
  end
  @scrubber.sanitize(html)
end
```

### Does Scrubber work with HTML emails?

Yes! Use the `html_email` profile:

```ruby
scrubber = Scrubber.new do |config|
  config.use_profiles = { html_email: true }
end
```

This includes legacy attributes and per-tag restrictions needed for email clients.

### What about performance?

Scrubber processes ~300 KB/s with default config and ~3,000 KB/s with strict config on modern hardware. Reuse configuration instances for best performance. See [Performance](#performance) section.

### How do I allow custom elements?

```ruby
scrubber = Scrubber.new do |config|
  config.additional_tags = ['my-custom-element', 'web-component']
end
```

Elements with hyphens are treated as custom elements by default.

### Can I allow inline styles?

Yes, but they're sanitized for safety:

```ruby
scrubber = Scrubber.new do |config|
  config.allowed_attributes = ['style']  # style is allowed by default
end

# Safe styles pass through
scrubber.sanitize('<div style="color: red;">Text</div>')
# => '<div style="color:red;">Text</div>'

# Dangerous styles are removed
scrubber.sanitize('<div style="expression(alert(1))">Text</div>')
# => '<div>Text</div>'
```

### How do I debug what's being removed?

```ruby
scrubber = Scrubber.new
scrubber.sanitize(html)

# Check what was removed
removed = scrubber.removed
removed.each do |item|
  if item[:element]
    puts "Removed element: #{item[:element].name}"
  elsif item[:attribute]
    puts "Removed attribute: #{item[:attribute].name} from #{item[:from].name}"
  end
end
```

## 🛠️ Troubleshooting

### Content is being removed unexpectedly

**Check your configuration:**

```ruby
# Enable keep_content to preserve text
config.keep_content = true

# Check if tags are in your allowlist
puts scrubber.config.allowed_tags

# Use additional_tags instead of allowed_tags to extend defaults
config.additional_tags = ['custom-tag']  # instead of replacing all
```

### Attributes are being stripped

**Verify attribute configuration:**

```ruby
# Check which attributes are allowed
puts scrubber.config.allowed_attributes

# Use additional_attributes to extend
config.additional_attributes = ['data-custom']

# Or use per-tag control
config.allowed_attributes_per_tag = {
  'div' => ['class', 'id', 'data-custom']
}
```

### Style tags are removed

**Enable style tags:**

```ruby
config.allow_style_tags = true

# For whole documents (like emails)
config.whole_document = true
```

### URI validation is too strict

**Customize URI validation:**

```ruby
# Allow more protocols
config.allowed_uri_regexp = /^(?:https?|ftp|mailto):/

# Or allow unknown protocols (⚠️ less secure)
config.allow_unknown_protocols = true
```

### Performance is slow

**Optimize configuration:**

```ruby
# Use specific allowlists
config.allowed_tags = ['p', 'strong', 'em']  # faster than nil/defaults

# Reduce multi-pass iterations for trusted content
config.mutation_max_passes = 1  # default is 2

# Disable multi-pass for pre-validated content  
config.sanitize_until_stable = false  # use with caution
```

## 🤝 Contributing

We welcome contributions! Here's how to get involved:

### Development Setup

```bash
# Clone the repository
git clone https://github.com/kuyio/scrubber.git
cd scrubber

# Install dependencies
bundle install

# Run tests
make test

# Run linter
make lint

# Open console
bin/console
```

### Running Tests

```bash
# All tests
rake spec

# With coverage
COVERAGE=true rake spec

# Specific test file
rspec spec/basic_sanitization_spec.rb

# Performance tests
ruby spec/scrubber_performance_spec.rb
```

### Contribution Guidelines

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Write** tests for your changes
4. **Ensure** all tests pass (`rake spec`)
5. **Update** documentation as needed
6. **Commit** your changes (`git commit -am 'Add amazing feature'`)
7. **Push** to the branch (`git push origin feature/amazing-feature`)
8. **Open** a Pull Request

### Development Guidelines

- **Security First**: All changes must maintain or improve security
- **Backward Compatibility**: Avoid breaking changes when possible
- **Comprehensive Tests**: New features need full test coverage (aim for 100%)
- **Documentation**: Update README and inline YARD docs for API changes
- **Performance**: Consider performance impact of changes
- **Code Quality**: Follow Ruby best practices and existing code style

### Reporting Issues

Found a bug or have a feature request?

1. **Search** existing issues to avoid duplicates
2. **Include** relevant details:
   - Ruby version
   - Scrubber version
   - Minimal reproduction code
   - Expected vs. actual behavior
3. **Security issues**: Email security@kuyio.com instead of filing public issues

## 📄 License

This gem is available as open source under the terms of the **Apache License 2.0** and **Mozilla Public License 2.0**.

## 🙏 Acknowledgments

Originally inspired by the excellent [DOMPurify](https://github.com/cure53/DOMPurify) JavaScript library by Cure53 and contributors. Scrubber brings DOMPurify's battle-tested security model to the Ruby ecosystem with an idiomatic Ruby API.

Special thanks to all [contributors](https://github.com/kuyio/scrubber/graphs/contributors) who have helped make Scrubber better!

---

**Made with ❤️ in Ottawa, Canada 🇨🇦** • [GitHub](https://github.com/kuyio/scrubber) • [Documentation](https://rubydoc.info/gems/scrubber)
