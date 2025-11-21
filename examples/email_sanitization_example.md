# HTML Email Sanitization Example

This example demonstrates how to use Scrubber to safely sanitize HTML emails for display, protecting against XSS while preserving formatting.

## Use Case

When displaying HTML emails from external sources in a web application, you need to:
- Remove malicious scripts and XSS payloads
- Preserve email formatting (tables, styling, links)
- Allow safe email content like images and basic formatting
- Prevent iframe escape attempts

## Implementation

```ruby
require 'scrubber'

class EmailSanitizer
  def self.sanitize_for_iframe(html_content)
    # Configure Scrubber for email content
    scrubber = Scrubber.new do |c|
      # Allow email-specific tags
      c.allowed_tags = [
        # Basic formatting
        'p', 'br', 'div', 'span',
        # Text formatting
        'strong', 'b', 'em', 'i', 'u', 's', 'strike',
        # Headings
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        # Lists
        'ul', 'ol', 'li', 'dl', 'dt', 'dd',
        # Tables (essential for emails)
        'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'caption',
        # Links and images
        'a', 'img',
        # Block elements
        'blockquote', 'hr', 'pre', 'code',
        # Email-specific
        'font', 'center'
      ]

      # Allow safe attributes
      c.allowed_attributes = [
        # Links
        'href', 'title', 'target',
        # Images
        'src', 'alt', 'width', 'height', 'border',
        # Tables
        'cellpadding', 'cellspacing', 'colspan', 'rowspan', 'align', 'valign',
        # Text formatting
        'color', 'size', 'face', 'style', 'class',
        # Lists
        'type', 'start',
        # General
        'id', 'dir'
      ]

      # Security settings
      c.forbidden_tags = ['script', 'iframe', 'object', 'embed', 'form', 'input', 'button']
      c.forbidden_attributes = ['onclick', 'onload', 'onerror', 'onmouseover', 'javascript:']

      # Allow data attributes for tracking (optional)
      c.allow_data_attributes = true

      # Allow ARIA attributes for accessibility
      c.allow_aria_attributes = true

      # Safe for templates (remove template expressions)
      c.safe_for_templates = true

      # Keep comments for email client compatibility
      c.safe_for_xml = false

      # Don't return whole document (we want fragment)
      c.whole_document = false
    end

    # Add hooks for additional security
    add_email_security_hooks(scrubber)

    # Sanitize the email content
    clean_html = scrubber.sanitize(html_content)

    # Post-process for iframe safety
    post_process_for_iframe(clean_html)
  end

  private

  def self.add_email_security_hooks(scrubber)
    # Hook to sanitize URLs
    scrubber.add_hook(:upon_sanitize_attribute) do |node, data, config|
      case data[:attr_name]
      when 'href'
        # Block dangerous protocols
        href = data[:value]
        if href.match?(/\b(javascript|data|vbscript):/i)
          data[:keep_attr] = false
        end
      when 'src'
        # Only allow http/https protocols for images
        src = data[:value]
        unless src.match?(/\b(https?):/i)
          data[:keep_attr] = false
        end
      when 'style'
        # Remove dangerous CSS
        style = data[:value]
        if style.match?(/(expression|javascript|behavior|import)/i)
          data[:keep_attr] = false
        end
      end
    end

    # Hook to process table elements
    scrubber.add_hook(:before_sanitize_elements) do |node, data, config|
      # Remove tables with excessive nesting (potential DoS)
      if node.name == 'table'
        depth = count_table_depth(node)
        if depth > 10
          data[:keep_node] = false
        end
      end
    end
  end

  def self.count_table_depth(node, depth = 0)
    return depth if depth > 10

    max_depth = depth
    node.children.each do |child|
      if child.name == 'table'
        child_depth = count_table_depth(child, depth + 1)
        max_depth = [max_depth, child_depth].max
      end
    end

    max_depth
  end

  def self.post_process_for_iframe(html)
    # Add sandbox attributes if iframe will be used
    # This is typically done in the HTML template, but we document it here

    # Example iframe usage:
    # <iframe sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox"
    #         srcdoc="#{sanitized_html}">
    # </iframe>

    html
  end
end

# Usage example
class EmailController < ApplicationController
  def show
    # Get email from database or external source
    raw_email = Email.find(params[:id]).html_content

    # Sanitize for safe display
    @sanitized_email = EmailSanitizer.sanitize_for_iframe(raw_email)

    # Render with iframe
    # In your view:
    # <iframe sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox"
    #         srcdoc="#{@sanitized_email}"
    #         width="100%" height="600">
    # </iframe>
  end
end
```

## Security Considerations

### 1. **Iframe Sandbox Attributes**
```html
<iframe sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox"
        srcdoc="#{@sanitized_email}"
        width="100%" height="600">
</iframe>
```

### 2. **Content Security Policy**
```ruby
# In your Rails app or web server config
response.headers['Content-Security-Policy'] =
  "default-src 'self'; " \
  "img-src https: data:; " \
  "style-src 'unsafe-inline'; " \
  "script-src 'none';"
```

### 3. **Additional Protections**
- Rate limiting email processing
- File size limits for email content
- Virus scanning for attachments
- Logging of sanitization attempts

## Testing the Sanitizer

```ruby
# Test malicious content
malicious_email = <<~HTML
  <html>
    <body>
      <h1>Important Email</h1>
      <p>Click <a href="javascript:alert('XSS')">here</a> for prize!</p>
      <script>steal_data();</script>
      <iframe src="http://evil.com"></iframe>
      <table>
        <tr><td>Safe content</td></tr>
      </table>
      <img src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoJ1hTUyknPg==" />
    </body>
  </html>
HTML

sanitized = EmailSanitizer.sanitize_for_iframe(malicious_email)
puts sanitized
# => <h1>Important Email</h1><p>Click <a>here</a> for prize!</p><table><tbody><tr><td>Safe content</td></tr></tbody></table>
```

## Performance Considerations

- Cache sanitized emails when possible
- Process emails asynchronously for large volumes
- Monitor memory usage with large email attachments
- Consider streaming for very large email content

## Integration Examples

### Rails Integration
```ruby
# app/helpers/email_helper.rb
module EmailHelper
  def safe_email_iframe(email_content)
    sanitized = EmailSanitizer.sanitize_for_iframe(email_content)
    content_tag(:iframe, '',
                sandbox: 'allow-same-origin allow-popups allow-popups-to-escape-sandbox',
                srcdoc: sanitized,
                width: '100%',
                height: '600',
                style: 'border: 1px solid #ccc;')
  end
end

# In view:
# <%= safe_email_iframe(@email.html_content) %>
```

### Sinatra Integration
```ruby
# Email processing endpoint
post '/emails/sanitize' do
  content_type :json

  begin
    raw_html = request.body.read
    sanitized = EmailSanitizer.sanitize_for_iframe(raw_html)

    { success: true, html: sanitized }.to_json
  rescue => e
    { success: false, error: e.message }.to_json
  end
end
```

This example provides a comprehensive solution for safely displaying HTML emails in iframes while maintaining security and preserving email formatting.
