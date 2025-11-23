# frozen_string_literal: true

require 'rspec'
require 'scrubber'

RSpec.describe Scrubber do
  let(:scrubber) { described_class.new }

  describe '.set_config' do
    it 'allows customizing allowed tags' do
      scrubber.set_config(allowed_tags: %w[p b])
      clean = scrubber.sanitize('<p><b>Bold</b> <i>Italic</i></p>')
      expect(clean).to include('<p><b>Bold</b>  </p>')
      expect(clean).not_to include('<i>')
    end

    it 'allows customizing allowed attributes' do
      scrubber.set_config(allowed_attributes: ['class'])
      clean = scrubber.sanitize('<div class="test" id="test">Content</div>')
      expect(clean).to include('class="test')
      expect(clean).not_to include('id="test')
    end
  end

  describe 'Comprehensive Configuration Options' do
    describe 'allowed_tags configuration' do
      it 'restricts to only allowed tags' do
        scrubber.set_config(allowed_tags: %w[p strong])
        dirty = '<p><strong>Bold</strong> <em>italic</em> <u>underline</u></p>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('<p><strong>Bold</strong>    </p>')
        expect(clean).not_to include('<em>')
        expect(clean).not_to include('<u>')
      end

      it 'allows custom tags' do
        scrubber.set_config(allowed_tags: %w[custom-tag])
        dirty = '<custom-tag>Custom content</custom-tag><p>Paragraph</p>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('<custom-tag>Custom content</custom-tag>')
        expect(clean).not_to include('<p>')
      end

      it 'handles empty allowed_tags' do
        scrubber.set_config(allowed_tags: [])
        dirty = '<p>Paragraph</p><div>Division</div>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to eq('  ')
      end
    end

    describe 'forbidden_tags configuration' do
      it 'removes forbidden tags while keeping others' do
        scrubber.set_config(forbidden_tags: %w[script style])
        dirty = '<p>Paragraph</p><script>alert("xss")</script><style>body{color:red}</style><div>Division</div>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('<p>Paragraph</p>')
        expect(clean).to include('<div>Division</div>')
        expect(clean).not_to include('<script')
        expect(clean).not_to include('<style')
      end
    end

    describe 'allowed_attributes configuration' do
      it 'restricts to only allowed attributes' do
        scrubber.set_config(allowed_attributes: %w[class id], allow_data_attributes: false)
        dirty = '<div class="test" id="test" data-value="123" onclick="alert()">Content</div>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('class="test"')
        expect(clean).to include('id="test"')
        expect(clean).not_to include('data-value')
        expect(clean).not_to include('onclick')
      end

      it 'allows custom attributes' do
        scrubber.set_config(allowed_attributes: %w[custom-attr], allow_data_attributes: false)
        dirty = '<div custom-attr="value" class="test">Content</div>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('custom-attr="value"')
        expect(clean).not_to include('class')
      end
    end

    describe 'forbidden_attributes configuration' do
      it 'removes forbidden attributes while keeping others' do
        scrubber.set_config(forbidden_attributes: %w[onclick onload])
        dirty = '<div onclick="alert()" onload="alert()" class="test" id="test">Content</div>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('class="test"')
        expect(clean).to include('id="test"')
        expect(clean).not_to include('onclick')
        expect(clean).not_to include('onload')
      end
    end

    describe 'additional_tags configuration' do
      it 'adds additional allowed tags' do
        scrubber.set_config(additional_tags: %w[custom-tag])
        dirty = '<p>Paragraph</p><custom-tag>Custom</custom-tag>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('<p>Paragraph</p>')
        expect(clean).to include('<custom-tag>Custom</custom-tag>')
      end
    end

    describe 'additional_attributes configuration' do
      it 'adds additional allowed attributes' do
        scrubber.set_config(use_profiles: { html: true }, additional_attributes: %w[custom-attr])
        dirty = '<div custom-attr="value" class="test">Content</div>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('custom-attr="value"')
        expect(clean).to include('class="test"')
      end
    end

    describe 'whole_document configuration' do
      it 'processes entire HTML document' do
        dirty = '<!DOCTYPE html><html><head><title>Test</title></head><body><p>Content</p></body></html>'
        clean = scrubber.sanitize(dirty, whole_document: true)
        expect(clean).to include('<!DOCTYPE html>')
        expect(clean).to include('<html>')
        expect(clean).to include('<head>')
        expect(clean).to include('<title>Test</title>')
        expect(clean).to include('<body>')
        expect(clean).to include('<p>Content</p>')
      end

      it 'drops document-level elements by default when not whole_document' do
        dirty = '<html><head><title>Test</title></head><body><p>Content</p></body></html>'
        clean = scrubber.sanitize(dirty)
        expect(clean).not_to include('<html>')
        expect(clean).not_to include('<head>')
        expect(clean).not_to include('<body')
        expect(clean).to include('<p>Content</p>')
      end

      it 'allows document-level elements when explicitly enabled' do
        dirty = '<html><head><title>Test</title></head><body><p>Content</p></body></html>'
        clean = scrubber.sanitize(dirty, allow_document_elements: true)
        expect(clean).to include('<html>')
        expect(clean).to include('<head>')
        expect(clean).to include('<body')
      end
    end

    describe 'force_body configuration' do
      it 'forces body context for fragments' do
        dirty = '<p>Content</p>'
        clean = scrubber.sanitize(dirty, force_body: true)
        expect(clean).to include('<p>Content</p>')
      end
    end

    describe 'keep_content configuration' do
      it 'keeps content when removing tags' do
        dirty = '<p>Paragraph content</p><script>alert("xss")</script>'
        clean = scrubber.sanitize(dirty, keep_content: true)
        expect(clean).to include('<p>Paragraph content</p>')
        expect(clean).not_to include('<script')
        expect(clean).not_to include('alert')
      end

      it 'removes content when keep_content is false' do
        dirty = '<p>Paragraph content</p><script>alert("xss")</script>'
        clean = scrubber.sanitize(dirty, keep_content: false)
        expect(clean).to include('<p>Paragraph content</p>')
        expect(clean).not_to include('alert')
      end
    end

    describe 'namespace configuration' do
      it 'handles custom namespaces' do
        dirty = '<div xmlns="http://www.w3.org/1999/xhtml">Content</div>'
        clean = scrubber.sanitize(dirty, namespace: 'http://www.w3.org/1999/xhtml')
        expect(clean).to include('<div')
        expect(clean).to include('Content')
      end
    end

    describe 'parser_media_type configuration' do
      it 'handles XHTML parsing' do
        dirty = '<div>Content</div>'
        clean = scrubber.sanitize(dirty, parser_media_type: 'application/xhtml+xml')
        expect(clean).to include('<div')
        expect(clean).to include('Content')
      end
    end

    describe 'allowed_uri_regexp configuration' do
      it 'validates URIs against custom regex' do
        custom_regexp = %r{^https?://example\.com/}
        scrubber.set_config(allowed_uri_regexp: custom_regexp)
        dirty = '<a href="https://example.com/path">Good</a><a href="https://evil.com/path">Bad</a>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('href="https://example.com/path"')
        expect(clean).not_to include('href="https://evil.com/path"')
      end

      it 'handles case-insensitive regex' do
        custom_regexp = %r{^https?://example\.com/}i
        scrubber.set_config(allowed_uri_regexp: custom_regexp)
        dirty = '<a href="HTTPS://EXAMPLE.COM/PATH">Good</a>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('href="HTTPS://EXAMPLE.COM/PATH"')
      end

      it 'handles complex regex patterns' do
        # Allow only specific paths on a domain
        custom_regexp = %r{^https://example\.com/(api|static)/}
        scrubber.set_config(allowed_uri_regexp: custom_regexp)
        dirty = '<a href="https://example.com/api/v1">API</a><a href="https://example.com/admin">Admin</a>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('href="https://example.com/api/v1"')
        expect(clean).not_to include('href="https://example.com/admin"')
      end
    end

    describe 'namespace configuration' do
      it 'handles custom namespaces' do
        dirty = '<div xmlns="http://www.w3.org/1999/xhtml">Content</div>'
        clean = scrubber.sanitize(dirty, namespace: 'http://www.w3.org/1999/xhtml')
        expect(clean).to include('<div')
        expect(clean).to include('Content')
      end

      it 'switches namespaces correctly' do
        # Test that we can sanitize SVG with correct namespace config
        dirty = '<svg><rect/></svg>'
        clean = scrubber.sanitize(dirty, namespace: 'http://www.w3.org/2000/svg')
        expect(clean).to include('<svg')
        expect(clean).to include('<rect')
      end

      it 'handles MathML namespace' do
        dirty = '<math><mi>x</mi></math>'
        clean = scrubber.sanitize(dirty, namespace: 'http://www.w3.org/1998/Math/MathML')
        expect(clean).to include('<math')
        expect(clean).to include('<mi>x</mi>')
      end
    end

    describe 'allow_unknown_protocols configuration' do
      it 'allows unknown protocols when enabled' do
        dirty = '<a href="custom://example.com">Link</a>'
        clean = scrubber.sanitize(dirty, allow_unknown_protocols: true)
        expect(clean).to include('href="custom://example.com"')
      end

      it 'blocks unknown protocols when disabled' do
        dirty = '<a href="custom://example.com">Link</a>'
        clean = scrubber.sanitize(dirty, allow_unknown_protocols: false)
        expect(clean).not_to include('href="custom://example.com"')
      end
    end

    describe 'add_data_uri_tags configuration' do
      it 'allows data URIs in additional tags' do
        scrubber.set_config(add_data_uri_tags: %w[div])
        # rubocop:disable Layout/LineLength
        dirty = '<div style="background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==)">Content</div>'
        # rubocop:enable Layout/LineLength
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('<div')
        expect(clean).to include('Content')
      end
    end

    describe 'add_uri_safe_attr configuration' do
      it 'marks additional attributes as URI-safe' do
        scrubber.set_config(use_profiles: { html: true }, add_uri_safe_attr: %w[custom-href],
          additional_attributes: %w[custom-href])
        dirty = '<div custom-href="https://example.com">Content</div>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('custom-href="https://example.com"')
      end
    end

    describe 'forbid_contents configuration' do
      it 'removes content of forbidden elements' do
        scrubber.set_config(forbid_contents: %w[script])
        dirty = '<script>alert("xss")</script><p>Safe content</p>'
        clean = scrubber.sanitize(dirty)
        expect(clean).not_to include('alert')
        expect(clean).to include('<p>Safe content</p>')
      end
    end

    describe 'custom_element_handling configuration' do
      it 'handles custom elements' do
        scrubber.set_config(additional_tags: %w[custom-element])
        dirty = '<custom-element>Content</custom-element>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('<custom-element>Content</custom-element>')
      end
    end

    describe 'custom elements and trusted types' do
      it 'preserves safe custom elements while sanitizing attributes' do
        scrubber.set_config(additional_tags: %w[custom-element])
        dirty = '<custom-element onclick="alert(1)" data-safe="ok">Hi</custom-element>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('<custom-element')
        expect(clean).to include('data-safe="ok"')
        expect(clean).not_to include('onclick')
      end
    end

    describe 'return_dom configuration' do
      it 'returns DOM when enabled' do
        dirty = '<div>Content</div>'
        result = scrubber.sanitize(dirty, return_dom: true)
        expect(result).to be_a(Nokogiri::HTML5::Document)
        expect(result.to_html).to include('<div')
        expect(result.to_html).to include('Content')
      end
    end

    describe 'return_dom_fragment configuration' do
      it 'returns DOM fragment when enabled' do
        dirty = '<div>Content</div>'
        result = scrubber.sanitize(dirty, return_dom_fragment: true)
        expect(result).to be_a(Nokogiri::HTML5::DocumentFragment)
        expect(result.to_html).to include('<div')
        expect(result.to_html).to include('Content')
      end
    end

    describe 'in_place configuration' do
      it 'modifies input in place when enabled' do
        dirty = '<div>Content</div>'
        result = scrubber.sanitize(dirty, in_place: true)
        expect(result).to eq(dirty)
      end
    end
  end
end
