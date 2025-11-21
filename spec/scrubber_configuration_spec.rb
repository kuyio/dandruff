# frozen_string_literal: true

require 'rspec'
require 'scrubber'

RSpec.describe Scrubber do
  describe '.set_config' do
    it 'allows customizing allowed tags' do
      described_class.set_config(allowed_tags: %w[p b])
      clean = described_class.sanitize('<p><b>Bold</b> <i>Italic</i></p>')
      expect(clean).to include('<p><b>Bold</b>  </p>')
      expect(clean).not_to include('<i>')
      described_class.clear_config
    end

    it 'allows customizing allowed attributes' do
      described_class.set_config(allowed_attributes: ['class'])
      clean = described_class.sanitize('<div class="test" id="test">Content</div>')
      expect(clean).to include('class="test')
      expect(clean).not_to include('id="test')
      described_class.clear_config
    end
  end

  describe 'Comprehensive Configuration Options' do
    before do
      described_class.clear_config
    end
    describe 'allowed_tags configuration' do
      it 'restricts to only allowed tags' do
        described_class.set_config(allowed_tags: %w[p strong])
        dirty = '<p><strong>Bold</strong> <em>italic</em> <u>underline</u></p>'
        clean = described_class.sanitize(dirty)
        expect(clean).to include('<p><strong>Bold</strong>    </p>')
        expect(clean).not_to include('<em>')
        expect(clean).not_to include('<u>')
        described_class.clear_config
      end

      it 'allows custom tags' do
        described_class.set_config(allowed_tags: %w[custom-tag])
        dirty = '<custom-tag>Custom content</custom-tag><p>Paragraph</p>'
        clean = described_class.sanitize(dirty)
        expect(clean).to include('<custom-tag>Custom content</custom-tag>')
        expect(clean).not_to include('<p>')
        described_class.clear_config
      end

      it 'handles empty allowed_tags' do
        described_class.set_config(allowed_tags: [])
        dirty = '<p>Paragraph</p><div>Division</div>'
        clean = described_class.sanitize(dirty)
        expect(clean).to eq('  ')
        described_class.clear_config
      end
    end

    describe 'forbidden_tags configuration' do
      it 'removes forbidden tags while keeping others' do
        described_class.set_config(forbidden_tags: %w[script style])
        dirty = '<p>Paragraph</p><script>alert("xss")</script><style>body{color:red}</style><div>Division</div>'
        clean = described_class.sanitize(dirty)
        expect(clean).to include('<p>Paragraph</p>')
        expect(clean).to include('<div>Division</div>')
        expect(clean).not_to include('<script')
        expect(clean).not_to include('<style')
        described_class.clear_config
      end
    end

    describe 'allowed_attributes configuration' do
      it 'restricts to only allowed attributes' do
        described_class.set_config(allowed_attributes: %w[class id])
        dirty = '<div class="test" id="test" data-value="123" onclick="alert()">Content</div>'
        clean = described_class.sanitize(dirty)
        expect(clean).to include('class="test"')
        expect(clean).to include('id="test"')
        expect(clean).not_to include('data-value')
        expect(clean).not_to include('onclick')
        described_class.clear_config
      end

      it 'allows custom attributes' do
        described_class.set_config(allowed_attributes: %w[custom-attr])
        dirty = '<div custom-attr="value" class="test">Content</div>'
        clean = described_class.sanitize(dirty)
        expect(clean).to include('custom-attr="value"')
        expect(clean).not_to include('class')
        described_class.clear_config
      end
    end

    describe 'forbidden_attributes configuration' do
      it 'removes forbidden attributes while keeping others' do
        described_class.set_config(forbidden_attributes: %w[onclick onload])
        dirty = '<div onclick="alert()" onload="alert()" class="test" id="test">Content</div>'
        clean = described_class.sanitize(dirty)
        expect(clean).to include('class="test"')
        expect(clean).to include('id="test"')
        expect(clean).not_to include('onclick')
        expect(clean).not_to include('onload')
        described_class.clear_config
      end
    end

    describe 'additional_tags configuration' do
      it 'adds additional allowed tags' do
        described_class.set_config(additional_tags: %w[custom-tag])
        dirty = '<p>Paragraph</p><custom-tag>Custom</custom-tag>'
        clean = described_class.sanitize(dirty)
        expect(clean).to include('<p>Paragraph</p>')
        expect(clean).to include('<custom-tag>Custom</custom-tag>')
        described_class.clear_config
      end
    end

    describe 'additional_attributes configuration' do
      it 'adds additional allowed attributes' do
        described_class.set_config(additional_attributes: %w[custom-attr])
        dirty = '<div custom-attr="value" class="test">Content</div>'
        clean = described_class.sanitize(dirty)
        expect(clean).to include('custom-attr="value"')
        expect(clean).to include('class="test"')
        described_class.clear_config
      end
    end

    describe 'whole_document configuration' do
      it 'processes entire HTML document' do
        dirty = '<!DOCTYPE html><html><head><title>Test</title></head><body><p>Content</p></body></html>'
        clean = described_class.sanitize(dirty, whole_document: true)
        expect(clean).to include('<!DOCTYPE html>')
        expect(clean).to include('<html>')
        expect(clean).to include('<head>')
        expect(clean).to include('<title>Test</title>')
        expect(clean).to include('<body>')
        expect(clean).to include('<p>Content</p>')
      end

      it 'drops document-level elements by default when not whole_document' do
        dirty = '<html><head><title>Test</title></head><body><p>Content</p></body></html>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<html>')
        expect(clean).not_to include('<head>')
        expect(clean).not_to include('<body')
        expect(clean).to include('<p>Content</p>')
      end

      it 'allows document-level elements when explicitly enabled' do
        dirty = '<html><head><title>Test</title></head><body><p>Content</p></body></html>'
        clean = described_class.sanitize(dirty, allow_document_elements: true)
        expect(clean).to include('<html>')
        expect(clean).to include('<head>')
        expect(clean).to include('<body')
      end
    end

    describe 'force_body configuration' do
      it 'forces body context for fragments' do
        dirty = '<p>Content</p>'
        clean = described_class.sanitize(dirty, force_body: true)
        expect(clean).to include('<p>Content</p>')
      end
    end

    describe 'keep_content configuration' do
      it 'keeps content when removing tags' do
        dirty = '<p>Paragraph content</p><script>alert("xss")</script>'
        clean = described_class.sanitize(dirty, keep_content: true)
        expect(clean).to include('<p>Paragraph content</p>')
        expect(clean).not_to include('<script')
        expect(clean).not_to include('alert')
      end

      it 'removes content when keep_content is false' do
        dirty = '<p>Paragraph content</p><script>alert("xss")</script>'
        clean = described_class.sanitize(dirty, keep_content: false)
        expect(clean).to include('<p>Paragraph content</p>')
        expect(clean).not_to include('alert')
      end
    end

    describe 'namespace configuration' do
      it 'handles custom namespaces' do
        dirty = '<div xmlns="http://www.w3.org/1999/xhtml">Content</div>'
        clean = described_class.sanitize(dirty, namespace: 'http://www.w3.org/1999/xhtml')
        expect(clean).to include('<div')
        expect(clean).to include('Content')
      end
    end

    describe 'parser_media_type configuration' do
      it 'handles XHTML parsing' do
        dirty = '<div>Content</div>'
        clean = described_class.sanitize(dirty, parser_media_type: 'application/xhtml+xml')
        expect(clean).to include('<div')
        expect(clean).to include('Content')
      end
    end

    describe 'allowed_uri_regexp configuration' do
      it 'validates URIs against custom regexp' do
        custom_regexp = %r{^https?://example\.com/}
        described_class.set_config(allowed_uri_regexp: custom_regexp)
        dirty = '<a href="https://example.com/path">Good</a><a href="https://evil.com/path">Bad</a>'
        clean = described_class.sanitize(dirty)
        expect(clean).to include('href="https://example.com/path"')
        expect(clean).not_to include('href="https://evil.com/path"')
        described_class.clear_config
      end
    end

    describe 'allow_unknown_protocols configuration' do
      it 'allows unknown protocols when enabled' do
        dirty = '<a href="custom://example.com">Link</a>'
        clean = described_class.sanitize(dirty, allow_unknown_protocols: true)
        expect(clean).to include('href="custom://example.com"')
      end

      it 'blocks unknown protocols when disabled' do
        dirty = '<a href="custom://example.com">Link</a>'
        clean = described_class.sanitize(dirty, allow_unknown_protocols: false)
        expect(clean).not_to include('href="custom://example.com"')
      end
    end

    describe 'add_data_uri_tags configuration' do
      it 'allows data URIs in additional tags' do
        described_class.set_config(add_data_uri_tags: %w[div])
        # rubocop:disable Layout/LineLength
        dirty = '<div style="background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==)">Content</div>'
        # rubocop:enable Layout/LineLength
        clean = described_class.sanitize(dirty)
        expect(clean).to include('<div')
        expect(clean).to include('Content')
        described_class.clear_config
      end
    end

    describe 'add_uri_safe_attr configuration' do
      it 'marks additional attributes as URI-safe' do
        described_class.set_config(add_uri_safe_attr: %w[custom-href])
        dirty = '<div custom-href="https://example.com">Content</div>'
        clean = described_class.sanitize(dirty)
        expect(clean).to include('custom-href="https://example.com"')
        described_class.clear_config
      end
    end

    describe 'forbid_contents configuration' do
      it 'removes content of forbidden elements' do
        described_class.set_config(forbid_contents: %w[script])
        dirty = '<script>alert("xss")</script><p>Safe content</p>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('alert')
        expect(clean).to include('<p>Safe content</p>')
        described_class.clear_config
      end
    end

    describe 'custom_element_handling configuration' do
      it 'handles custom elements' do
        dirty = '<custom-element>Content</custom-element>'
        clean = described_class.sanitize(dirty)
        expect(clean).to include('<custom-element>Content</custom-element>')
      end
    end

    describe 'custom elements and trusted types' do
      it 'preserves safe custom elements while sanitizing attributes' do
        dirty = '<custom-element onclick="alert(1)" data-safe="ok">Hi</custom-element>'
        clean = described_class.sanitize(dirty)
        expect(clean).to include('<custom-element')
        expect(clean).to include('data-safe="ok"')
        expect(clean).not_to include('onclick')
      end
    end

    describe 'return_dom configuration' do
      it 'returns DOM when enabled' do
        dirty = '<div>Content</div>'
        result = described_class.sanitize(dirty, return_dom: true)
        expect(result).to be_a(Nokogiri::HTML5::Document)
        expect(result.to_html).to include('<div')
        expect(result.to_html).to include('Content')
      end
    end

    describe 'return_dom_fragment configuration' do
      it 'returns DOM fragment when enabled' do
        dirty = '<div>Content</div>'
        result = described_class.sanitize(dirty, return_dom_fragment: true)
        expect(result).to be_a(Nokogiri::HTML5::DocumentFragment)
        expect(result.to_html).to include('<div')
        expect(result.to_html).to include('Content')
      end
    end

    describe 'in_place configuration' do
      it 'modifies input in place when enabled' do
        dirty = '<div>Content</div>'
        result = described_class.sanitize(dirty, in_place: true)
        expect(result).to eq(dirty)
      end
    end
  end
end
