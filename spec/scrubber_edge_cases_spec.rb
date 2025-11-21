# frozen_string_literal: true

require 'rspec'
require 'scrubber'

RSpec.describe Scrubber do
  let(:scrubber) { described_class.new }

  describe 'Edge Cases and Malformed HTML' do
    describe 'unclosed tags' do
      it 'handles unclosed tags gracefully' do
        dirty = '<div><p>Paragraph text<div>Another div'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('<div><p>Paragraph text</p><div>Another div</div></div>')
      end
    end

    describe 'improperly nested tags' do
      it 'handles improperly nested tags' do
        dirty = '<b><i>Bold and italic</b></i>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('<b><i>Bold and italic</i></b>')
      end
    end

    describe 'malformed attributes' do
      it 'handles attributes without values' do
        dirty = '<input disabled checked readonly>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('<input')
      end

      it 'handles attributes with unquoted values' do
        dirty = '<div class=test>Content</div>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('class="test"')
      end

      it 'handles attributes with special characters' do
        dirty = '<div title="Test with &quot;quotes&quot; and &lt;angles&gt;">Content</div>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('title')
        expect(clean).to include('Content')
      end
    end

    describe 'invalid HTML entities' do
      it 'handles invalid entities gracefully' do
        dirty = '<p>Invalid entity: &unknown;</p>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('<p>Invalid entity: &unknown;</p>')
      end

      it 'handles numeric entities' do
        dirty = '<p>Numeric entity: &#65;</p>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('<p>Numeric entity: A</p>')
      end
    end

    describe 'unicode and encoding issues' do
      it 'handles unicode characters' do
        dirty = '<div>Unicode: 🚀 ñáéíóú 中文</div>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('Unicode: 🚀 ñáéíóú 中文')
      end

      it 'handles mixed encoding' do
        dirty = '<div>Mixed: &#x1F600; 😀</div>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('Mixed: 😀 😀')
      end
    end

    describe 'large input handling' do
      it 'handles very large HTML strings' do
        large_content = "<p>#{'Test content. ' * 10_000}</p>"
        clean = scrubber.sanitize(large_content)
        expect(clean).to include('<p>')
        expect(clean).to include('Test content.')
      end
    end

    describe 'empty and whitespace input' do
      it 'handles nil input' do
        expect(scrubber.sanitize(nil)).to eq('')
      end

      it 'handles empty string' do
        expect(scrubber.sanitize('')).to eq('')
      end

      it 'handles whitespace only' do
        expect(scrubber.sanitize('   ')).to eq('   ')
      end
    end

    describe 'nested elements' do
      it 'handles deeply nested elements' do
        dirty = "<div>#{'<span>' * 100}Deep content#{'</span>' * 100}</div>"
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('Deep content')
      end
    end

    describe 'special characters in content' do
      it 'preserves special characters in text content' do
        dirty = '<p>Special chars: &lt; &gt; &amp; " \'</p>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('<p>Special chars: &lt; &gt; &amp; " \'</p>')
      end
    end

    describe 'HTML comments' do
      it 'removes HTML comments by default' do
        dirty = '<!-- This is a comment --><p>Visible content</p>'
        clean = scrubber.sanitize(dirty)
        expect(clean).not_to include('<!--')
        expect(clean).to include('<p>Visible content</p>')
      end

      it 'handles conditional comments' do
        dirty = '<!--[if IE]>Special content<![endif]--><p>Normal content</p>'
        clean = scrubber.sanitize(dirty)
        expect(clean).not_to include('<!--[if IE]')
        expect(clean).to include('<p>Normal content</p>')
      end
    end

    describe 'DOCTYPE declarations' do
      it 'handles DOCTYPE in whole document mode' do
        dirty = '<!DOCTYPE html><html><head></head><body><p>Content</p></body></html>'
        clean = scrubber.sanitize(dirty, whole_document: true)
        expect(clean).to include('<!DOCTYPE html>')
        expect(clean).to include('<p>Content</p>')
      end
    end

    describe 'XML declarations' do
      it 'handles XML declarations' do
        dirty = '<?xml version="1.0" encoding="UTF-8"?><root>Content</root>'
        clean = scrubber.sanitize(dirty)
        expect(clean).to include('Content')
      end
    end

    describe 'mutation XSS resilience' do
      it 'performs at least two passes by default' do
        count = 0
        scrubber.add_hook(:before_sanitize_elements) { |_node, _data, _config| count += 1 }
        dirty = '<div><script>alert(1)</script><style>body{color:black}</style></div>'
        scrubber.sanitize(dirty)
        expect(count).to be >= 2
        scrubber.remove_all_hooks
      end

      it 'stabilizes mutated SVG payloads across passes' do
        dirty = '<svg><foreignObject><body><svg><script>alert(1)</script></svg></body></foreignObject></svg>'
        clean = scrubber.sanitize(dirty, sanitize_until_stable: true, mutation_max_passes: 3)
        second_pass = scrubber.sanitize(clean, sanitize_until_stable: true, mutation_max_passes: 3)
        expect(clean).to eq(second_pass)
        expect(clean).not_to include('<script')
      end

      it 'allows disabling stabilization with pass_limit 0' do
        count = 0
        scrubber.add_hook(:before_sanitize_elements) { |_node, _data, _config| count += 1 }
        dirty = '<div><script>alert(1)</script></div>'
        scrubber.sanitize(dirty, sanitize_until_stable: true, pass_limit: 0)
        expect(count).to eq(1)
        scrubber.remove_all_hooks
      end
    end
  end
end
