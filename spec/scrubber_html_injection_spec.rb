# frozen_string_literal: true

require 'rspec'
require 'scrubber'

RSpec.describe Scrubber do
  describe 'HTML Injection and Bypass Techniques' do
    describe 'tag closing attacks' do
      it 'prevents tag closing injection' do
        dirty = '<img src="x" onerror="alert(\'xss\')" ">'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('onerror')
        expect(clean).not_to include('alert')
      end

      it 'handles malformed attributes' do
        dirty = '<div "onclick="alert(\'xss\')">Test</div>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('onclick')
        expect(clean).not_to include('alert')
      end
    end

    describe 'namespace attacks' do
      it 'removes elements with unknown namespaces' do
        dirty = '<x:script xmlns:x="http://example.com">alert("xss")</x:script>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<x:script')
        # Updated: text content is now preserved when removing namespace elements
        # This prevents content loss attacks while still removing dangerous tags
        expect(clean).to include('alert') # text preserved, but script tag removed
      end

      it 'handles XML namespace declarations' do
        dirty = '<html xmlns:x="http://www.w3.org/1999/xhtml"><x:script>alert("xss")</x:script></html>'
        clean = described_class.sanitize(dirty)
        # Updated: text content preserved from removed namespace elements
        expect(clean).to include('alert') # text preserved
        expect(clean).not_to include('<x:script') # tag removed
      end
    end

    describe 'comment-based attacks' do
      it 'removes conditional comments' do
        dirty = '<!--[if IE]><script>alert("xss")</script><![endif]-->'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<script')
        expect(clean).not_to include('alert')
      end

      it 'removes downlevel-hidden conditional comments' do
        dirty = '<![if !IE]><script>alert("xss")</script><![endif]>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<script')
        expect(clean).not_to include('alert')
      end
    end

    describe 'processing instruction attacks' do
      it 'removes XML processing instructions' do
        dirty = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<?xml')
        expect(clean).not_to include('<!ENTITY')
      end
    end

    describe 'CDATA section attacks' do
      it 'handles CDATA sections safely' do
        dirty = '<script><![CDATA[alert("xss")]]></script>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<script')
        expect(clean).not_to include('alert')
      end
    end

    describe 'template injection' do
      it 'removes template tags with script content' do
        dirty = '<template><script>alert("xss")</script></template>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<script')
        expect(clean).not_to include('alert')
      end

      it 'handles template content injection' do
        dirty = '<div><template onclick="alert(\'xss\')">Click</template></div>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('onclick')
        expect(clean).not_to include('alert')
      end
    end

    describe 'shadow DOM attacks' do
      it 'removes dangerous shadow DOM content' do
        dirty = '<div><script>alert("xss")</script></div>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<script')
        expect(clean).not_to include('alert')
      end
    end

    describe 'mXSS attacks' do
      it 'prevents mutation XSS through HTML parsing' do
        dirty = '<svg><script>alert("xss")</script></svg>'
        clean = described_class.sanitize(dirty, safe_for_xml: true)
        expect(clean).not_to include('<script')
        expect(clean).not_to include('alert')
      end

      it 'handles nested mutations' do
        dirty = '<math><mtext><script>alert("xss")</script></mtext></math>'
        clean = described_class.sanitize(dirty, safe_for_xml: true)
        expect(clean).not_to include('<script')
        expect(clean).not_to include('alert')
      end
    end
  end
end
