# frozen_string_literal: true

require 'rspec'
require 'scrubber'

RSpec.describe Scrubber do
  describe 'XSS Attack Vectors' do
    describe 'script tag variations' do
      it 'removes basic script tags' do
        dirty = '<script>alert("xss")</script>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<script>')
        expect(clean).not_to include('alert')
      end

      it 'removes script tags with attributes' do
        dirty = '<script src="evil.js" defer>alert("xss")</script>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<script')
        expect(clean).not_to include('src=')
        expect(clean).not_to include('alert')
      end

      it 'removes script tags with mixed case' do
        dirty = '<ScRiPt>alert("xss")</ScRiPt>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to match(/<script/i)
        expect(clean).not_to include('alert')
      end

      it 'removes script tags with encoding attempts' do
        dirty = '<script>&#97;&#108;&#101;&#114;&#116;&#40;&#34;&#120;&#115;&#115;&#34;&#41;</script>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<script')
      end
    end

    describe 'javascript protocol' do
      it 'removes javascript: URLs' do
        dirty = '<a href="javascript:alert(\'xss\')">Click me</a>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('javascript:')
        expect(clean).not_to include('alert')
      end

      it 'removes javascript: with variations' do
        dirty = '<img src="javascript:alert(\'xss\')">'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('javascript:')
        expect(clean).not_to include('alert')
      end

      it 'removes javascript: with encoding' do
        # rubocop:disable Layout/LineLength
        dirty = '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#120;&#115;&#115;&#39;&#41;">Link</a>'
        # rubocop:enable Layout/LineLength
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('alert')
      end
    end

    describe 'event handlers' do
      it 'removes onclick handlers' do
        dirty = '<div onclick="alert(\'xss\')">Click me</div>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('onclick')
        expect(clean).not_to include('alert')
      end

      it 'removes onload handlers' do
        dirty = '<img src="x" onload="alert(\'xss\')">'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('onload')
        expect(clean).not_to include('alert')
      end

      it 'removes onerror handlers' do
        dirty = '<img src="invalid" onerror="alert(\'xss\')">'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('onerror')
        expect(clean).not_to include('alert')
      end

      it 'removes various event handlers' do
        event_handlers = %w[onmouseover onmouseout onfocus onblur onchange onsubmit onreset]
        event_handlers.each do |handler|
          dirty = "<input #{handler}=\"alert('xss')\">"
          clean = described_class.sanitize(dirty)
          expect(clean).not_to include(handler)
          expect(clean).not_to include('alert')
        end
      end
    end

    describe 'data and object attacks' do
      it 'removes data URLs with script content' do
        dirty = '<object data="data:text/html,<script>alert(\'xss\')</script>"></object>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<object')
        expect(clean).not_to include('alert')
      end

      it 'removes embed tags with dangerous content' do
        dirty = '<embed src="javascript:alert(\'xss\')" type="text/html">'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<embed')
        expect(clean).not_to include('javascript:')
      end
    end

    describe 'form-based attacks' do
      it 'removes form action with javascript' do
        dirty = '<form action="javascript:alert(\'xss\')"><input type="submit"></form>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('javascript:')
        expect(clean).not_to include('alert')
      end

      it 'removes input formaction with javascript' do
        dirty = '<input type="submit" formaction="javascript:alert(\'xss\')">'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('formaction')
        expect(clean).not_to include('javascript:')
      end
    end

    describe 'meta and link attacks' do
      it 'removes meta refresh with javascript' do
        dirty = '<meta http-equiv="refresh" content="0;url=javascript:alert(\'xss\')">'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<meta')
        expect(clean).not_to include('javascript:')
      end

      it 'removes dangerous link tags' do
        dirty = '<link rel="stylesheet" href="javascript:alert(\'xss\')">'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<link')
        expect(clean).not_to include('javascript:')
      end
    end

    describe 'iframe and frame attacks' do
      it 'removes iframe tags' do
        dirty = '<iframe src="javascript:alert(\'xss\')"></iframe>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<iframe')
        expect(clean).not_to include('javascript:')
      end

      it 'removes frame tags' do
        dirty = '<frame src="javascript:alert(\'xss\')">'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<frame')
        expect(clean).not_to include('javascript:')
      end

      it 'removes frameset tags' do
        dirty = '<frameset><frame src="javascript:alert(\'xss\')"></frameset>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<frameset')
        expect(clean).not_to include('<frame')
      end
    end

    describe 'svg attacks' do
      it 'removes script tags in SVG' do
        dirty = '<svg><script>alert("xss")</script></svg>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<script')
        expect(clean).not_to include('alert')
      end

      it 'removes event handlers in SVG' do
        dirty = '<svg><circle onclick="alert(\'xss\')" r="10"/></svg>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('onclick')
        expect(clean).not_to include('alert')
      end

      it 'removes foreignObject with HTML' do
        dirty = '<svg><foreignObject><body><script>alert("xss")</script></body></foreignObject></svg>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<script')
        expect(clean).not_to include('alert')
      end
    end

    describe 'mathml attacks' do
      it 'removes script tags in MathML' do
        dirty = '<math><script>alert("xss")</script></math>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<script')
        expect(clean).not_to include('alert')
      end

      it 'removes dangerous MathML elements' do
        dirty = '<math><maction actiontype="statusline" xlink:href="javascript:alert(\'xss\')">Click</maction></math>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('javascript:')
        expect(clean).not_to include('alert')
      end
    end

    describe 'css-based attacks' do
      it 'removes style tags with javascript' do
        dirty = '<style>body { background: url("javascript:alert(\'xss\')") }</style>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<style')
        expect(clean).not_to include('javascript:')
      end

      it 'removes style attributes with javascript' do
        dirty = '<div style="background: url(\'javascript:alert("xss")\')">Test</div>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('javascript:')
        expect(clean).not_to include('alert')
      end

      it 'removes expression() in CSS' do
        dirty = '<div style="width: expression(alert(\'xss\'))">Test</div>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('expression')
        expect(clean).not_to include('alert')
      end

      it 'removes @import with javascript' do
        dirty = '<style>@import url("javascript:alert(\'xss\')");</style>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<style')
        expect(clean).not_to include('javascript:')
      end
    end

    describe 'encoding and bypass attempts' do
      it 'handles HTML entity encoding' do
        dirty = '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<script>')
        expect(clean).not_to include('alert')
      end

      it 'handles URL encoding in attributes' do
        dirty = '<a href="javascript%3Aalert%28%27xss%27%29">Link</a>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('javascript')
        expect(clean).not_to include('alert')
      end

      it 'handles hex encoding' do
        # rubocop:disable Layout/LineLength
        dirty = '<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x27;&#x78;&#x73;&#x73;&#x27;&#x29;">Link</a>'
        # rubocop:enable Layout/LineLength
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('alert')
      end

      it 'handles mixed encoding attacks' do
        dirty = '<img src="jav&#x61;script:alert(\'xss\')">'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('alert')
      end
    end

    describe 'DOM clobbering attacks' do
      it 'removes dangerous name attributes' do
        dirty = '<form name="alert"><input name="submit"></form>'
        clean = described_class.sanitize(dirty, sanitize_dom: true)
        expect(clean).not_to include('name="alert"')
      end

      it 'removes dangerous id attributes' do
        dirty = '<div id="alert">Content</div>'
        clean = described_class.sanitize(dirty, sanitize_dom: true)
        expect(clean).not_to include('id="alert"')
      end
    end

    describe 'protocol bypass attempts' do
      it 'blocks data protocol with HTML content' do
        dirty = '<iframe src="data:text/html,<script>alert(\'xss\')</script>"></iframe>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<iframe')
        expect(clean).not_to include('data:')
      end

      it 'blocks vbscript protocol' do
        dirty = '<a href="vbscript:msgbox(\'xss\')">Link</a>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('vbscript:')
        expect(clean).not_to include('msgbox')
      end

      it 'blocks file protocol' do
        dirty = '<iframe src="file:///etc/passwd"></iframe>'
        clean = described_class.sanitize(dirty)
        expect(clean).not_to include('<iframe')
        expect(clean).not_to include('file:')
      end
    end
  end
end
