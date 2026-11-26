# frozen_string_literal: true

require 'rspec'
require 'dandruff'

# Regression specs for the security review fixes. Most examples here fail (or raise) on
# the code before the fixes; the remainder pin down intended behaviour around them so
# the fixes do not over-correct.
RSpec.describe 'Dandruff security regressions' do
  let(:email) { Dandruff.new { |c| c.use_profiles = { html_email: true } } }

  def body_of(html)
    html[%r{<body[^>]*>(.*)</body>}m, 1] || html
  end

  describe '<style> goes through the element and attribute pipeline' do
    it 'removes event handlers from a nested <style> with the default config' do
      out = Dandruff.sanitize('<div><style onload="alert(1)" onerror="alert(2)">p{}</style>hi</div>')
      expect(out).to eq('<div><style>p{}</style>hi</div>')
    end

    it 'removes event handlers from <style> in the html_email profile at any position' do
      out = email.sanitize('<div><style onload="alert(1)">p{}</style></div><style onload="alert(2)"></style>')
      expect(out).not_to match(/onload/i)
      expect(out).to include('<style>p{}</style>')
    end

    it 'only keeps the per-tag allowed attributes on <style> in html_email' do
      out = email.sanitize('<style type="text/css" id="x" media="all" foo="bar">p{}</style>')
      expect(out).to include('<style type="text/css">p{}</style>')
    end

    it 'honours forbidden_tags for <style>' do
      forbid = Dandruff.new do |c|
        c.use_profiles = { html_email: true }
        c.forbidden_tags = %w[style]
      end
      expect(forbid.sanitize('<div><style>p{}</style>x</div>')).not_to include('<style')
      expect(Dandruff.sanitize('<div><style>p{}</style>x</div>', forbidden_tags: %w[style])).not_to include('<style')
    end

    it 'honours an explicit allowed_tags list that omits <style>' do
      expect(Dandruff.sanitize('<div><style>p{}</style>x</div>', allowed_tags: %w[div])).not_to include('<style')
    end

    it 'keeps <style> when an explicit allowed_tags list includes it' do
      out = Dandruff.sanitize('<div><style onload="x">p{}</style>x</div>', allowed_tags: %w[div style])
      expect(out).to eq('<div><style>p{}</style>x</div>')
    end

    it 'drops <style> under the html profile, whose allowlist does not contain it' do
      out = Dandruff.sanitize('<div><style>p{}</style>x</div>', use_profiles: { html: true })
      expect(out).not_to include('<style')
      expect(out).to include('x')
    end

    it 'still removes <style> when allow_style_tags is false, even if allow-listed' do
      out = Dandruff.sanitize('<div><style>p{}</style>x</div>', allowed_tags: %w[div style], allow_style_tags: false)
      expect(out).not_to include('<style')
    end

    it 'runs upon_sanitize_element and upon_sanitize_attribute hooks for <style>' do
      seen = []
      email.add_hook(:upon_sanitize_element) { |_n, d, _c| seen << d[:tag_name] }
      email.add_hook(:upon_sanitize_attribute) { |_n, d, _c| seen << "#{d[:tag_name]}@#{d[:attr_name]}" }
      email.sanitize('<style type="text/css">p{}</style><p>x</p>')
      expect(seen).to include('style', 'style@type')
    end

    it 'records removed <style> elements' do
      sanitizer = Dandruff.new(forbidden_tags: %w[style])
      sanitizer.sanitize('<div><style>p{}</style>x</div>')
      expect(sanitizer.removed.map { |r| r[:element]&.name }).to include('style')
    end

    it 'removes <style> inside SVG (mXSS precaution applied to style, title and mglyph)' do
      out = Dandruff.sanitize('<svg><style>.a{fill:red}</style><rect class="a"></rect></svg>')
      expect(out).not_to include('<style')
    end
  end

  describe 'disallowed elements whose children are hoisted' do
    single_pass_configs = [{ mutation_max_passes: 1 }, { pass_limit: 1 }, { sanitize_until_stable: false }]

    single_pass_configs.each do |cfg|
      it "removes the emptied element and its event handlers with #{cfg}" do
        out = Dandruff.sanitize('<xyz onclick="alert(1)" style="display:block">text</xyz>', cfg)
        expect(out).to eq('text')
      end

      it "removes the emptied element and its javascript: URL with #{cfg}" do
        out = Dandruff.sanitize('<a2 href="javascript:alert(1)">click</a2>', cfg)
        expect(out).to eq('click')
      end
    end

    it 'removes the element in DOM-returning modes with a single pass' do
      out = Dandruff.sanitize('<xyz onfocus="alert(1)" autofocus tabindex="0">t</xyz>',
        mutation_max_passes: 1, return_dom_fragment: true)
      expect(out.to_html).to eq('t')
    end

    it 'gives the same result with one pass as with the default two passes' do
      input = '<xyz onclick="alert(1)"><abc onfocus="x" autofocus tabindex="0">t</abc><b>b</b></xyz>'
      expect(Dandruff.sanitize(input, mutation_max_passes: 1)).to eq(Dandruff.sanitize(input))
    end

    it 'only reports elements in removed that are actually gone from the output' do
      sanitizer = Dandruff.new(mutation_max_passes: 1)
      out = sanitizer.sanitize('<xyz onclick="alert(1)">text</xyz>')
      expect(sanitizer.removed.map { |r| r[:element]&.name }).to include('xyz')
      expect(out).not_to include('xyz')
    end
  end

  describe 'upon_sanitize_attribute hook data' do
    let(:sanitizer) { Dandruff.new }

    def with_hook(&)
      sanitizer.add_hook(:upon_sanitize_attribute, &)
      sanitizer
    end

    it 'keeps a non-allow-listed attribute when keep_attr is true' do
      with_hook { |_a, data, _c| data[:keep_attr] = true if data[:attr_name] == 'x-custom' }
      expect(sanitizer.sanitize('<div x-custom="v">c</div>')).to eq('<div x-custom="v">c</div>')
    end

    it 'keeps an attribute outside the html_email per-tag list when keep_attr is true' do
      email.add_hook(:upon_sanitize_attribute) { |_a, d, _c| d[:keep_attr] = true if d[:attr_name] == 'x-track' }
      expect(body_of(email.sanitize('<div x-track="1">c</div>'))).to eq('<div x-track="1">c</div>')
    end

    it 'removes an allowed attribute when keep_attr is false' do
      with_hook { |_a, data, _c| data[:keep_attr] = false if data[:attr_name] == 'title' }
      expect(sanitizer.sanitize('<div title="t" class="c">c</div>')).to eq('<div class="c">c</div>')
    end

    it 'never keeps event handlers because of keep_attr' do
      with_hook { |_a, data, _c| data[:keep_attr] = true }
      out = sanitizer.sanitize('<a onclick="alert(1)" onpointerdown="alert(2)" href="https://ok.example">x</a>')
      expect(out).to eq('<a href="https://ok.example">x</a>')
    end

    it 'never keeps forbidden attributes because of keep_attr' do
      forbidding = Dandruff.new(forbidden_attributes: %w[title])
      forbidding.add_hook(:upon_sanitize_attribute) { |_a, data, _c| data[:keep_attr] = true }
      expect(forbidding.sanitize('<div title="t">c</div>')).to eq('<div>c</div>')
    end

    it 'still applies URI checks when keep_attr is true' do
      with_hook { |_a, data, _c| data[:keep_attr] = true }
      expect(sanitizer.sanitize('<a href="javascript:alert(1)">x</a>')).to eq('<a>x</a>')
    end

    it 'uses a value assigned to data[:value]' do
      with_hook do |_a, data, _c|
        # hooks run once per pass, so keep the rewrite idempotent
        if data[:attr_name] == 'src' && !data[:value].start_with?('https://proxy.example/')
          data[:value] = "https://proxy.example/?u=#{data[:value]}"
        end
      end
      out = sanitizer.sanitize('<img src="https://tracker.example/p.gif">')
      expect(out).to eq('<img src="https://proxy.example/?u=https://tracker.example/p.gif">')
    end

    it 'uses a value written directly to the attribute node' do
      with_hook { |attr, data, _c| attr.value = 'new' if data[:attr_name] == 'title' }
      expect(sanitizer.sanitize('<div title="old">c</div>')).to eq('<div title="new">c</div>')
    end

    it 'accepts a frozen string in data[:value]' do
      # string literals are frozen in this file (frozen_string_literal: true)
      with_hook { |_a, data, _c| data[:value] = ' https://ok.example/ ' if data[:attr_name] == 'href' }
      expect(sanitizer.sanitize('<a href="https://a.example">x</a>')).to eq('<a href="https://ok.example/">x</a>')
    end

    it 'validates a value rewritten by a hook' do
      with_hook { |_a, data, _c| data[:value] = 'javascript:alert(1)' if data[:attr_name] == 'href' }
      expect(sanitizer.sanitize('<a href="https://ok.example">c</a>')).to eq('<a>c</a>')
    end

    it 'validates a rewritten style value' do
      with_hook { |_a, data, _c| data[:value] = 'width:expression(alert(1))' if data[:attr_name] == 'style' }
      expect(sanitizer.sanitize('<p style="color:red">c</p>')).to eq('<p>c</p>')
    end

    it 'runs the README hook example' do
      readme = Dandruff.new { |c| c.allow_data_attributes = false }
      readme.add_hook(:upon_sanitize_attribute) do |_attr, data, _config|
        data[:keep_attr] = true if data[:attr_name].start_with?('data-safe-')
        data[:value] = data[:value].downcase if data[:attr_name] == 'id'
      end
      out = readme.scrub('<div data-safe-user-id="123" data-key="ABC" id="MyID">Content</div>')
      expect(out).to eq('<div data-safe-user-id="123" id="myid">Content</div>')
    end
  end

  describe 'default URI allowlist (IS_ALLOWED_URI)' do
    it 'keeps cid: references to inline images in html_email' do
      out = email.sanitize('<img src="cid:image001.png@01D9C2A0" alt="logo">')
      expect(out).to include('<img src="cid:image001.png@01D9C2A0" alt="logo">')
    end

    it 'keeps the other DOMPurify schemes' do
      %w[ftps://f.example/x sms:+15551234 callto:someone xmpp:a@b.example matrix:u/a:b.example].each do |uri|
        expect(Dandruff.sanitize(%(<a href="#{uri}">x</a>))).to eq(%(<a href="#{uri}">x</a>))
      end
    end

    it 'keeps relative URLs containing digits or slashes' do
      html = '<a href="page2.html">a</a><a href="docs/page.html">b</a><img src="images/logo.png"><img src="img2.png">'
      expect(Dandruff.sanitize(html)).to eq(html)
    end

    it 'still rejects javascript:, vbscript: and unknown schemes' do
      %w[javascript:alert(1) JaVaScRiPt:alert(1) vbscript:msgbox(1) unknown:foo %6Aavascript:alert(1)].each do |uri|
        expect(Dandruff.sanitize(%(<a href="#{uri}">x</a>))).to eq('<a>x</a>')
      end
    end

    it 'anchors at the start of the whole value, not at line starts' do
      pattern = Dandruff::Expressions::IS_ALLOWED_URI
      expect(pattern.match?("javascript:alert(1)\nhttps://ok.example")).to be(false)
      expect(pattern.match?("javascript:alert(1)\n")).to be(false)
    end
  end

  describe '<style> content sanitization' do
    def style_of(sanitizer, css)
      sanitizer.sanitize("<style>#{css}</style><p>x</p>")[%r{<style>(.*?)</style>}m, 1]
    end

    it 'removes @import rules but keeps the rest of the stylesheet' do
      css = '@import url(https://evil.example/x.css); @import "y.css"; p{color:red}'
      expect(style_of(email, css)).to eq(';; p{color:red}')
    end

    it 'removes @import obfuscated with CSS escapes and comments' do
      ['@\69mport url(x.css);', '@\49 MPORT url(x.css);', '@im\port url(x.css);', '@/**/import url(x);',
        '@import/**/url(x);'].each do |css|
        expect(style_of(email, "#{css}p{color:red}")).to eq(';p{color:red}'), css
      end
    end

    it 'removes declarations with script URLs, including obfuscated url()' do
      ['background:url(javascript:alert(1))', 'background:u\rl(javascript:alert(1))',
        'background:\75 rl(\6a avascript:alert(1))', 'background:url( "vbscript:x" )',
        "background:url(\"java\\\nscript:alert(1)\")", 'background:url(javascript:x;y)'].each do |decl|
        expect(style_of(email, "p{#{decl};color:red}")).to eq('p{;color:red}'), decl
      end
    end

    it 'removes expression(), behavior and -moz-binding, including obfuscated forms' do
      ['width:expression(alert(1))', 'width:expr/**/ession(alert(1))', 'width:e\78pression(alert(1))',
        'behavior:url(x.htc)', '-moz-binding:url(x.xml#y)', '-moz-bin\64ing:url(x.xml#y)'].each do |decl|
        expect(style_of(email, "p{color:red;#{decl}}")).to eq('p{color:red;}'), decl
      end
    end

    it 'only allows data: URLs for images, and only with allow_data_uri' do
      css = 'a{background:url(data:image/png;base64,AAAA)}b{background:url(data:text/html,x)}'
      expect(style_of(email, css)).to eq('a{background:url(data:image/png;base64,AAAA)}b{}')

      no_data = Dandruff.new do |c|
        c.use_profiles = { html_email: true }
        c.allow_data_uri = false
      end
      expect(style_of(no_data, css)).to eq('a{}b{}')
    end

    it 'applies allowed_uri_regexp to CSS URLs' do
      proxied = Dandruff.new do |c|
        c.use_profiles = { html_email: true }
        c.allowed_uri_regexp = %r{\Ahttps://proxy\.example/}
      end
      css = 'a{background:url(https://proxy.example/a.png)}b{background:url(https://t.example/p.gif)}'
      expect(style_of(proxied, css)).to eq('a{background:url(https://proxy.example/a.png)}b{}')
    end

    it 'keeps safe stylesheets, comments, media queries, relative, cid: and remote URLs' do
      css = "/* Outlook */ body{margin:0} @media (max-width:600px){.a{width:100%!important}} " \
            'a > b{background:url(images/bg.png)} c{background:url(cid:bg@x)} ' \
            'd{background:url(https://cdn.example/bg.png)} e{content:"\201C"}'
      expect(style_of(email, css)).to eq(css)
    end

    it 'treats delimiters inside strings, comments and url() as text' do
      css = 'p{color:red;/* a;b{ */background:url(javascript:x)} q{background:url("a;b.png")}'
      expect(style_of(email, css)).to eq('p{color:red;} q{background:url("a;b.png")}')
    end

    it 'sanitizes nested <style> content with the default config' do
      out = Dandruff.sanitize('<div><style>a{color:red} b{background:url(javascript:x)}</style></div>')
      expect(out).to eq('<div><style>a{color:red} b{}</style></div>')
    end

    describe 'allow_remote_style_urls: false' do
      let(:private_email) do
        Dandruff.new do |c|
          c.use_profiles = { html_email: true }
          c.allow_remote_style_urls = false
        end
      end

      it 'removes remote url(), src() and image-set() URLs from <style> but keeps local ones' do
        css = 'a{background:url(https://t.example/p.gif);color:red} b{background:url(//t.example/p.gif)} ' \
              'c{background:url(\\\\\\\\t.example/p.gif)} d{background-image:image-set("http://t.example/a.png" 1x)} ' \
              '@font-face{font-family:f;src:url(https://f.example/a.woff2)} e{background:url(images/bg.png)} ' \
              'g{background:url(cid:bg@x)}'
        expect(style_of(private_email, css)).to eq(
          'a{;color:red} b{} c{} d{} @font-face{font-family:f;} e{background:url(images/bg.png)} ' \
          'g{background:url(cid:bg@x)}'
        )
      end

      it 'removes remote URLs from style attributes and drops attributes left empty' do
        html = '<p style="color:red;background:url(https://t.example/p.gif)">x</p>' \
               '<p style="background:url(https://t.example/p.gif)">y</p>'
        expect(Dandruff.sanitize(html, allow_remote_style_urls: false)).to eq('<p style="color:red;">x</p><p>y</p>')
      end

      it 'keeps remote CSS URLs by default' do
        html = '<p style="background:url(https://cdn.example/bg.png)">x</p>'
        expect(Dandruff.sanitize(html)).to eq(html)
      end
    end
  end

  describe 'whole-document mode with an explicit allowed_tags list' do
    it 'does not raise for html_email with a custom allowed_tags list lacking html/body' do
      custom = Dandruff.new do |c|
        c.use_profiles = { html_email: true }
        c.allowed_tags = %w[p b]
      end
      out = nil
      expect { out = custom.sanitize('<p onclick="x">x</p><i>y</i>') }.not_to raise_error
      expect(body_of(out)).to eq('<p>x</p> ')
    end

    it 'does not raise with return_dom and an allowed_tags list lacking html/body' do
      out = Dandruff.sanitize('<p>x</p><i>y</i>', return_dom: true, allowed_tags: %w[p])
      expect(out.at_css('body').inner_html).to eq('<p>x</p> ')
    end

    it 'removes everything instead of raising when the document root itself is forbidden' do
      out = Dandruff.sanitize('<p>x</p>', whole_document: true, forbidden_tags: %w[html])
      expect(out).not_to include('<p>')
    end
  end

  describe 'configuration hash ordering with use_profiles' do
    let(:html) { '<p>a</p><b>bold</b>' }

    it 'applies forbidden_tags given before use_profiles' do
      out = Dandruff.sanitize(html, forbidden_tags: %w[b], use_profiles: { html_email: true })
      expect(out).not_to include('<b>')
    end

    it 'gives the same result for either key order' do
      before = Dandruff.sanitize(html, forbidden_tags: %w[b], use_profiles: { html_email: true })
      after = Dandruff.sanitize(html, use_profiles: { html_email: true }, forbidden_tags: %w[b])
      expect(before).to eq(after)
    end

    it 'applies other profile-dependent options given before use_profiles' do
      config = Dandruff::Config.new(
        'allowed_tags' => %w[p], 'sanitize_dom' => true, 'use_profiles' => { html_email: true }
      )
      expect(config.allowed_tags).to eq(%w[p])
      expect(config.sanitize_dom).to be(true)
    end

    it 'applies options passed to sanitize before use_profiles' do
      out = Dandruff.new.sanitize('<b>x</b><i>y</i>', allowed_tags: %w[i], use_profiles: { html: true })
      expect(out).to eq(' <i>y</i>')
    end
  end

  describe 'srcset' do
    it 'validates every candidate URL, not the attribute as a whole' do
      out = Dandruff.sanitize('<img srcset="https://ok.example/a.png 1x, javascript:alert(1) 2x">')
      expect(out).to eq('<img>')
    end

    it 'applies allowed_uri_regexp to every candidate' do
      out = Dandruff.sanitize('<img srcset="https://proxy.example/a.png 1x, https://tracker.example/p.gif 2x">',
        allowed_uri_regexp: %r{\Ahttps://proxy\.example/})
      expect(out).to eq('<img>')
    end

    it 'keeps valid srcsets, including descriptors and data: image candidates' do
      html = '<img srcset="a.png 1x, images/b2.png 2x"><img srcset="data:image/png;base64,AAAA 1x, b.png 2x">' \
             '<picture><source srcset="https://cdn.example/a.webp 480w, https://cdn.example/b.webp 800w"></picture>'
      expect(Dandruff.sanitize(html)).to eq(html)
    end
  end
end
