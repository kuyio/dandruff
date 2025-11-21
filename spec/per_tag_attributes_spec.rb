# frozen_string_literal: true

require 'rspec'
require 'scrubber'

RSpec.describe 'Per-Tag Attribute Control' do
  let(:scrubber) { Scrubber.new }

  describe 'allowed_attributes_per_tag configuration' do
    it 'allows specific attributes only on designated tags' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {
          'a' => %w[href title],
          'img' => %w[src alt]
        }
      end

      html = '<a href="/page" title="Link">Text</a>'
      result = scrubber.sanitize(html)
      expect(result).to include('href="/page"')
      expect(result).to include('title="Link"')
    end

    it 'removes attributes not in per-tag allow list' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {
          'a' => ['href']
        }
      end

      html = '<a href="/page" title="Link" onclick="alert()">Text</a>'
      result = scrubber.sanitize(html)
      expect(result).to include('href="/page"')
      expect(result).not_to include('title=')
      expect(result).not_to include('onclick=')
    end

    it 'prevents attribute confusion attacks' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {
          'a' => %w[href title],
          'img' => %w[src alt]
        }
      end

      # href should not be allowed on img tags
      html = '<img src="pic.jpg" href="/malicious">'
      result = scrubber.sanitize(html)
      expect(result).to include('src="pic.jpg"')
      expect(result).not_to include('href=')

      # src should not be allowed on a tags
      html = '<a href="/page" src="malicious.js">Link</a>'
      result = scrubber.sanitize(html)
      expect(result).to include('href="/page"')
      expect(result).not_to include('src=')
    end

    it 'works with multiple tags with different attribute sets' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {
          'a' => %w[href title target],
          'img' => %w[src alt width height],
          'td' => %w[colspan rowspan],
          'th' => %w[colspan rowspan scope]
        }
      end

      html = '<table><tr><td colspan="2">Cell</td><th scope="col">Header</th></tr></table>'
      result = scrubber.sanitize(html)
      expect(result).to include('colspan="2"')
      expect(result).to include('scope="col"')
    end

    it 'handles tags not in per-tag config with default behavior' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {
          'a' => ['href']
        }
        # p tag not in per-tag config, should use default behavior
      end

      html = '<p class="intro">Text</p><a href="/page" class="link">Link</a>'
      result = scrubber.sanitize(html)
      # p tag should allow class (default behavior)
      expect(result).to include('<p')
      # a tag should only allow href
      expect(result).to include('href="/page"')
      expect(result).not_to include('class="link"')
    end
  end

  describe 'interaction with forbidden_attributes' do
    it 'respects forbidden_attributes over per-tag rules' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {
          'a' => %w[href onclick] # onclick in per-tag list
        }
        config.forbidden_attributes = ['onclick'] # but forbidden globally
      end

      html = '<a href="/page" onclick="alert()">Link</a>'
      result = scrubber.sanitize(html)
      expect(result).to include('href="/page"')
      expect(result).not_to include('onclick=')
    end

    it 'removes dangerous attributes even if in per-tag list' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {
          'a' => %w[href onerror] # onerror is dangerous
        }
      end

      html = '<a href="/page" onerror="alert()">Link</a>'
      result = scrubber.sanitize(html)
      expect(result).to include('href="/page"')
      expect(result).not_to include('onerror=')
    end
  end

  describe 'interaction with allowed_attributes' do
    it 'uses per-tag rules instead of global allowed_attributes for specified tags' do
      scrubber.configure do |config|
        config.allowed_attributes = %w[class id] # global allow list
        config.allowed_attributes_per_tag = {
          'a' => ['href'] # specific rule for a tags
        }
      end

      # a tag should use per-tag rule (only href)
      html = '<a href="/page" class="link" id="main">Link</a>'
      result = scrubber.sanitize(html)
      expect(result).to include('href="/page"')
      expect(result).not_to include('class=')
      expect(result).not_to include('id=')

      # p tag should use global allowed_attributes
      html = '<p class="intro" id="para">Text</p>'
      result = scrubber.sanitize(html)
      expect(result).to include('class="intro"')
      expect(result).to include('id="para"')
    end
  end

  describe 'edge cases' do
    it 'handles nil allowed_attributes_per_tag' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = nil
      end

      html = '<a href="/page" class="link">Link</a>'
      result = scrubber.sanitize(html)
      # Should use default behavior
      expect(result).to include('<a')
    end

    it 'handles empty hash for allowed_attributes_per_tag' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {}
      end

      html = '<a href="/page" class="link">Link</a>'
      result = scrubber.sanitize(html)
      # Should use default behavior
      expect(result).to include('<a')
    end

    it 'handles tag with empty attribute array' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {
          'a' => [] # no attributes allowed
        }
      end

      html = '<a href="/page" class="link">Link</a>'
      result = scrubber.sanitize(html)
      expect(result).to eq('<a>Link</a>')
    end

    it 'handles unknown tags in per-tag config' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {
          'custom-element' => %w[data-id data-value]
        }
        config.allowed_tags = ['custom-element']
      end

      html = '<custom-element data-id="123" data-value="test">Content</custom-element>'
      result = scrubber.sanitize(html)
      expect(result).to include('data-id="123"')
      expect(result).to include('data-value="test"')
    end

    it 'is case-insensitive for tag names' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {
          'a' => ['href'] # lowercase in config
        }
      end

      html = '<A HREF="/page" CLASS="link">Link</A>'
      result = scrubber.sanitize(html)
      expect(result.downcase).to include('href="/page"')
      expect(result.downcase).not_to include('class=')
    end
  end

  describe 'security scenarios' do
    it 'prevents XSS via per-tag attribute restrictions' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {
          'a' => ['href'],
          'img' => %w[src alt],
          'div' => ['class']
        }
      end

      xss_vectors = [
        '<a href="javascript:alert()">XSS</a>',
        '<img src="x" onerror="alert()">',
        '<div onclick="alert()" class="safe">Text</div>',
        '<a href="/page" onmouseover="alert()">Link</a>'
      ]

      xss_vectors.each do |vector|
        result = scrubber.sanitize(vector)
        expect(result).not_to include('javascript:')
        expect(result).not_to include('onerror=')
        expect(result).not_to include('onclick=')
        expect(result).not_to include('onmouseover=')
      end
    end

    it 'restricts form attributes to prevent CSRF' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {
          'form' => ['method'], # no action allowed
          'input' => %w[type name] # no value allowed
        }
      end

      html = '<form action="/evil" method="post"><input type="text" name="user" value="hacked"></form>'
      result = scrubber.sanitize(html)
      expect(result).to include('method="post"')
      expect(result).not_to include('action=')
      expect(result).not_to include('value=')
    end

    it 'prevents style injection on specific tags' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {
          'div' => ['class'],  # no style attribute
          'p' => ['class']     # no style attribute
        }
      end

      html = '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:red;">Overlay</div>'
      result = scrubber.sanitize(html)
      expect(result).not_to include('style=')
    end
  end

  describe 'combined with hook-based control' do
    it 'calls hooks for per-tag attribute validation' do
      scrubber.configure do |config|
        config.allowed_attributes_per_tag = {
          'a' => ['href'] # only href allowed
        }
      end

      hook_called = false
      hook_data = nil

      # Hook to verify it's called with correct data
      scrubber.add_hook(:upon_sanitize_attribute) do |_node, data, _config|
        if data[:tag_name] == 'a' && data[:attr_name] == 'title'
          hook_called = true
          hook_data = data
        end
      end

      html = '<a href="/page" title="Link">Text</a>'
      result = scrubber.sanitize(html)

      # Verify hook was called
      expect(hook_called).to be true
      expect(hook_data[:tag_name]).to eq('a')
      expect(hook_data[:attr_name]).to eq('title')

      # Per-tag rules still apply (title is removed)
      expect(result).to include('href="/page"')
      expect(result).not_to include('title=')

      scrubber.remove_all_hooks
    end
  end
end
