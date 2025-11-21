# frozen_string_literal: true

require 'rspec'
require 'scrubber'

RSpec.describe Scrubber do
  describe '.sanitize' do
    it 'removes script tags' do
      dirty = '<script>alert("xss")</script><p>Safe content</p>'
      clean = described_class.sanitize(dirty)
      expect(clean).not_to include('<script>')
      expect(clean).to include('<p>Safe content</p>')
    end

    it 'removes dangerous attributes' do
      dirty = '<div onclick="alert(\'xss\')">Click me</div>'
      clean = described_class.sanitize(dirty)
      expect(clean).not_to include('onclick')
    end

    it 'keeps safe HTML' do
      dirty = '<div class="safe">Safe content</div>'
      clean = described_class.sanitize(dirty)
      expect(clean).to include('<div class="safe">Safe content</div>')
    end

    it 'handles empty input' do
      expect(described_class.sanitize(nil)).to eq('')
      expect(described_class.sanitize('')).to eq('')
    end

    it 'removes comments when safe_for_xml is true' do
      dirty = '<!-- malicious comment --><p>Safe content</p>'
      clean = described_class.sanitize(dirty, safe_for_xml: true)
      expect(clean).not_to include('<!--')
      expect(clean).to include('<p>Safe content</p>')
    end

    it 'handles template expressions when safe_for_templates is true' do
      dirty = '<p>{{ malicious }}</p><script>${dangerous()}</script>'
      clean = described_class.sanitize(dirty, safe_for_templates: true)
      expect(clean).to include('<p>  </p>')
      expect(clean).not_to include('{{ malicious }}')
      expect(clean).not_to include('${dangerous()}')
    end
  end

  describe '.valid_attribute?' do
    it 'validates attributes correctly' do
      described_class.set_config(allowed_attributes: ['class'])
      expect(described_class.valid_attribute?('class', 'test')).to be true
      expect(described_class.valid_attribute?('onclick', 'alert()')).to be false
    end
  end

  describe 'profiles' do
    it 'supports HTML profile' do
      described_class.set_config(use_profiles: { html: true })
      clean = described_class.sanitize('<p><b>Bold</b></p>')
      expect(clean).to include('<p><b>Bold</b></p>')
    end

    it 'supports SVG profile' do
      described_class.set_config(use_profiles: { svg: true })
      clean = described_class.sanitize('<svg><circle r="10"/></svg>')
      expect(clean).to include('<svg><circle r="10"/></svg>')
    end
  end

  describe 'data attributes' do
    it 'allows data attributes by default' do
      described_class.clear_config
      dirty = '<div data-test="value">Content</div>'
      clean = described_class.sanitize(dirty)
      expect(clean).to include('data-test="value"')
    end

    it 'can disable data attributes' do
      dirty = '<div data-test="value">Content</div>'
      clean = described_class.sanitize(dirty, allow_data_attr: false)
      expect(clean).not_to include('data-test')
    end
  end

  describe 'ARIA attributes' do
    it 'allows ARIA attributes by default' do
      dirty = '<div aria-label="test">Content</div>'
      clean = described_class.sanitize(dirty)
      expect(clean).to include('aria-label="test"')
    end

    it 'can disable ARIA attributes' do
      dirty = '<div aria-label="test">Content</div>'
      clean = described_class.sanitize(dirty, allow_aria_attr: false)
      expect(clean).not_to include('aria-label')
    end
  end
end
