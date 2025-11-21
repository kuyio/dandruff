# frozen_string_literal: true

require 'rspec'
require 'scrubber'

RSpec.describe Scrubber do
  let(:scrubber) { described_class.new }

  describe 'hooks' do
    it 'executes before_sanitize_elements hook' do
      hook_called = false
      scrubber.add_hook(:before_sanitize_elements) do |_node, _data, _config|
        hook_called = true
      end

      scrubber.sanitize('<p>test</p>')
      expect(hook_called).to be true
    end

    it 'executes upon_sanitize_element hook' do
      hook_called = false
      tag_names = []

      scrubber.add_hook(:upon_sanitize_element) do |_node, data, _config|
        hook_called = true
        tag_names << data[:tag_name]
      end

      scrubber.sanitize('<p>test</p>')
      expect(hook_called).to be true
      expect(tag_names).to include('p')
    end

    it 'executes upon_sanitize_attribute hook' do
      hook_called = false
      attrs = []

      scrubber.add_hook(:upon_sanitize_attribute) do |attr, data, _config|
        hook_called = true
        attrs << [data[:tag_name], data[:attr_name], attr.value]
      end

      scrubber.sanitize('<a href="https://example.com">test</a>')
      expect(hook_called).to be true
      expect(attrs).to include(['a', 'href', 'https://example.com'])
    end

    it 'can remove hooks' do
      hook_called = false
      hook_proc = proc { hook_called = true }

      scrubber.add_hook(:before_sanitize_elements, &hook_proc)
      scrubber.remove_hook(:before_sanitize_elements, hook_proc)
      scrubber.sanitize('<p>test</p>')

      expect(hook_called).to be false
    end
  end
end
