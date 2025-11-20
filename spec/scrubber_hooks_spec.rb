# frozen_string_literal: true

require 'rspec'
require 'scrubber'

RSpec.describe Scrubber do
  describe 'hooks' do
    it 'executes before_sanitize_elements hook' do
      hook_called = false
      described_class.add_hook(:before_sanitize_elements) do |_node, _data, _config|
        hook_called = true
      end

      described_class.sanitize('<p>test</p>')
      expect(hook_called).to be true
    end

    it 'executes upon_sanitize_element hook' do
      hook_called = false
      tag_names = []

      described_class.add_hook(:upon_sanitize_element) do |_node, data, _config|
        hook_called = true
        tag_names << data[:tag_name]
      end

      described_class.sanitize('<p>test</p>')
      expect(hook_called).to be true
      expect(tag_names).to include('p')
    end

    it 'can remove hooks' do
      hook_called = false
      hook_proc = proc { hook_called = true }

      described_class.add_hook(:before_sanitize_elements, &hook_proc)
      described_class.remove_hook(:before_sanitize_elements, hook_proc)
      described_class.sanitize('<p>test</p>')

      expect(hook_called).to be false
    end
  end
end
