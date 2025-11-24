# frozen_string_literal: true

require 'rspec'
require 'dandruff'

RSpec.describe Dandruff do
  let(:dandruff) { described_class.new }

  describe 'hooks' do
    it 'executes before_sanitize_elements hook' do
      hook_called = false
      dandruff.add_hook(:before_sanitize_elements) do |_node, _data, _config|
        hook_called = true
      end

      dandruff.sanitize('<p>test</p>')
      expect(hook_called).to be true
    end

    it 'executes upon_sanitize_element hook' do
      hook_called = false
      tag_names = []

      dandruff.add_hook(:upon_sanitize_element) do |_node, data, _config|
        hook_called = true
        tag_names << data[:tag_name]
      end

      dandruff.sanitize('<p>test</p>')
      expect(hook_called).to be true
      expect(tag_names).to include('p')
    end

    it 'executes upon_sanitize_attribute hook' do
      hook_called = false
      attrs = []

      dandruff.add_hook(:upon_sanitize_attribute) do |attr, data, _config|
        hook_called = true
        attrs << [data[:tag_name], data[:attr_name], attr.value]
      end

      dandruff.sanitize('<a href="https://example.com">test</a>')
      expect(hook_called).to be true
      expect(attrs).to include(['a', 'href', 'https://example.com'])
    end

    it 'can remove hooks' do
      hook_called = false
      hook_proc = proc { hook_called = true }

      dandruff.add_hook(:before_sanitize_elements, &hook_proc)
      dandruff.remove_hook(:before_sanitize_elements, hook_proc)
      dandruff.sanitize('<p>test</p>')

      expect(hook_called).to be false
    end

    it 'can remove a specific hook when multiple are present' do
      hook1_called = false
      hook2_called = false
      hook1 = proc { hook1_called = true }
      hook2 = proc { hook2_called = true }

      dandruff.add_hook(:before_sanitize_elements, &hook1)
      dandruff.add_hook(:before_sanitize_elements, &hook2)

      dandruff.remove_hook(:before_sanitize_elements, hook1)
      dandruff.sanitize('<p>test</p>')

      expect(hook1_called).to be false
      expect(hook2_called).to be true
    end

    it 'executes hooks in the order they were added' do
      dandruff.set_config(mutation_max_passes: 1)
      order = []
      hook1 = proc { order << 1 }
      hook2 = proc { order << 2 }

      dandruff.add_hook(:before_sanitize_elements, &hook1)
      dandruff.add_hook(:before_sanitize_elements, &hook2)

      dandruff.sanitize('<p>test</p>')

      expect(order).to eq([1, 2])
    end

    it 'does not fail when removing a non-existent hook' do
      hook = proc {}
      expect { dandruff.remove_hook(:before_sanitize_elements, hook) }.not_to raise_error
    end
  end
end
