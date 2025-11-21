# frozen_string_literal: true

require 'rspec'
require 'scrubber'

path = File.expand_path('fixtures/examples.rb', __dir__)
# Fixture uses a top-level local (`examples = [...]`), so we eval to capture it.
EXPECTATIONS = Kernel.eval(File.read(path), binding, path)

RSpec.describe 'Scrubber DOMPurify expectations' do
  EXPECTATIONS.each do |example|
    it example['title'] do
      actual = Scrubber.new(use_profiles: [:purify]).sanitize(example['payload'])
      expected = example['expected']

      if expected.is_a?(Array)
        expect(expected).to include(actual), "Expected one of #{expected.inspect}, got #{actual.inspect}"
      else
        expect(actual).to eq(expected)
      end
    end
  end
end
