# frozen_string_literal: true

begin
  require 'rspec'
rescue LoadError
  # RSpec = nil
end
require_relative '../lib/scrubber'

if defined?(RSpec) && RSpec
  RSpec.describe Scrubber do
    describe 'Performance and Stress Tests' do
      describe 'large document processing' do
        it 'processes large documents efficiently' do
          start_time = Time.now
          content = '<p>Test paragraph with <strong>bold</strong> and <em>italic</em> text.</p>' * 1000
          large_doc = "<div>#{content}</div>"
          clean = described_class.sanitize(large_doc)
          end_time = Time.now

          expect(clean).to include('<p>Test paragraph')
          expect(end_time - start_time).to be < 5.0 # Should complete within 5 seconds
        end
      end

      describe 'many small documents' do
        it 'processes many small documents efficiently' do
          start_time = Time.now
          1000.times do |i|
            dirty = "<div>Document #{i} with <script>alert('xss')</script> and safe content</div>"
            clean = described_class.sanitize(dirty)
            expect(clean).not_to include('<script')
          end
          end_time = Time.now

          expect(end_time - start_time).to be < 10.0 # Should complete within 10 seconds
        end
      end

      describe 'complex nested structures' do
        it 'handles complex nesting efficiently' do
          start_time = Time.now
          # Create deeply nested structure
          nested = '<div>'
          100.times do |i|
            nested += "<div class='level-#{i}'><span>"
          end
          nested += 'Deep content'
          100.times do
            nested += '</span></div>'
          end
          nested += '</div>'

          clean = described_class.sanitize(nested)
          end_time = Time.now

          expect(clean).to include('Deep content')
          expect(end_time - start_time).to be < 5.0
        end
      end

      describe 'memory usage' do
        it 'does not leak memory during repeated sanitization' do
          # This is a basic test - in a real scenario you'd monitor memory more carefully
          initial_objects = ObjectSpace.count_objects
          100.times do
            dirty = "<div>#{'<p>Content with <script>alert("xss")</script> and safe text</p>' * 100}</div>"
            described_class.sanitize(dirty)
          end
          GC.start # Force garbage collection
          final_objects = ObjectSpace.count_objects

          # Allow for some object growth but not excessive
          object_growth = final_objects[:TOTAL] - initial_objects[:TOTAL]
          expect(object_growth).to be < 50_000
        end
      end
    end
  end
else
  puts 'RSpec not available; running stress scenarios directly...'

  def ensure!
    raise 'Assertion failed' unless yield
  end

  start_time = Time.now
  large_doc = "<div>#{'<p>Test paragraph with <strong>bold</strong> and <em>italic</em> text.</p>' * 1000}</div>"
  clean = Scrubber.sanitize(large_doc)
  ensure! { clean.include?('<p>Test paragraph') }
  ensure! { (Time.now - start_time) < 5.0 }
  puts 'Large document: passed'

  start_time = Time.now
  1000.times do |i|
    dirty = "<div>Document #{i} with <script>alert('xss')</script> and safe content</div>"
    clean = Scrubber.sanitize(dirty)
    ensure! { !clean.include?('<script') } # rubocop:disable Rails/NegateInclude
  end
  ensure! { (Time.now - start_time) < 10.0 }
  puts 'Many small documents: passed'

  start_time = Time.now
  nested = '<div>'
  100.times do |i|
    nested += "<div class='level-#{i}'><span>"
  end
  nested += 'Deep content'
  100.times { nested += '</span></div>' }
  nested += '</div>'
  clean = Scrubber.sanitize(nested)
  ensure! { clean.include?('Deep content') }
  ensure! { (Time.now - start_time) < 5.0 }
  puts 'Complex nesting: passed'

  initial_objects = ObjectSpace.count_objects
  100.times do
    dirty = "<div>#{'<p>Content with <script>alert("xss")</script> and safe text</p>' * 100}</div>"
    Scrubber.sanitize(dirty)
  end
  GC.start
  final_objects = ObjectSpace.count_objects
  object_growth = final_objects[:TOTAL] - initial_objects[:TOTAL]
  ensure! { object_growth < 50_000 }
  puts 'Memory usage: passed'
end
