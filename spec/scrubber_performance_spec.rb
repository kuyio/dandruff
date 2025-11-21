# frozen_string_literal: true

require_relative '../lib/scrubber'
require 'benchmark'
require 'securerandom'

# Generate large HTML document for performance testing
def generate_large_html(size_kb)
  base_content = <<-HTML
    <div class="container">
      <h1>Performance Test Document</h1>
      <p>This is a test paragraph with <a href="https://example.com" onclick="alert('xss')">a link</a> and some <strong>bold text</strong>.</p>
      <ul>
        <li>Item 1 with <script>alert('xss')</script> potential XSS</li>
        <li>Item 2 with <img src="x" onerror="alert('xss')"> malicious image</li>
        <li>Item 3 with <div style="background:url(javascript:alert('xss'))">CSS attack</div></li>
      </ul>
      <table>
        <tr><th>Header 1</th><th>Header 2</th></tr>
        <tr><td>Data 1</td><td onclick="alert('xss')">Data 2</td></tr>
      </table>
      <form action="/submit" method="post">
        <input type="text" name="field1" value="test">
        <input type="hidden" name="csrf" value="token">
        <button type="submit" onclick="return validate()">Submit</button>
      </form>
    </div>
  HTML

  target_size = size_kb * 1024
  content = base_content
  while content.length < target_size
    content += base_content.gsub('Performance Test Document', "Section #{content.length / 1000}")
  end
  content[0...target_size]
end

# Performance test scenarios
def run_performance_tests
  puts 'Scrubber Performance Tests'
  puts '=' * 50

  test_sizes = [1, 10, 50, 100, 500] # KB
  iterations = 10

  test_sizes.each do |size_kb|
    html = generate_large_html(size_kb)
    puts "\nTesting #{size_kb}KB HTML document (#{html.length} bytes)"

    # Test with default configuration
    default_time = Benchmark.realtime do
      iterations.times { Scrubber.sanitize(html) }
    end

    # Test with strict configuration
    strict_config = {
      ALLOWED_TAGS: %w[p h1 h2 h3 strong em a],
      ALLOWED_ATTRIBUTES: %w[href],
      FORBIDDEN_ATTR: %w[onclick onerror onload],
      ALLOW_DATA_URI: false
    }
    strict_time = Benchmark.realtime do
      iterations.times { Scrubber.sanitize(html, strict_config) }
    end

    # Test with permissive configuration
    permissive_config = {
      ADDITIONAL_TAGS: %w[custom-element web-component],
      ADDITIONAL_ATTRIBUTES: %w[data-* custom-attr],
      ALLOW_DATA_URI: true,
      KEEP_CONTENT: true
    }
    permissive_time = Benchmark.realtime do
      iterations.times { Scrubber.sanitize(html, permissive_config) }
    end

    # Test RETURN_DOM configuration
    dom_config = { RETURN_DOM: true }
    dom_time = Benchmark.realtime do
      iterations.times { Scrubber.sanitize(html, dom_config) }
    end

    puts "  Default config:    #{(default_time * 1000).round(2)}ms total, " \
         "#{(default_time / iterations * 1000).round(2)}ms avg"
    puts "  Strict config:     #{(strict_time * 1000).round(2)}ms total, " \
         "#{(strict_time / iterations * 1000).round(2)}ms avg"
    puts "  Permissive config: #{(permissive_time * 1000).round(2)}ms total, " \
         "#{(permissive_time / iterations * 1000).round(2)}ms avg"
    puts "  RETURN_DOM config: #{(dom_time * 1000).round(2)}ms total, " \
         "#{(dom_time / iterations * 1000).round(2)}ms avg"

    # Calculate throughput
    throughput_default = (size_kb * iterations) / default_time
    throughput_strict = (size_kb * iterations) / strict_time
    puts "  Throughput: #{throughput_default.round(2)} KB/s (default), #{throughput_strict.round(2)} KB/s (strict)"
  end
end

# Memory usage test
def test_memory_usage
  puts "\nMemory Usage Test"
  puts '=' * 30

  # Test with progressively larger documents
  sizes = [10, 50, 100, 200, 500] # KB

  sizes.each do |size_kb|
    html = generate_large_html(size_kb)

    # Measure memory before and after sanitization
    GC.start
    memory_before = begin
      `ps -o rss= -p #{Process.pid}`.to_i
    rescue StandardError
      nil
    end

    # Run multiple sanitizations
    5.times { Scrubber.sanitize(html) }

    GC.start
    memory_after = begin
      `ps -o rss= -p #{Process.pid}`.to_i
    rescue StandardError
      nil
    end

    if memory_before && memory_after
      memory_used = memory_after - memory_before
      puts "  #{size_kb}KB: #{memory_used}KB additional memory used"
    else
      puts "  #{size_kb}KB: memory measurement skipped (ps unavailable)"
    end
  end
end

# Stress test with many small documents
def stress_test_small_documents
  puts "\nStress Test: Many Small Documents"
  puts '=' * 40

  small_html = "<p>Small document with <a href='#' onclick='alert(1)'>link</a> and <script>alert('xss')</script></p>"
  document_counts = [100, 500, 1000, 2000]

  document_counts.each do |count|
    time = Benchmark.realtime do
      count.times { Scrubber.sanitize(small_html) }
    end

    puts "  #{count} documents: #{(time * 1000).round(2)}ms total, #{(time / count * 1000).round(4)}ms avg"
    puts "  Throughput: #{(count / time).round(2)} docs/sec"
  end
end

# Test configuration switching performance
def test_configuration_switching
  puts "\nConfiguration Switching Performance"
  puts '=' * 40

  html = generate_large_html(50) # 50KB document

  configs = [
    { name: 'Default', config: {} },
    { name: 'Strict', config: { ALLOWED_TAGS: %w[p], ALLOWED_ATTRIBUTES: [] } },
    { name: 'Permissive', config: { ADDITIONAL_TAGS: %w[*], ADDITIONAL_ATTRIBUTES: %w[*] } },
    { name: 'Custom', config: { FORBIDDEN_TAGS: %w[script], FORBIDDEN_ATTR: %w[onclick] } }
  ]

  configs.each do |config_test|
    time = Benchmark.realtime do
      20.times { Scrubber.sanitize(html, config_test[:config]) }
    end

    puts "  #{config_test[:name]}: #{(time * 1000).round(2)}ms total, #{(time / 20 * 1000).round(2)}ms avg"
  end

  # Test rapid config switching
  switching_time = Benchmark.realtime do
    50.times do |i|
      config = configs[i % configs.length][:config]
      Scrubber.sanitize(html, config)
    end
  end

  puts "  Rapid switching: #{(switching_time * 1000).round(2)}ms total, #{(switching_time / 50 * 1000).round(2)}ms avg"
end

# Run all performance tests
if __FILE__ == $PROGRAM_NAME
  run_performance_tests
  test_memory_usage
  stress_test_small_documents
  test_configuration_switching

  puts "\nPerformance testing completed!"
end
