#!/usr/bin/env ruby
# frozen_string_literal: true

require 'bundler/setup'

require 'dandruff'

# Example usage demonstrating Dandruff Ruby functionality

puts 'Dandruff Ruby Examples'
puts '========================'
puts

# Basic sanitization
puts '1. Basic sanitization:'
dirty = '<script>alert("xss")</script><p>Safe content</p>'
dandruff = Dandruff.new
clean = dandruff.sanitize(dirty)
puts "  Original: #{dirty}"
puts "  Clean:    #{clean}"
puts

# Removing dangerous attributes
puts '2. Removing dangerous attributes:'
dirty = '<div onclick="alert(\'xss\')" class="safe">Click me</div>'
dandruff = Dandruff.new
clean = dandruff.sanitize(dirty)
puts "  Original: #{dirty}"
puts "  Clean:    #{clean}"
puts

# Configuration example
puts '3. Custom configuration:'
dandruff = Dandruff.new do |c|
  c.allowed_tags = %w[p b i]
  c.allowed_attributes = ['class']
end
dirty = '<p class="text"><b>Bold</b> <i>Italic</i></p>'
clean = dandruff.sanitize(dirty)
puts "  Original: #{dirty}"
puts "  Clean:    #{clean}"
puts

# Data attributes
puts '4. Data attributes:'
dirty = '<div data-user="123" data-role="admin">User content</div>'
dandruff = Dandruff.new
clean = dandruff.sanitize(dirty)
puts "  Original: #{dirty}"
puts "  Clean:    #{clean}"
puts

# Template safety
puts '5. Template safety:'
dirty = '<p>{{ user_input }}</p><script>${malicious()}</script>'
dandruff = Dandruff.new
clean = dandruff.sanitize(dirty, safe_for_templates: true)
puts "  Original: #{dirty}"
puts "  Clean:    #{clean}"
puts

# Hooks example
puts '6. Using hooks:'
hook_called = false
dandruff = Dandruff.new
dandruff.add_hook(:before_sanitize_elements) do |node, _data, _config|
  hook_called = true
  puts "    Hook: Processing #{node.name} element"
end

dandruff.sanitize('<div>Test</div>')
puts "    Hook was called: #{hook_called}"
puts

# Profiles
puts '7. Using profiles:'
dandruff = Dandruff.new(use_profiles: { svg: true })
dirty = '<svg><circle r="10" fill="red"/></svg>'
clean = dandruff.sanitize(dirty)
puts "  Original: #{dirty}"
puts "  Clean:    #{clean}"
puts

puts 'Examples completed!'
