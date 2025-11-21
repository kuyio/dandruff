#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'lib/scrubber'
require_relative 'lib/scrubber/version'

Gem::Specification.new do |spec|
  spec.name        = 'scrubber'
  spec.version     = Scrubber::VERSION
  spec.authors     = ['Scrubber Ruby Contributors']
  spec.email       = ['dev@kuy.io']

  spec.summary     = 'Scrubber – Ruby HTML sanitizer'
  spec.description = 'Scrubber is a Ruby HTML sanitizer providing robust XSS protection ' \
                     'with a clean, idiomatic configuration API.'
  spec.homepage    = 'https://github.com/kuyio/scrubber'
  spec.license     = 'Apache-2.0'
  spec.required_ruby_version = '>= 2.7.0' # rubocop:disable Gemspec/RequiredRubyVersion

  spec.metadata['source_code_uri'] = spec.homepage
  spec.metadata['changelog_uri']   = "#{spec.homepage}/blob/main/CHANGELOG.md"

  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'nokogiri', '~> 1.10'

  spec.add_development_dependency 'benchmark', '~> 0.5'
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'rubocop', '~> 1.21'
  spec.metadata['rubygems_mfa_required'] = 'true'
end
