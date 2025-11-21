# frozen_string_literal: true

require 'nokogiri'
require 'set'
require 'uri'

require_relative 'scrubber/version'
require_relative 'scrubber/config'
require_relative 'scrubber/tags'
require_relative 'scrubber/attributes'
require_relative 'scrubber/expressions'
require_relative 'scrubber/utils'

# Scrubber - A robust HTML sanitizer for Ruby
#
# Scrubber is a Ruby implementation of DOMPurify, providing comprehensive XSS protection
# by sanitizing HTML strings and removing malicious payloads. It supports flexible
# configuration, hooks for custom processing, and handles various content types including
# HTML, SVG, and MathML.
#
# @example Basic usage
#   require 'scrubber'
#   scrubber = Scrubber.new
#   clean_html = scrubber.sanitize('<script>alert("xss")</script><p>Safe</p>')
#
# @example Configuration with block
#   scrubber = Scrubber.new do |config|
#     config.allowed_tags = ['p', 'b']
#     config.allowed_attributes = ['class']
#   end
#
# @see https://github.com/cure53/DOMPurify Original JavaScript implementation
module Scrubber
  class Error < StandardError; end

  # Main sanitizer class handling HTML sanitization logic
  #
  # This class manages the core sanitization process, configuration, and hooks.
  # It parses HTML, removes dangerous elements and attributes, and serializes the result.
  class Sanitizer
    attr_reader :removed, :config, :hooks

    # Initializes a new sanitizer instance
    #
    # @param config [Config] optional configuration object
    # @yield [config] optional block to configure instance config
    def initialize(config = nil)
      @removed = []
      @config = build_config(config)
      @hooks = create_hooks_map
      @is_supported = check_support
      yield(@config) if block_given?
    end

    # Hook management
    def add_hook(entry_point, &hook_function)
      return unless hook_function.is_a?(Proc)

      @hooks[entry_point] ||= []
      @hooks[entry_point] << hook_function
    end

    def remove_hook(entry_point, hook_function = nil)
      arr = @hooks[entry_point]
      return nil unless arr

      if hook_function
        idx = arr.rindex(hook_function)
        return nil unless idx

        arr.delete_at(idx)
      else
        arr.pop
      end
    end

    def remove_hooks(entry_point)
      @hooks[entry_point] = []
    end

    def remove_all_hooks
      @hooks = create_hooks_map
    end

    # Checks if the current environment supports Scrubber functionality
    #
    # @return [Boolean] true if Nokogiri is available, false otherwise
    def supported?
      @is_supported
    end

    # Sets configuration for the sanitizer
    #
    # @param cfg [Hash] configuration options
    def set_config(cfg = {})
      @config = parse_config(cfg)
    end

    # Configures the sanitizer with a block
    #
    # @yield [config] the configuration object to modify
    # @return [Sanitizer] the sanitizer instance
    def configure
      yield(@config) if block_given?
      self
    end

    # Clears current configuration, resetting to defaults
    def clear_config
      @config = parse_config({})
    end

    # Main sanitization method
    #
    # Parses the input HTML, sanitizes elements and attributes, and returns clean HTML.
    #
    # @param dirty [String, Nokogiri::XML::Node] the input to sanitize
    # @param cfg [Hash] optional configuration override
    # @return [String, Nokogiri::XML::Document] sanitized HTML or DOM
    def sanitize(dirty, cfg = {})
      return dirty unless supported?

      cfg.empty? ? ensure_config : set_config(cfg)
      @removed = []
      return '' if dirty.nil?
      return dirty.to_s if dirty.to_s.strip.empty?

      dirty = dirty.to_s unless dirty.is_a?(String)
      doc = parse_html(dirty)
      sanitize_document(doc)
      output = serialize_html(doc)

      output = resanitize_until_stable(output) if @config.sanitize_until_stable

      if @config.return_dom
        return parse_html(output)
      elsif @config.return_dom_fragment
        return Nokogiri::HTML5::DocumentFragment.parse(output)
      end

      output
    end

    private

    # Checks if required dependencies are available
    def check_support
      defined?(Nokogiri) && Nokogiri::VERSION
    end

    # Creates the default hooks map
    #
    # @return [Hash] hash of hook arrays keyed by hook name
    def create_hooks_map
      {
        before_sanitize_attributes: [],
        after_sanitize_attributes: [],
        before_sanitize_elements: [],
        after_sanitize_elements: [],
        upon_sanitize_attribute: [],
        upon_sanitize_element: []
      }
    end

    # Parses configuration options
    def parse_config(cfg = {})
      Config.new(cfg)
    end

    # Builds a configuration from hash or existing Config
    def build_config(cfg)
      return parse_config(cfg) if cfg.is_a?(Hash)
      return cfg if cfg.is_a?(Config)

      parse_config({})
    end

    # Ensures configuration is set
    def ensure_config
      @config ||= parse_config({})
    end

    # Parses HTML string into Nokogiri document
    #
    # @param html [String] HTML string to parse
    # @return [Nokogiri::XML::Document] parsed document
    def parse_html(html)
      html = "<remove></remove>#{html}" if @config.force_body
      if @config.parser_media_type == 'application/xhtml+xml' && @config.namespace == 'http://www.w3.org/1999/xhtml'
        html = "<html xmlns=\"http://www.w3.org/1999/xhtml\"><head></head><body>#{html}</body></html>"
      end
      if @config.whole_document || @config.return_dom || @config.allow_document_elements
        Nokogiri::HTML5.parse(html)
      else
        Nokogiri::HTML5.fragment(html)
      end
    end

    # Sanitizes the document by processing elements and attributes
    #
    # @param doc [Nokogiri::XML::Document] document to sanitize
    # @return [Nokogiri::XML::Document] sanitized document
    def sanitize_document(doc) # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
      doc.children.first.remove if @config.force_body && doc.children.first&.name == 'remove'
      execute_hooks(:before_sanitize_elements, doc)
      doc.traverse do |node|
        if node.element? && %w[script iframe frame frameset object embed template].include?(node.name)
          @removed << { element: node }
          node.remove
          next
        elsif node.element? && node.name == 'style'
          unless @config.allow_style_tags
            node.remove
            next
          end
          node.remove if unsafe_style_block?(node.content)
        elsif node.element?
          sanitize_element(node)
        elsif node.text? && @config.safe_for_templates
          sanitize_text_node(node)
        elsif node.comment? && @config.safe_for_xml
          sanitize_comment_node(node)
        end
      end
      execute_hooks(:after_sanitize_elements, doc)
    end

    def sanitize_element(node)
      tag_name = transform_case(node.name)
      # remove unknown namespace elements entirely (including content)
      if tag_name.include?(':')
        @removed << { element: node }
        node.remove
        return
      end
      execute_hooks(:upon_sanitize_element, node, { tag_name: tag_name })
      unless allowed_element?(tag_name)
        if @config.keep_content && !forbidden_content?(tag_name) && !@config.allowed_tags
          node.children.each { |child| node.add_next_sibling(child) }
        elsif @config.allowed_tags && node.children.any?
          node.add_next_sibling(Nokogiri::XML::Text.new(' ', node.document))
        end
        @removed << { element: node }
        node.remove
        return
      end
      sanitize_attributes(node)
    end

    # Sanitizes attributes of an element
    #
    # @param node [Nokogiri::XML::Element] element to sanitize attributes for
    def sanitize_attributes(node)
      tag_name = transform_case(node.name)
      to_remove = []
      dangerous_removed = false
      dangerous_attrs = %w[href content]
      dangerous_tags = %w[meta link]
      execute_hooks(:before_sanitize_attributes, node)
      node.attributes.each do |name, attr|
        lc_name = transform_case(name)
        value = attr.value
        execute_hooks(:upon_sanitize_attribute, attr, { tag_name: tag_name, attr_name: lc_name, value: value })
        next if valid_attribute?(tag_name, lc_name, value)

        to_remove << name
        @removed << { attribute: attr, from: node }
        dangerous_removed = true if dangerous_attrs.include?(lc_name) && dangerous_tags.include?(tag_name)
      end
      to_remove.each { |n| node.delete(n) }
      # Remove meta/link tags entirely if dangerous attributes were removed
      node.remove if dangerous_removed && dangerous_tags.include?(tag_name)
      execute_hooks(:after_sanitize_attributes, node)
    end

    # Checks if an element tag is allowed
    #
    # @param tag_name [String] the tag name to check
    # @return [Boolean] true if the tag is allowed, false otherwise
    def allowed_element?(tag_name)
      if !@config.whole_document && !@config.allow_document_elements && !@config.return_dom &&
          %w[html head body].include?(tag_name)
        return false
      end

      return false if @config.forbidden_tags&.include?(tag_name)

      unless @config.allowed_tags.nil?
        allowed = @config.allowed_tags.dup
        allowed.concat(@config.additional_tags) if @config.additional_tags
        is_included = allowed.include?(tag_name)
        return is_included
      end
      return true if @config.additional_tags&.include?(tag_name)
      return true if tag_name.include?('-')

      default_allowed_tags.include?(tag_name)
    end

    # Checks if an attribute is valid for a given tag
    #
    # @param tag_name [String] the element tag name
    # @param attr_name [String] the attribute name
    # @param value [String] the attribute value
    # @return [Boolean] true if the attribute is valid, false otherwise
    def valid_attribute?(tag_name, attr_name, value) # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
      # puts "Checking attribute: #{tag_name} #{attr_name}=#{value}"
      return false if @config.forbidden_attributes&.include?(attr_name)

      # Security: Check dangerous attributes (name and value) FIRST
      return false if Attributes::DANGEROUS.any? { |d| attr_name.match?(/#{d}/i) }
      if value && Attributes::DANGEROUS.any? do |d|
        value.match?(/#{d}/i)
      end && !(@config.allow_data_uri && value.match?(/^data:/i))
        return false
      end

      # Determine if attribute is allowed for this tag
      attr_allowed = nil # nil means "not yet determined"
      has_per_tag_rule = false

      # Check per-tag allowed attributes if configured
      if @config.allowed_attributes_per_tag.is_a?(Hash)
        per_tag_attrs = @config.allowed_attributes_per_tag[tag_name]
        if per_tag_attrs
          has_per_tag_rule = true
          attr_allowed = per_tag_attrs.include?(attr_name)
        end
      end

      # Check allowed attributes list if no per-tag rule applies
      if !has_per_tag_rule && !@config.allowed_attributes.nil?
        allowed = @config.allowed_attributes.dup
        allowed.concat(@config.additional_attributes) if @config.additional_attributes
        attr_allowed = allowed.include?(attr_name)
      end
      # else: attr_allowed stays nil, will use default permissive checks later

      # For style attributes, validate and sanitize
      if attr_name == 'style' && value && (attr_allowed || attr_allowed.nil?)
        sanitized_style = sanitize_style_value(value)
        return false unless sanitized_style

        # mutate value to the sanitized version
        attr_name.replace(attr_name)
        value.replace(sanitized_style) if value.respond_to?(:replace)
        return true
      end

      # DOM clobbering protection
      if @config.sanitize_dom && value && !value.to_s.strip.empty? && %w[name id].include?(attr_name) &&
          Attributes::DOM_CLOBBERING.include?(value.downcase)
        return false
      end

      # URI validation - CRITICAL: must validate URI safety even if attribute is allowed
      if uri_like?(attr_name) && value
        val = value.to_s
        return false if val.strip != val
        return false if val.match?(/[\x00-\x1f\x7f]/)

        decoded = begin
          URI.decode_www_form_component(val)
        rescue StandardError
          val
        end
        return false if @config.allowed_uri_regexp && !val.match?(@config.allowed_uri_regexp)

        # For URI attributes, check if it's allowed and has valid URI
        uri_allowed =  attr_allowed.nil? || attr_allowed # default to allowed if not explicitly set
        return true if uri_allowed && @config.allow_data_uri && decoded.match?(/^data:/i)
        return true if uri_allowed && decoded.match?(Expressions::IS_ALLOWED_URI)
        return true if uri_allowed && @config.allow_unknown_protocols && !decoded.match?(Expressions::IS_SCRIPT_OR_DATA)

        return false # Reject invalid URIs or non-allowed URI attributes
      end

      # For non-URI attributes, return based on whether attribute is allowed
      return attr_allowed if attr_allowed == true || attr_allowed == false

      # Default permissive checks (when no explicit allowed list is set)
      return true if @config.additional_attributes&.include?(attr_name)
      return true if @config.allow_data_attributes && attr_name.match?(Expressions::DATA_ATTR)
      return true if @config.allow_aria_attributes && attr_name.match?(Expressions::ARIA_ATTR)

      # Final fallback - if allowed_attributes is nil, use default behavior
      if @config.allow_unknown_protocols && value && !value.match?(Expressions::IS_SCRIPT_OR_DATA)
        return false if value.match?(/^data:/i) && !@config.allow_data_uri

        return true
      end

      false
    end

    # Checks if an attribute name is URI-like
    #
    # @param attr_name [String] the attribute name
    # @return [Boolean] true if the attribute is URI-like, false otherwise
    def uri_like?(attr_name)
      default_uri_safe_attributes.include?(attr_name) || @config.additional_uri_safe_attributes&.include?(attr_name)
    end

    def unsafe_inline_style?(value)
      normalized = value.downcase
      # Decode CSS hex escapes to surface hidden protocol names
      normalized = normalized.gsub(/\\([0-9a-f]{1,6})\s?/i) do
        [::Regexp.last_match(1).to_i(16)].pack('U')
      rescue StandardError
        ''
      end
      normalized = normalized.delete('\\')
      normalized = normalized.gsub(/\s+/, '')
      normalized.include?('javascript:') ||
        normalized.include?('expression(') ||
        normalized.include?('@import') ||
        normalized.include?('data:text/html') ||
        normalized.include?('data:image/svg+xml') ||
        normalized.include?('data:svg+xml') ||
        normalized.include?('behavior:') ||
        normalized.include?('binding:') ||
        normalized.match?(/url\([^)]*data:/i)
    end

    def sanitize_style_value(value)
      return nil if unsafe_inline_style?(value)
      return nil if value.match?(/\\[0-9a-f]{1,6}/i)

      allowed_props = Set.new(%w[
        align-content align-items align-self all animation animation-delay animation-direction animation-duration
        animation-fill-mode animation-iteration-count animation-name animation-play-state animation-timing-function
        background background-clip background-color background-image background-origin background-position
        background-repeat background-size border border-bottom border-bottom-color border-bottom-style
        border-bottom-width
        border-collapse border-color border-image border-left border-left-color border-left-style border-left-width
        border-radius border-right border-right-color border-right-style border-right-width border-spacing border-style
        border-top border-top-color border-top-style border-top-width border-width bottom box-shadow box-sizing
        caption-side clear clip color column-count column-fill column-gap column-rule column-rule-color
        column-rule-style
        column-rule-width column-span column-width columns content cursor direction display empty-cells filter flex
        flex-basis flex-direction flex-flow flex-grow flex-shrink flex-wrap float font font-family font-size
        font-size-adjust font-stretch font-style font-variant font-weight gap grid grid-area grid-auto-columns
        grid-auto-flow grid-auto-rows grid-column grid-column-end grid-column-gap grid-column-start grid-gap grid-row
        grid-row-end grid-row-gap grid-row-start grid-template grid-template-areas grid-template-columns
        grid-template-rows
        height justify-content left letter-spacing line-height list-style list-style-image
        list-style-position list-style-type
        margin margin-bottom margin-left margin-right margin-top max-height max-width min-height min-width opacity order
        outline outline-color outline-offset outline-style outline-width overflow overflow-x overflow-y padding
        padding-bottom padding-left padding-right padding-top page-break-after page-break-before page-break-inside
        perspective perspective-origin pointer-events position quotes resize right row-gap table-layout text-align
        text-align-last text-decoration text-decoration-color text-decoration-line text-decoration-style text-indent
        text-justify text-overflow text-shadow text-transform top transform transform-origin transition transition-delay
        transition-duration transition-property transition-timing-function unicode-bidi vertical-align visibility
        white-space width word-break word-spacing word-wrap writing-mode z-index
      ])

      declarations = value.split(';').map(&:strip).reject(&:empty?)
      sanitized = declarations.filter_map do |decl|
        prop, val = decl.split(':', 2).map { |p| p&.strip }
        next nil unless prop && val

        lc_prop = prop.downcase
        next nil unless allowed_props.include?(lc_prop)
        # reject dangerous urls/protocols in values
        next nil if unsafe_inline_style?(val)

        "#{lc_prop}:#{val}"
      end

      return nil if sanitized.empty?

      sanitized.join('; ')
    end

    def unsafe_style_block?(content)
      return false if content.nil? || content.strip.empty?

      unsafe_inline_style?(content)
    end

    def resanitize_until_stable(html)
      current = html
      max_passes = @config.mutation_max_passes.to_i
      return current if max_passes <= 1

      passes = 1
      while passes < max_passes
        doc = parse_html(current)
        sanitize_document(doc)
        next_output = serialize_html(doc)
        passes += 1
        break if next_output == current

        current = next_output
      end
      current
    end

    # Serializes the document back to HTML string
    #
    # @param doc [Nokogiri::XML::Document] document to serialize
    # @return [String] HTML string
    def serialize_html(doc)
      result = doc.respond_to?(:to_html) ? doc.to_html : doc.to_s
      result = fix_svg_self_closing_tags(result).gsub('&amp;unknown;', '&unknown;')
      # Remove encoded script blocks
      result = result.gsub(%r{&lt;script&gt;.*?&lt;/script&gt;}i, '')
      if !@config.whole_document && !@config.allow_document_elements && !@config.return_dom
        result = result.gsub(%r{</?(?:html|head|body)[^>]*>}i, '')
      end
      result
    end

    def fix_svg_self_closing_tags(html)
      %w[circle ellipse line path polygon polyline rect stop use].each do |tag|
        html = html.gsub(%r{<#{tag}([^>]*)></#{tag}>}, "<#{tag}\\1/>")
      end
      html
    end

    # Transforms tag/attribute names to lowercase if not XHTML
    #
    # @param str [String] string to transform
    # @return [String] transformed string
    def transform_case(str)
      @config&.parser_media_type == 'application/xhtml+xml' ? str : str.downcase
    end

    # Returns the default set of allowed tags
    #
    # @return [Set] set of allowed HTML, SVG, MathML, and text tags
    def default_allowed_tags
      @default_allowed_tags ||= begin
        source = @config.minimal_profile ? Tags::MINIMAL_HTML : Tags::HTML
        s = Set.new(source)
        unless @config.minimal_profile
          s.merge(Tags::SVG)
          s.merge(Tags::SVG_FILTERS)
          s.merge(Tags::MATH_ML)
        end
        s.merge(Tags::TEXT)
        s
      end
    end

    # Returns the default set of URI-safe attributes
    #
    # @return [Set] set of attributes that can contain URIs
    def default_uri_safe_attributes
      @default_uri_safe_attributes ||= Set.new(%w[href src xlink:href action formaction cite data poster alt class for
        id label name pattern placeholder role summary title value style xmlns filter])
    end

    # Checks if a tag's content should be forbidden
    #
    # @param tag_name [String] the tag name to check
    # @return [Boolean] true if content should be forbidden, false otherwise
    def forbidden_content?(tag_name)
      default_forbid_contents.include?(tag_name) || @config.forbid_contents&.include?(tag_name)
    end

    # Returns the default set of tags whose content should be forbidden
    #
    # @return [Set] set of tags with forbidden content
    def default_forbid_contents
      @default_forbid_contents ||= Set.new(%w[annotation-xml audio colgroup desc foreignobject head iframe math mi mn
        mo ms mtext noembed noframes noscript plaintext script style svg template thead title video xmp])
    end

    # Returns the set of tags that can have data URIs
    #
    # @return [Set] set of tags allowed to have data URIs
    def data_uri_tags
      @data_uri_tags ||= begin
        t = Set.new(%w[audio video img source image track])
        t.merge(@config.add_data_uri_tags) if @config.add_data_uri_tags
        t
      end
    end

    # Sanitizes text nodes by removing template expressions
    #
    # @param node [Nokogiri::XML::Text] text node to sanitize
    def sanitize_text_node(node)
      content = node.content
      [Expressions::MUSTACHE_EXPR, Expressions::ERB_EXPR, Expressions::TMPLIT_EXPR].each do |expr|
        content = content.gsub(expr, '  ')
      end
      return if node.content == content

      @removed << { element: node.dup }
      node.content = content
    end

    # Sanitizes comment nodes by removing them entirely
    #
    # @param node [Nokogiri::XML::Comment] comment node to sanitize
    def sanitize_comment_node(node)
      @removed << { element: node }
      node.remove
    end

    # Executes hooks for a given entry point
    #
    # @param entry_point [Symbol] the hook entry point
    # @param node [Nokogiri::XML::Node] the node being processed
    # @param data [Hash] additional data for the hook
    def execute_hooks(entry_point, node, data = nil)
      hooks = @hooks[entry_point]
      return unless hooks

      hooks.each { |h| h.call(node, data, @config) }
    end
  end

  # Builds a new sanitizer instance with optional configuration
  #
  # @param cfg [Hash, Config] optional configuration to initialize with
  # @yield [config] optional block to mutate configuration before use
  # @return [Sanitizer] a new sanitizer instance
  def self.new(cfg = {}, &block)
    Sanitizer.new(cfg, &block)
  end

  # Convenience helper to sanitize with a fresh, default-configured instance.
  #
  # @param dirty [String, Nokogiri::XML::Node] the input to sanitize
  # @param cfg [Hash] optional configuration override
  # @return [String, Nokogiri::XML::Document] sanitized HTML or DOM
  def self.sanitize(dirty, cfg = {})
    new(cfg).sanitize(dirty)
  end
end
