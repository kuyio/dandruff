# frozen_string_literal: true

require 'nokogiri'
require 'set'
require 'uri'

require_relative 'dandruff/version'
require_relative 'dandruff/config'
require_relative 'dandruff/tags'
require_relative 'dandruff/attributes'
require_relative 'dandruff/expressions'
require_relative 'dandruff/utils'

# Dandruff - A robust HTML sanitizer for Ruby
#
# Dandruff is a Ruby implementation inspired by DOMPurify, providing comprehensive XSS protection
# by sanitizing HTML strings and removing malicious payloads. It's designed for excellent developer
# experience while maintaining battle-tested security.
#
# ## Key Features
#
# - **Comprehensive XSS Protection**: Defends against XSS, mXSS, DOM clobbering, and protocol injection
# - **Flexible Configuration**: Fine-grained control over tags, attributes, and sanitization behavior
# - **Content Type Profiles**: Pre-configured settings for HTML, SVG, MathML, and HTML email
# - **Hook System**: Extend sanitization with custom processing logic
# - **Developer-Friendly API**: Intuitive Ruby idioms with block-based configuration
# - **Battle-Tested Security**: Based on DOMPurify's proven security model
# - **Performance Optimized**: Efficient multi-pass sanitization with configurable limits
#
# ## Quick Start
#
# @example Basic sanitization
#   require 'dandruff'
#
#   dandruff = Dandruff.new
#   clean = dandruff.sanitize('<script>alert("xss")</script><p>Safe content</p>')
#   # => "<p>Safe content</p>"
#
# @example Configure with block
#   dandruff = Dandruff.new do |config|
#     config.allowed_tags = ['p', 'strong', 'em', 'a']
#     config.allowed_attributes = ['href', 'title', 'class']
#   end
#
# @example Use convenience class method
#   clean = Dandruff.sanitize(dirty_html, allowed_tags: ['p', 'strong'])
#
# @example Profile-based configuration
#   dandruff = Dandruff.new do |config|
#     config.use_profiles = { html: true, svg: true }
#   end
#
# @example Per-tag attribute control
#   dandruff = Dandruff.new do |config|
#     config.allowed_attributes_per_tag = {
#       'a' => ['href', 'title'],
#       'img' => ['src', 'alt', 'width', 'height']
#     }
#   end
#
# @example Custom hooks
#   dandruff = Dandruff.new
#   dandruff.add_hook(:upon_sanitize_attribute) do |node, data, config|
#     # Custom attribute processing
#     if data[:attr_name] == 'data-safe'
#       data[:keep_attr] = true
#     end
#   end
#
# ## Security
#
# Dandruff protects against multiple attack vectors:
# - **XSS**: Removes script tags, event handlers, javascript: URIs
# - **mXSS**: Multi-pass sanitization prevents mutation-based attacks
# - **DOM Clobbering**: Blocks dangerous id/name attribute values
# - **Protocol Injection**: Validates URI protocols (javascript:, vbscript:, data:text/html)
# - **Namespace Confusion**: Prevents mXSS via SVG/MathML namespace attacks
# - **CSS Injection**: Sanitizes inline styles and style tag content
#
# @see https://github.com/kuyio/dandruff GitHub repository
# @see https://github.com/cure53/DOMPurify Original JavaScript implementation
# @see Config Configuration options reference
# @see Sanitizer Core sanitization engine
module Dandruff
  class Error < StandardError; end

  # Main sanitizer class handling HTML sanitization logic
  #
  # This class manages the core sanitization process, configuration, and hooks.
  # It parses HTML, removes dangerous elements and attributes, and serializes the result.
  class Sanitizer
    MATH_SVG_TAGS = %w[math svg].freeze
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

    # Checks if the current environment supports Dandruff functionality
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
    alias_method :scrub, :sanitize

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
      if @config.whole_document || @config.return_dom || @config.allow_document_elements || html.match?(/<frameset/i)
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
        if node.element? && %w[script iframe frame frameset object embed].include?(node.name)
          @removed << { element: node }
          if node.name == 'frameset'
            parent = node.parent
            # puts "Removing frameset and parent: #{parent&.name}"
            node.remove
            parent&.remove
          else
            node.remove
          end
          next
        elsif node.element? && node.name == 'style'
          node.remove && next unless @config.allow_style_tags

          if unsafe_style_node?(node)
            node.remove
            next
          end
        elsif node.element?
          sanitize_element(node)
        elsif node.text? && @config.safe_for_templates
          sanitize_text_node(node)
        elsif node.comment? && @config.safe_for_xml
          sanitize_comment_node(node)
        elsif node.cdata?
          node.replace(Nokogiri::XML::Text.new(node.text, node.document))
        end
      end
      execute_hooks(:after_sanitize_elements, doc)
    end

    def sanitize_element(node)
      tag_name = transform_case(node.name)

      return if handle_isindex(node, tag_name)
      return if handle_dangerous_math_svg(node)
      return if handle_namespace_check(node)
      return if handle_prefixed_element(node, tag_name)

      execute_hooks(:upon_sanitize_element, node, { tag_name: tag_name })

      unless allowed_element?(tag_name)
        handle_disallowed_element(node, tag_name)
        return
      end

      sanitize_attributes(node)
      handle_vml_namespace(node)
    end

    # Sanitizes attributes of an element
    #
    # @param node [Nokogiri::XML::Element] element to sanitize attributes for
    def sanitize_attributes(node)
      tag_name = transform_case(node.name)
      to_remove = []
      dangerous_removed = false
      had_xlink_href = node.key?('xlink:href')

      execute_hooks(:before_sanitize_attributes, node)

      node.attributes.each do |name, attr|
        lc_name = normalize_attribute_name(name, attr)

        handle_is_attribute(attr, lc_name)
        value = attr.value

        handle_xlink_namespace_definition(node, lc_name)

        had_xlink_href ||= (lc_name == 'xlink:href')
        had_xlink_href ||= (attr.namespace&.href == 'http://www.w3.org/1999/xlink')

        execute_hooks(:upon_sanitize_attribute, attr, { tag_name: tag_name, attr_name: lc_name, value: value })

        if valid_attribute?(tag_name, lc_name, value)
          attr.value = value if value != attr.value
        else
          to_remove << name
          @removed << { attribute: attr, from: node }
          dangerous_removed = true if dangerous_attribute_removed?(lc_name, tag_name)
        end
      end

      to_remove.each { |n| node.delete(n) }

      # Remove meta/link tags entirely if dangerous attributes were removed
      if dangerous_removed && %w[meta link].include?(tag_name)
        node.remove
        return
      end

      ensure_alt_attribute(node, tag_name)
      ensure_xlink_namespace(node) if had_xlink_href || node.key?('xlink:href')

      execute_hooks(:after_sanitize_attributes, node)
    end

    def build_isindex_replacement(node)
      doc = node.document
      form = Nokogiri::XML::Node.new('form', doc)
      hr1 = Nokogiri::XML::Node.new('hr', doc)
      hr2 = Nokogiri::XML::Node.new('hr', doc)
      label = Nokogiri::XML::Node.new('label', doc)
      label.content = 'This is a searchable index. Enter search keywords: '
      input = Nokogiri::XML::Node.new('input', doc)
      if node['src']
        input['name'] = 'isindex'
        input['label'] = node['label'] if node['label']
      else
        input['label'] = node['label'] if node['label']
        input['name'] = 'isindex'
      end
      label.add_child(input)
      form.add_child(hr1)
      form.add_child(label)
      form.add_child(hr2)
      form
    rescue StandardError
      nil
    end

    # Checks if an element tag is allowed
    #
    # @param tag_name [String] the tag name to check
    # @return [Boolean] true if the tag is allowed, false otherwise
    # rubocop:disable Metrics/CyclomaticComplexity
    def allowed_element?(tag_name)
      if !@config.whole_document && !@config.allow_document_elements && !@config.return_dom &&
          %w[html head body].include?(tag_name)
        return false
      end

      return false if @config.forbidden_tags&.include?(tag_name)

      unless @config.allowed_tags.nil?
        allowed = @config.allowed_tags.dup.map { |t| transform_case(t) }
        allowed.concat(@config.additional_tags) if @config.additional_tags
        is_included = allowed.include?(tag_name)
        return is_included
      end
      return true if @config.additional_tags&.map { |t| transform_case(t) }&.include?(tag_name)

      default_allowed_tags.include?(tag_name)
    end
    # rubocop:enable Metrics/CyclomaticComplexity

    # Checks if an attribute is valid for a given tag
    #
    # @param tag_name [String] the element tag name
    # @param attr_name [String] the attribute name
    # @param value [String] the attribute value
    # @return [Boolean] true if the attribute is valid, false otherwise
    # Checks if an attribute is valid for a given tag
    #
    # @param tag_name [String] the element tag name
    # @param attr_name [String] the attribute name
    # @param value [String] the attribute value
    # @return [Boolean] true if the attribute is valid, false otherwise
    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
    def valid_attribute?(tag_name, attr_name, value)
      return false if forbidden_attribute?(attr_name)
      return false if dangerous_attribute?(attr_name)

      attr_allowed = attribute_allowed?(tag_name, attr_name)

      return true if data_attribute_allowed?(attr_name)
      return true if aria_attribute_allowed?(attr_name)
      return true if attr_name == 'is'

      if attr_name == 'style'
        return false unless attr_allowed || attr_allowed.nil?

        return valid_style_attribute?(value)
      end

      return false if @config.sanitize_dom && dom_clobbering_attribute?(attr_name, value)

      return valid_uri_attribute?(tag_name, value, attr_allowed) if uri_like?(attr_name) && value

      return attr_allowed if [true, false].include?(attr_allowed)

      # Default permissive checks
      return true if @config.additional_attributes&.include?(attr_name)

      allow_unknown_protocols_fallback?(value)
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

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
      normalized = normalized.delete('\\') # Remove backslashes after decoding hex escapes
      # Check for truly dangerous CSS patterns
      # More lenient than before to match DOMPurify behavior
      normalized = normalized.gsub(/\s+/, '') # Remove all whitespace for easier matching

      # Dangerous: javascript/vbscript/data protocols in background/import
      return true if normalized.match?(/javascript:/i) && normalized.match?(/background|@import/i)
      return true if normalized.match?(/vbscript:/i)

      # Dangerous: expression() (IE)
      return true if normalized.include?('expression(')

      # Dangerous: @import (can load external stylesheets)
      return true if normalized.match?(/@import\s*url/i)

      # Dangerous: data:text/html (can contain scripts)
      return true if normalized.include?('data:text/html')

      # Note: behavior:, binding:, data:image/svg+xml in content/filter are SAFE
      # These are only dangerous in specific contexts that modern browsers don't execute

      false
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

    # Checks if a node is within a MathML or SVG context
    #
    # @param node [Nokogiri::XML::Element] element to check
    # @return [Boolean] true if inside math or svg element
    def in_math_or_svg_context?(node)
      current = node.parent
      while current
        if current.respond_to?(:element?) && current.element? && MATH_SVG_TAGS.include?(current.name.downcase)
          return true
        end
        break unless current.respond_to?(:parent)

        current = current.parent
      end
      false
    end

    # Checks if an element is dangerous when inside MathML/SVG context
    #
    # @param node [Nokogiri::XML::Element] element to check
    # @return [Boolean] true if element can cause mXSS in math/svg context
    def dangerous_in_math_svg?(node)
      return false unless node.element?

      tag = node.name.downcase
      return false unless in_math_or_svg_context?(node)

      # These elements can cause mXSS when inside MathML/SVG
      # - style: can break out of context with </style><img onerror=...>
      # - title: similar context confusion
      # - mglyph: not standard in MathML 3.0, used in nesting attacks
      %w[style title mglyph].include?(tag)
    end

    def unsafe_style_node?(node)
      parent_name = node.parent&.name
      top_level = parent_name.nil? || parent_name == '#document' || parent_name == '#document-fragment' ||
        %w[html head body].include?(parent_name)

      # For whole_document/html_email profiles, allow style tags at top level (in head/body)
      # This is safe because the entire document structure is being preserved
      if @config.whole_document && @config.allow_style_tags
        # Only block style in truly unsafe contexts (e.g., option/select)
        return true if %w[option select].include?(parent_name)

        # Allow style tags even if they contain CSS content
        return false
      end

      # For non-whole-document contexts, block top-level style tags as they're unexpected
      return true if top_level
      return true if %w[option select].include?(parent_name)
      return true if node.content.include?('<') || node.element_children.any?

      false
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
      result = result.sub(/\A\n+/, '')
      result = fix_svg_self_closing_tags(result).gsub('&amp;unknown;', '&unknown;')
      # Remove encoded script blocks
      result = result.gsub(%r{&lt;script&gt;.*?&lt;/script&gt;}i, '')
      if !@config.whole_document && !@config.allow_document_elements && !@config.return_dom
        result = result.gsub(%r{</?(?:html|head|body)(?:\s[^>]*)?>}i, '')
      end
      result
    end

    def fix_svg_self_closing_tags(html)
      %w[circle ellipse line path polygon polyline rect stop use feimage mask g defs].each do |tag|
        html = html.gsub(%r{<#{tag}([^>]*)/>}, "<#{tag}\\1></#{tag}>")
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
        s = Set.new(source.map { |t| transform_case(t) })
        unless @config.minimal_profile
          s.merge(Tags::SVG.map { |t| transform_case(t) })
          s.merge(Tags::SVG_FILTERS.map { |t| transform_case(t) })
          s.merge(Tags::MATH_ML.map { |t| transform_case(t) })
        end
        s.merge(Tags::TEXT.map { |t| transform_case(t) })
        s
      end
    end

    # Returns the default set of URI-safe attributes
    #
    # @return [Set] set of attributes that can contain URIs
    def default_uri_safe_attributes
      @default_uri_safe_attributes ||= Set.new(%w[href src xlink:href action formaction cite data poster background
        srcset])
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

    # Helper methods for sanitize_element

    # Handles the deprecated isindex element by converting it to a form
    #
    # @param node [Nokogiri::XML::Element] the element node
    # @param tag_name [String] the tag name
    # @return [Boolean] true if handled (removed/replaced), false otherwise
    def handle_isindex(node, tag_name)
      return false unless tag_name == 'isindex'

      replacement = build_isindex_replacement(node)
      node.add_next_sibling(replacement) if replacement
      @removed << { element: node }
      node.remove
      true
    end

    # Removes elements that are dangerous in MathML/SVG contexts
    #
    # @param node [Nokogiri::XML::Element] the element node
    # @return [Boolean] true if removed, false otherwise
    def handle_dangerous_math_svg(node)
      return false unless dangerous_in_math_svg?(node)

      @removed << { element: node }
      node.remove
      true
    end

    # Checks and handles element namespaces
    #
    # @param node [Nokogiri::XML::Element] the element node
    # @return [Boolean] true if removed due to invalid namespace, false otherwise
    def handle_namespace_check(node)
      return false unless node.namespace&.href
      return false if ['http://www.w3.org/1999/xhtml', 'http://www.w3.org/2000/svg', 'http://www.w3.org/1998/Math/MathML'].include?(node.namespace.href)

      node.children.to_a.each { |child| node.add_previous_sibling(child) } if @config.keep_content
      @removed << { element: node }
      node.remove
      true
    end

    # Handles elements with namespace prefixes
    #
    # @param node [Nokogiri::XML::Element] the element node
    # @param tag_name [String] the tag name
    # @return [Boolean] true if handled (removed), false otherwise
    def handle_prefixed_element(node, tag_name)
      return false unless tag_name.include?(':')

      prefix = tag_name.split(':').first.downcase
      if %w[xml xmlns].include?(prefix)
        if @config.keep_content
          text_nodes = []
          node.traverse { |n| text_nodes << n if n.text? }
          text_nodes.each { |text_node| node.add_previous_sibling(text_node.dup) }
        end
        @removed << { element: node }
        node.remove
        return true
      end

      node.children.to_a.each { |child| node.add_previous_sibling(child) } if @config.keep_content
      @removed << { element: node }
      node.remove
      true
    end

    # Handles elements that are not allowed by the configuration
    #
    # @param node [Nokogiri::XML::Element] the element node
    # @param tag_name [String] the tag name
    def handle_disallowed_element(node, tag_name)
      replaced_children = false
      if @config.keep_content && !forbidden_content?(tag_name) && !@config.allowed_tags
        if node.children.any?
          node.children.to_a.each { |child| node.add_previous_sibling(child) }
          replaced_children = true
        else
          node.remove
        end
      elsif @config.allowed_tags && node.children.any?
        node.add_next_sibling(Nokogiri::XML::Text.new(' ', node.document))
      end
      @removed << { element: node }
      node.remove unless replaced_children
    end

    # Removes elements with VML namespace
    #
    # @param node [Nokogiri::XML::Element] the element node
    def handle_vml_namespace(node)
      return unless node['xmlns']&.match?(/vml/i)

      @removed << { element: node }
      node.remove
    end

    # Helper methods for sanitize_attributes

    # Normalizes attribute name handling namespaces
    #
    # @param name [String] attribute name
    # @param attr [Nokogiri::XML::Attr] attribute object
    # @return [String] normalized attribute name
    def normalize_attribute_name(name, attr)
      if attr.namespace&.prefix == 'xmlns'
        name == 'xmlns' ? 'xmlns' : "xmlns:#{transform_case(name)}"
      else
        transform_case(name)
      end
    end

    # Handles the 'is' attribute by clearing its value
    #
    # @param attr [Nokogiri::XML::Attr] attribute object
    # @param lc_name [String] lowercased attribute name
    def handle_is_attribute(attr, lc_name)
      return unless lc_name == 'is'

      attr.value = ''
    end

    # Adds xlink namespace definition if needed
    #
    # @param node [Nokogiri::XML::Element] the element node
    # @param lc_name [String] lowercased attribute name
    def handle_xlink_namespace_definition(node, lc_name)
      return unless lc_name.start_with?('xlink:')

      begin
        node.add_namespace_definition('xlink', 'http://www.w3.org/1999/xlink')
      rescue StandardError
        nil
      end
    end

    # Checks if a removed attribute was dangerous enough to warrant removing the element
    #
    # @param lc_name [String] lowercased attribute name
    # @param tag_name [String] tag name
    # @return [Boolean] true if dangerous
    def dangerous_attribute_removed?(lc_name, tag_name)
      %w[href content].include?(lc_name) && %w[meta link].include?(tag_name)
    end

    # Ensures img tags have an alt attribute if allowed
    #
    # @param node [Nokogiri::XML::Element] the element node
    # @param tag_name [String] tag name
    def ensure_alt_attribute(node, tag_name)
      return unless tag_name == 'img' && @config.allowed_attributes_per_tag.is_a?(Hash)

      allowed = @config.allowed_attributes_per_tag['img']
      node['alt'] = '' if allowed&.include?('alt') && !node.key?('alt')
    end

    # Ensures xlink namespace is present if needed
    #
    # @param node [Nokogiri::XML::Element] the element node
    def ensure_xlink_namespace(node)
      return if node['xmlns:xlink']

      node['xmlns:xlink'] = 'http://www.w3.org/1999/xlink'
      begin
        node.add_namespace_definition('xlink', 'http://www.w3.org/1999/xlink')
      rescue StandardError
        nil
      end
    end

    # Helper methods for valid_attribute?

    # Checks if an attribute is explicitly forbidden
    #
    # @param attr_name [String] attribute name
    # @return [Boolean] true if forbidden
    def forbidden_attribute?(attr_name)
      @config.forbidden_attributes&.include?(attr_name)
    end

    # Checks if an attribute is inherently dangerous
    #
    # @param attr_name [String] attribute name
    # @return [Boolean] true if dangerous
    def dangerous_attribute?(attr_name)
      Attributes::DANGEROUS.any? { |d| attr_name.match?(/#{d}/i) }
    end

    # Checks if an attribute is allowed for a specific tag
    #
    # @param tag_name [String] tag name
    # @param attr_name [String] attribute name
    # @return [Boolean, nil] true/false if determined, nil if no rule found
    def attribute_allowed?(tag_name, attr_name)
      if @config.allowed_attributes_per_tag.is_a?(Hash)
        per_tag_attrs = @config.allowed_attributes_per_tag[tag_name]
        return per_tag_attrs.map { |a| transform_case(a) }.include?(attr_name) if per_tag_attrs
      end

      return check_global_allowed_attributes(attr_name) unless @config.allowed_attributes.nil?

      check_default_allowed_attributes(tag_name, attr_name)
    end

    # Checks global allowed attributes list
    #
    # @param attr_name [String] attribute name
    # @return [Boolean] true if allowed
    def check_global_allowed_attributes(attr_name)
      allowed = @config.allowed_attributes.dup.map { |a| transform_case(a) }
      allowed.concat(@config.additional_attributes&.map { |a| transform_case(a) }) if @config.additional_attributes
      allowed.include?(attr_name)
    end

    # Checks default allowed attributes based on tag type
    #
    # @param tag_name [String] tag name
    # @param attr_name [String] attribute name
    # @return [Boolean, nil] true if allowed, nil otherwise
    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
    def check_default_allowed_attributes(tag_name, attr_name)
      html_attrs = @html_attrs ||= Attributes::HTML.map { |a| transform_case(a) }.to_set
      svg_attrs = @svg_attrs ||= (Attributes::SVG + Attributes::XML).map { |a| transform_case(a) }.to_set
      math_attrs = @math_attrs ||= (Attributes::MATH_ML + Attributes::XML).map { |a| transform_case(a) }.to_set

      @html_tags_set ||= Tags::HTML.map { |t| transform_case(t) }.to_set
      @svg_tags_set ||= (Tags::SVG + Tags::SVG_FILTERS).map { |t| transform_case(t) }.to_set
      @math_tags_set ||= Tags::MATH_ML.map { |t| transform_case(t) }.to_set

      is_svg = @svg_tags_set.include?(tag_name)
      is_math = @math_tags_set.include?(tag_name)
      is_html = @html_tags_set.include?(tag_name)

      # Default to HTML if not recognized as standard tag but allowed
      is_html = true if !is_svg && !is_math

      attr_allowed = false
      attr_allowed ||= svg_attrs.include?(attr_name) if is_svg
      attr_allowed ||= math_attrs.include?(attr_name) if is_math
      attr_allowed ||= html_attrs.include?(attr_name) if is_html
      attr_allowed ? true : nil
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

    # Checks if data attributes are allowed
    #
    # @param attr_name [String] attribute name
    # @return [Boolean] true if allowed
    def data_attribute_allowed?(attr_name)
      @config.allow_data_attributes && attr_name.match?(Expressions::DATA_ATTR)
    end

    # Checks if ARIA attributes are allowed
    #
    # @param attr_name [String] attribute name
    # @return [Boolean] true if allowed
    def aria_attribute_allowed?(attr_name)
      @config.allow_aria_attributes && attr_name.match?(Expressions::ARIA_ATTR)
    end

    # Validates style attribute value
    #
    # @param value [String] attribute value
    # @return [Boolean] true if valid
    def valid_style_attribute?(value)
      return false if value && unsafe_inline_style?(value.to_s)

      true
    end

    # Checks for DOM clobbering via attributes
    #
    # @param attr_name [String] attribute name
    # @param value [String] attribute value
    # @return [Boolean] true if clobbering detected
    def dom_clobbering_attribute?(attr_name, value)
      value && !value.to_s.strip.empty? && %w[name id].include?(attr_name) &&
        Attributes::DOM_CLOBBERING.include?(value.downcase)
    end

    # Validates URI attributes
    #
    # @param tag_name [String] tag name
    # @param _attr_name [String] attribute name (unused)
    # @param value [String] attribute value
    # @param attr_allowed [Boolean] whether attribute is allowed
    # @return [Boolean] true if valid
    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
    def valid_uri_attribute?(tag_name, value, attr_allowed)
      val = value.to_s
      leading_space_pattern = /\A[\s\u0085\u00a0\u1680\u180e\u2000-\u200b\u2028\u2029\u205f\u3000]+/
      trailing_space_pattern = /[\s\u0085\u00a0\u1680\u180e\u2000-\u200b\u2028\u2029\u205f\u3000]+\z/
      val = val.gsub(leading_space_pattern, '').gsub(trailing_space_pattern, '')
      value.replace(val) if value.respond_to?(:replace) && value != val
      return false if val.match?(/[\x00-\x1f\x7f]/)

      decoded = begin
        URI.decode_www_form_component(val)
      rescue StandardError
        val
      end
      return false if @config.allowed_uri_regexp && !val.match?(@config.allowed_uri_regexp)

      # For URI attributes, check if it's allowed and has valid URI
      uri_allowed = attr_allowed.nil? || attr_allowed # default to allowed if not explicitly set
      return false if decoded.match?(Expressions::IS_SCRIPT_OR_DATA)

      if decoded.match?(/^data:/i)
        return true if uri_allowed && @config.allow_data_uri && data_uri_tags.include?(tag_name)

        return false
      end

      return true if uri_allowed && decoded.match?(Expressions::IS_ALLOWED_URI)
      return true if uri_allowed && @config.allow_unknown_protocols && !decoded.match?(Expressions::IS_SCRIPT_OR_DATA)

      false # Reject invalid URIs or non-allowed URI attributes
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

    # Fallback check for unknown protocols
    #
    # @param value [String] attribute value
    # @return [Boolean] true if allowed
    def allow_unknown_protocols_fallback?(value)
      if @config.allow_unknown_protocols && value && !value.match?(Expressions::IS_SCRIPT_OR_DATA)
        return false if value.match?(/^data:/i) && !@config.allow_data_uri

        return true
      end

      false
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

  class << self
    alias_method :scrub, :sanitize
  end
end
