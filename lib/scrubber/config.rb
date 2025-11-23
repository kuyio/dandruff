# frozen_string_literal: true

module Scrubber
  # Configuration class for the Scrubber sanitizer
  #
  # This class manages all configuration options for customizing HTML sanitization behavior.
  # It provides sensible security-focused defaults and allows fine-grained control through
  # numerous configuration options. Configuration can be set during initialization or modified
  # later through accessor methods.
  #
  # @example Basic configuration
  #   config = Scrubber::Config.new(
  #     allowed_tags: ['p', 'strong', 'em'],
  #     allowed_attributes: ['class', 'href']
  #   )
  #
  # @example Using profiles
  #   config = Scrubber::Config.new(use_profiles: { html: true, svg: true })
  #
  # @example Block configuration
  #   scrubber = Scrubber.new do |config|
  #     config.allowed_tags = ['p', 'a']
  #     config.forbidden_attributes = ['onclick']
  #   end
  #
  # @see Sanitizer Main sanitizer class that uses this configuration
  class Config
    # @!attribute [rw] additional_attributes
    #   Additional attributes to allow beyond defaults
    #   @return [Array<String>] array of attribute names to add to allowlist
    #   @example
    #     config.additional_attributes = ['data-custom', 'aria-label']

    # @!attribute [rw] additional_tags
    #   Additional tags to allow beyond defaults
    #   @return [Array<String>] array of tag names to add to allowlist
    #   @example
    #     config.additional_tags = ['custom-element', 'web-component']

    # @!attribute [rw] additional_uri_safe_attributes
    #   Additional attributes that should be treated as URIs and validated
    #   @return [Array<String>] array of attribute names
    #   @example
    #     config.additional_uri_safe_attributes = ['data-link', 'poster']

    # @!attribute [rw] allow_aria_attributes
    #   Allow aria-* attributes for accessibility
    #   @return [Boolean] true to allow aria attributes (default: true)

    # @!attribute [rw] allow_data_attributes
    #   Allow data-* attributes for custom data
    #   @return [Boolean] true to allow data attributes (default: true)

    # @!attribute [rw] allow_data_uri
    #   Allow data: URIs in src and other URI attributes
    #   @return [Boolean] true to allow data URIs (default: true for safe elements)
    #   @note Data URIs can be large and may pose security risks if not validated

    # @!attribute [rw] allow_unknown_protocols
    #   Allow URI protocols not in the default safe list
    #   @return [Boolean] true to allow unknown protocols (default: false)
    #   @note Enabling this reduces security - use with caution

    # @!attribute [rw] allow_self_close_in_attributes
    #   Allow self-closing syntax in attributes
    #   @return [Boolean] (default: true)

    # @!attribute [rw] allowed_attributes
    #   Exact allowlist of attributes (replaces defaults when set)
    #   @return [Array<String>, nil] array of allowed attributes or nil to use defaults
    #   @example
    #     config.allowed_attributes = ['href', 'class', 'id']

    # @!attribute [rw] allowed_attributes_per_tag
    #   Per-tag attribute restrictions for fine-grained control
    #   @return [Hash<String, Array<String>>, nil] hash mapping tag names to allowed attributes
    #   @example
    #     config.allowed_attributes_per_tag = {
    #       'a' => ['href', 'title'],
    #       'img' => ['src', 'alt']
    #     }

    # @!attribute [rw] allowed_tags
    #   Exact allowlist of tags (replaces defaults when set)
    #   @return [Array<String>, nil] array of allowed tags or nil to use defaults
    #   @example
    #     config.allowed_tags = ['p', 'strong', 'em', 'a']

    # @!attribute [rw] allowed_uri_regexp
    #   Custom regexp for validating URI attributes
    #   @return [Regexp, nil] custom URI validation pattern or nil for default
    #   @example Only allow HTTPS
    #     config.allowed_uri_regexp = /^https:/

    # @!attribute [rw] forbidden_attributes
    #   Attributes that are always removed (takes precedence over allowed)
    #   @return [Array<String>] array of forbidden attribute names
    #   @example
    #     config.forbidden_attributes = ['onclick', 'onerror']

    # @!attribute [rw] forbidden_tags
    #   Tags that are always removed (takes precedence over allowed)
    #   @return [Array<String>] array of forbidden tag names
    #   @example
    #     config.forbidden_tags = ['script', 'iframe']

    # @!attribute [rw] allow_style_tags
    #   Allow <style> tags with content sanitization
    #   @return [Boolean] true to allow style tags (default: true)
    #   @note Style tag content is scanned for unsafe patterns

    # @!attribute [rw] allow_document_elements
    #   Allow html/head/body document structure elements
    #   @return [Boolean] true to allow document elements (default: false)

    # @!attribute [rw] keep_content
    #   Keep text content when removing disallowed tags
    #   @return [Boolean] true to preserve content (default: true)
    #   @example
    #     # With keep_content: true
    #     # <script>alert()</script>Hello -> Hello
    #     # With keep_content: false
    #     # <script>alert()</script>Hello -> (empty)

    # @!attribute [rw] return_dom
    #   Return Nokogiri document instead of HTML string
    #   @return [Boolean] true to return DOM (default: false)

    # @!attribute [rw] return_dom_fragment
    #   Return Nokogiri fragment instead of HTML string
    #   @return [Boolean] true to return fragment (default: false)

    # @!attribute [rw] whole_document
    #   Parse and sanitize as complete HTML document
    #   @return [Boolean] true for whole document (default: false)

    # @!attribute [rw] safe_for_templates
    #   Remove template expressions ({{, <%= , ${)
    #   @return [Boolean] true to remove templates (default: false)

    # @!attribute [rw] safe_for_xml
    #   Remove comments in XML contexts
    #   @return [Boolean] true to remove XML comments (default: true)

    # @!attribute [rw] sanitize_dom
    #   Enable DOM clobbering protection
    #   @return [Boolean] true for protection (default: true)
    #   @note Prevents id/name values from clobbering built-in DOM properties

    # @!attribute [rw] sanitize_until_stable
    #   Re-sanitize multiple passes to prevent mXSS
    #   @return [Boolean] true for multi-pass (default: true)
    #   @note Important for preventing mutation-based XSS attacks

    # @!attribute [rw] mutation_max_passes
    #   Maximum sanitization passes for stability
    #   @return [Integer] max passes (default: 2)
    #   @note Higher values increase security but reduce performance

    # @!attribute [rw] namespace
    #   XML namespace for document parsing
    #   @return [String] namespace URI (default: 'http://www.w3.org/1999/xhtml')

    # @!attribute [rw] parser_media_type
    #   Parser media type for content parsing
    #   @return [String] media type (default: 'text/html')

    # @!attribute [rw] minimal_profile
    #   Use minimal HTML-only profile (excludes SVG/MathML)
    #   @return [Boolean] true for minimal (default: false)

    # @!attribute [rw] force_body
    #   Force body context when parsing
    #   @return [Boolean] (default: false)

    # @!attribute [rw] in_place
    #   Attempt to sanitize in place (experimental)
    #   @return [Boolean] (default: false)

    attr_accessor :additional_attributes, :add_attributes, :add_data_uri_tags,
      :additional_tags, :additional_uri_safe_attributes, :add_uri_safe_attributes,
      :allow_aria_attributes, :allow_data_attributes, :allow_data_uri, :allow_unknown_protocols,
      :allow_self_close_in_attributes, :allowed_attributes, :allowed_attributes_per_tag, :allowed_tags,
      :allowed_namespaces, :allowed_uri_regexp, :custom_element_handling,
      :forbidden_attributes, :forbid_attributes, :forbid_contents, :add_forbid_contents, :forbidden_tags,
      :force_body, :html_integration_points, :in_place, :keep_content,
      :mathml_text_integration_points, :namespace, :parser_media_type,
      :return_dom_fragment, :return_dom,
      :safe_for_templates, :safe_for_xml, :sanitize_dom, :sanitize_until_stable, :mutation_max_passes,
      :sanitize_named_props, :trusted_types_policy, :allow_style_tags, :minimal_profile,
      :whole_document, :allow_document_elements

    # Initializes a new configuration instance
    #
    # @param cfg [Hash] configuration options to apply
    def initialize(cfg = {})
      # Attribute defaults
      @allow_aria_attributes = true   # permit aria-* attributes
      @allow_data_attributes = true   # permit data-* attributes
      @allow_self_close_in_attributes = true

      # URI/protocol defaults
      @allow_data_uri = true              # allow data URIs for safe elements by default
      @allow_unknown_protocols = false    # block unknown protocols by default

      # Output / parsing defaults
      @safe_for_templates = false
      @safe_for_xml = true
      @whole_document = false
      @allow_document_elements = false
      @force_body = false
      @return_dom = false
      @return_dom_fragment = false

      # Sanitization controls
      @sanitize_dom = true            # DOM clobbering protection enabled
      @sanitize_named_props = false
      @sanitize_until_stable = true   # run multiple passes to deter mXSS
      @mutation_max_passes = 2        # conservative default pass limit
      @keep_content = true
      @in_place = false
      @minimal_profile = false
      @allow_style_tags = true

      # Profiles / namespaces
      @use_profiles = {}
      @namespace = 'http://www.w3.org/1999/xhtml'
      @parser_media_type = 'text/html'

      # Tag/attribute allow/forbid defaults
      @forbidden_tags = %w[base link meta annotation-xml noscript]

      @allowed_attributes = nil

      apply_config(cfg)
      process_profiles unless @use_profiles.empty?
    end

    # Configuration key normalization mapping
    #
    # Maps configuration hash keys (including legacy aliases) to their corresponding
    # setter methods. This allows flexible configuration key naming while maintaining
    # backward compatibility with older key names.
    #
    # Keys are normalized to lowercase before lookup, so configuration is case-insensitive.
    #
    # @example Using different key styles
    #   Config.new(allowed_tags: ['p'])           # Modern style
    #   Config.new('allowed_tags' => ['p'])       # String keys
    #   Config.new(add_tags: ['custom'])          # Legacy alias
    #
    # @api private
    CONFIG_MAPPING = {
      'add_tags' => :additional_tags=, # backward compatibility
      'additional_tags' => :additional_tags=,
      'add_attr' => :additional_attributes=, # backward compatibility
      'additional_attributes' => :additional_attributes=,
      'add_attributes' => :additional_attributes=, # backward compatibility
      'add_uri_safe_attr' => :additional_uri_safe_attributes=, # backward compatibility
      'additional_uri_safe_attributes' => :additional_uri_safe_attributes=,
      'add_uri_safe_attributes' => :additional_uri_safe_attributes=, # backward compatibility
      'allowed_tags' => :allowed_tags=,
      'allowed_attr' => :allowed_attributes=, # backward compatibility
      'allowed_attributes' => :allowed_attributes=,
      'allowed_attributes_per_tag' => :allowed_attributes_per_tag=,
      'forbidden_tags' => :forbidden_tags=,
      'forbid_tags' => :forbidden_tags=, # backward compatibility
      'forbidden_attr' => :forbidden_attributes=, # backward compatibility
      'forbidden_attributes' => :forbidden_attributes=,
      'forbid_attributes' => :forbidden_attributes=, # backward compatibility
      'allow_data_uri' => :allow_data_uri=,
      'allow_aria_attr' => :allow_aria_attributes=,  # backward compatibility
      'allow_aria_attributes' => :allow_aria_attributes=,
      'allow_data_attr' => :allow_data_attributes=,  # backward compatibility
      'allow_data_attributes' => :allow_data_attributes=,
      'allow_self_close_in_attr' => :allow_self_close_in_attributes=, # backward compatibility
      'allow_self_close_in_attributes' => :allow_self_close_in_attributes=,
      'allow_style_tags' => :allow_style_tags=,
      'allow_document_elements' => :allow_document_elements=,
      'minimal_profile' => :minimal_profile=,
      'pass_limit' => :mutation_max_passes=
    }.freeze

    # Per-tag attribute restrictions for HTML email profile
    #
    # Defines which attributes are allowed on specific tags when using the html_email profile.
    # This provides fine-grained security control by limiting each tag to only its appropriate
    # attributes, preventing attribute confusion attacks where dangerous attributes appear on
    # unexpected tags.
    #
    # **Security rationale:** Email clients have inconsistent rendering behavior, and allowing
    # arbitrary attributes on any tag can lead to security issues. For example, allowing 'href'
    # on 'img' tags or 'src' on 'a' tags could enable attacks. Per-tag restrictions prevent this.
    #
    # **Usage:** This constant is automatically used when `use_profiles: { html_email: true }`
    # is configured. You can also use it as a template for your own per-tag attribute rules.
    #
    # @example Using email profile
    #   config = Config.new(use_profiles: { html_email: true })
    #   # Automatically uses HTML_EMAIL_ATTRIBUTES for per-tag control
    #
    # @example Custom per-tag attributes
    #   config.allowed_attributes_per_tag = {
    #     'a' => ['href', 'title'],
    #     'img' => ['src', 'alt', 'width', 'height']
    #   }
    #
    # @see #allowed_attributes_per_tag Configuration option for per-tag control
    HTML_EMAIL_ATTRIBUTES = {
      # Document structure
      'body' => %w[bgcolor text link vlink alink background style class id leftmargin topmargin marginwidth
        marginheight],
      'html' => %w[lang dir xmlns],
      'head' => [],
      'meta' => %w[name content charset],
      'title' => [],
      'style' => %w[type],

      # Table elements (core of email layouts)
      'table' => %w[width height border cellpadding cellspacing align bgcolor background style class id role summary],
      'thead' => %w[align class id style dir lang title],
      'tbody' => %w[align class id style dir lang title],
      'tfoot' => %w[align class id style dir lang title],
      'tr' => %w[height bgcolor background valign align style class id],
      'td' => %w[width height colspan rowspan align valign bgcolor background style class id headers scope],
      'th' => %w[width height colspan rowspan align valign bgcolor background style class id headers scope],

      # Legacy presentation elements
      'font' => %w[face size color style],
      'center' => %w[align class id style dir lang title],

      # Links and media
      'a' => %w[href target title class id style name rel],
      'img' => %w[src alt width height border align style class id],

      # Headings
      'h1' => %w[align class id style dir lang title],
      'h2' => %w[align class id style dir lang title],
      'h3' => %w[align class id style dir lang title],
      'h4' => %w[align class id style dir lang title],
      'h5' => %w[align class id style dir lang title],
      'h6' => %w[align class id style dir lang title],

      # Block elements
      'p' => %w[align class id style dir lang title],
      'div' => %w[align class id style dir lang title],
      'span' => %w[align class id style dir lang title],
      'blockquote' => %w[align class id style dir lang title cite],
      'pre' => %w[align class id style dir lang title],
      'code' => %w[align class id style dir lang title],

      # Lists
      'ul' => %w[align class id style dir lang title type],
      'ol' => %w[align class id style dir lang title type start],
      'li' => %w[align class id style dir lang title value],

      # Inline formatting
      'strong' => %w[align class id style dir lang title],
      'em' => %w[align class id style dir lang title],
      'b' => %w[align class id style dir lang title],
      'i' => %w[align class id style dir lang title],
      'u' => %w[align class id style dir lang title],
      's' => %w[align class id style dir lang title],
      'strike' => %w[align class id style dir lang title],
      'sup' => %w[align class id style dir lang title],
      'sub' => %w[align class id style dir lang title],
      'small' => %w[align class id style dir lang title],
      'big' => %w[align class id style dir lang title],
      'mark' => %w[align class id style dir lang title],
      'del' => %w[align class id style dir lang title cite datetime],
      'ins' => %w[align class id style dir lang title cite datetime],

      # Empty elements
      'br' => %w[class style],
      'hr' => %w[align class id style dir lang title width size noshade]
    }.freeze

    # Sets content type profiles and rebuilds configuration
    #
    # Profiles are pre-configured sets of tags and attributes for common content types.
    # When you set profiles, the configuration automatically enables the appropriate
    # tags, attributes, and security settings for those content types.
    #
    # **Available profiles:**
    # - `:html` - Standard HTML5 content
    # - `:svg` - SVG graphics
    # - `:svg_filters` - SVG filter effects
    # - `:math_ml` - Mathematical notation
    # - `:html_email` - HTML email with legacy attributes
    #
    # @param profiles [Hash<Symbol, Boolean>] hash of profile names to enable
    # @return [Hash] the set profiles
    #
    # @example Enable multiple profiles
    #   config.use_profiles = { html: true, svg: true }
    #
    # @example Email profile
    #   config.use_profiles = { html_email: true }
    #
    # @note Setting profiles resets allowed_tags and allowed_attributes to nil,
    #   allowing the profile configuration to take effect
    def use_profiles=(profiles)
      @use_profiles = profiles || {}
      reset_profile_dependent_settings
      process_profiles unless @use_profiles.empty?
    end

    private

    # Applies configuration options from a hash
    #
    # @param cfg [Hash] configuration hash
    def apply_config(cfg)
      cfg.each do |key, value|
        normalized = key.to_s.downcase
        setter = CONFIG_MAPPING[normalized] || :"#{normalized}="
        send(setter, value) if respond_to?(setter)
      end
    end

    # Resets configuration settings that depend on profiles
    #
    # Called when profiles are changed to clear out profile-dependent settings
    # before applying new profile configuration.
    #
    # @return [void]
    # @api private
    def reset_profile_dependent_settings
      @allowed_tags = nil
      @allowed_attributes = nil
      @allowed_attributes_per_tag = nil
      @allow_style_tags = true
      @allow_document_elements = false
      @allow_unknown_protocols = false
      @whole_document = false
      @forbidden_tags = %w[base link meta annotation-xml noscript]
    end

    # Processes profile configurations to set allowed tags and attributes
    #
    # @return [void]
    def process_profiles
      configure_allowed_tags if @allowed_tags.nil?
      configure_allowed_attributes if @allowed_attributes.nil?
    end

    # Configures allowed tags based on active profiles
    #
    # Builds the allowed tags list by combining tags from each enabled profile.
    # Always includes '#text' for text content handling.
    #
    # @return [void]
    # @api private
    def configure_allowed_tags
      @allowed_tags = ['#text']
      @allowed_tags += Tags::HTML if @use_profiles[:html]
      @allowed_tags += Tags::SVG if @use_profiles[:svg]
      @allowed_tags += Tags::SVG_FILTERS if @use_profiles[:svg_filters]
      @allowed_tags += Tags::MATH_ML if @use_profiles[:math_ml]
      configure_html_email_tags if @use_profiles[:html_email]
    end

    # Configures settings specific to HTML email profile
    #
    # Email rendering requires special handling:
    # - Allows style tags (required for email styling)
    # - Allows document elements (html, head, body)
    # - Treats as whole document
    # - Disables DOM clobbering protection (emails are sandboxed)
    # - Permits meta and style tags in forbidden list
    #
    # @return [void]
    # @api private
    def configure_html_email_tags
      @allowed_tags += Tags::HTML_EMAIL
      @allow_style_tags = true
      @allow_document_elements = true
      @allow_unknown_protocols = false
      @whole_document = true
      @sanitize_dom = false # Emails use IDs for styling, rendered in sandboxed contexts
      @forbidden_tags -= %w[meta style]
    end

    # Configures allowed attributes based on active profiles
    #
    # Builds the allowed attributes list by combining attributes from each enabled profile.
    # For html_email profile, uses per-tag attribute restrictions instead of global list.
    #
    # @return [void]
    # @api private
    def configure_allowed_attributes
      @allowed_attributes = []
      @allowed_attributes += Attributes::HTML if @use_profiles[:html]
      @allowed_attributes_per_tag = HTML_EMAIL_ATTRIBUTES if @use_profiles[:html_email]
      @allowed_attributes += Attributes::SVG + Attributes::XML if @use_profiles[:svg]
      @allowed_attributes += Attributes::SVG + Attributes::XML if @use_profiles[:svg_filters]
      @allowed_attributes += Attributes::MATH_ML + Attributes::XML if @use_profiles[:math_ml]
    end
  end
end
