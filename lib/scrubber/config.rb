# frozen_string_literal: true

module Scrubber
  # Configuration class for the Scrubber sanitizer
  #
  # This class holds all configuration options for customizing the sanitization behavior.
  # It provides default values and allows customization through various attributes.
  class Config
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
      :sanitize_named_props, :trusted_types_policy, :use_profiles, :allow_style_tags, :minimal_profile,
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
      @allow_data_uri = false             # block data: by default
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

      # Profiles / namespaces
      @use_profiles = {}
      @namespace = 'http://www.w3.org/1999/xhtml'
      @parser_media_type = 'text/html'

      # Tag/attribute allow/forbid defaults
      @forbidden_tags = %w[base link meta style annotation-xml]
      @allow_style_tags = false # style tags denied unless explicitly enabled

      apply_config(cfg)
      process_profiles unless @use_profiles.empty?
    end

    private

    # Applies configuration options from a hash
    #
    # @param cfg [Hash] configuration hash
    def apply_config(cfg)
      cfg.each do |key, value|
        normalized = key.to_s.downcase
        mapping = {
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
        }
        setter = mapping[normalized] || :"#{normalized}="
        send(setter, value) if respond_to?(setter)
      end
    end

    # Processes profile configurations to set allowed tags and attributes
    #
    # @return [void]
    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
    def process_profiles
      if @allowed_tags.nil?
        @allowed_tags = ['#text']
        @allowed_tags += Tags::HTML if @use_profiles[:html]
        @allowed_tags += Tags::SVG if @use_profiles[:svg]
        @allowed_tags += Tags::SVG_FILTERS if @use_profiles[:svg_filters]
        @allowed_tags += Tags::MATH_ML if @use_profiles[:math_ml]
        @allowed_tags += Tags::SVG if @use_profiles[:svg]
        @allowed_tags += Tags::SVG_FILTERS if @use_profiles[:svg_filters]
        @allowed_tags += Tags::MATH_ML if @use_profiles[:math_ml]
        if @use_profiles[:html_email]
          @allowed_tags += Tags::HTML_EMAIL
          @allow_style_tags = true
          @allow_document_elements = true
          @allow_unknown_protocols = false
          @forbidden_tags -= %w[meta style]
        end
      end
      return unless @allowed_attributes.nil?

      @allowed_attributes = []
      @allowed_attributes += Attributes::HTML if @use_profiles[:html]
      # For html_email profile, use per-tag attribute control instead of global allowlist
      setup_html_email_per_tag_attributes if @use_profiles[:html_email]
      @allowed_attributes += Attributes::SVG + Attributes::XML if @use_profiles[:svg]
      @allowed_attributes += Attributes::SVG + Attributes::XML if @use_profiles[:svg_filters]
      return unless @use_profiles[:math_ml]

      @allowed_attributes += Attributes::MATH_ML + Attributes::XML
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

    # Sets up per-tag attribute restrictions for HTML email profile
    #
    # This provides fine-grained control over which attributes can appear on which tags,
    # improving security by preventing attribute confusion attacks while maintaining
    # full HTML email compatibility.
    #
    # @return [void]
    def setup_html_email_per_tag_attributes
      # Common attributes for most content elements
      common_attrs = %w[align class id style dir lang title]

      @allowed_attributes_per_tag = {
        # Document structure
        'body' => %w[bgcolor text link vlink alink background style class id],
        'html' => %w[lang dir xmlns],
        'head' => [],
        'meta' => %w[name content charset],
        'title' => [],
        'style' => [],

        # Table elements (core of email layouts)
        'table' => %w[width height border cellpadding cellspacing align bgcolor background style class id role summary],
        'thead' => common_attrs,
        'tbody' => common_attrs,
        'tfoot' => common_attrs,
        'tr' => %w[height bgcolor valign align style class id],
        'td' => %w[width height colspan rowspan align valign bgcolor background style class id headers scope],
        'th' => %w[width height colspan rowspan align valign bgcolor background style class id headers scope],

        # Legacy presentation elements
        'font' => %w[face size color style],
        'center' => common_attrs,

        # Links and media
        'a' => %w[href target title class id style name rel],
        'img' => %w[src alt width height border align style class id],

        # Headings
        'h1' => common_attrs,
        'h2' => common_attrs,
        'h3' => common_attrs,
        'h4' => common_attrs,
        'h5' => common_attrs,
        'h6' => common_attrs,

        # Block elements
        'p' => common_attrs,
        'div' => common_attrs,
        'span' => common_attrs,
        'blockquote' => common_attrs + %w[cite],
        'pre' => common_attrs,
        'code' => common_attrs,

        # Lists
        'ul' => common_attrs + %w[type],
        'ol' => common_attrs + %w[type start],
        'li' => common_attrs + %w[value],

        # Inline formatting
        'strong' => common_attrs,
        'em' => common_attrs,
        'b' => common_attrs,
        'i' => common_attrs,
        'u' => common_attrs,
        's' => common_attrs,
        'strike' => common_attrs,
        'sup' => common_attrs,
        'sub' => common_attrs,
        'small' => common_attrs,
        'big' => common_attrs,
        'mark' => common_attrs,
        'del' => common_attrs + %w[cite datetime],
        'ins' => common_attrs + %w[cite datetime],

        # Empty elements
        'br' => %w[class style],
        'hr' => common_attrs + %w[width size noshade]
      }
    end
  end
end
