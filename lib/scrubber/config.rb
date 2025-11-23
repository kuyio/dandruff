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

    # Mapping of configuration keys to their setter methods
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

    # Reassign profiles after initialization and rebuild derived settings
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

    def configure_allowed_tags
      @allowed_tags = ['#text']
      @allowed_tags += Tags::HTML if @use_profiles[:html]
      @allowed_tags += Tags::SVG if @use_profiles[:svg]
      @allowed_tags += Tags::SVG_FILTERS if @use_profiles[:svg_filters]
      @allowed_tags += Tags::MATH_ML if @use_profiles[:math_ml]
      configure_html_email_tags if @use_profiles[:html_email]
    end

    def configure_html_email_tags
      @allowed_tags += Tags::HTML_EMAIL
      @allow_style_tags = true
      @allow_document_elements = true
      @allow_unknown_protocols = false
      @whole_document = true
      @sanitize_dom = false # Emails use IDs for styling, rendered in sandboxed contexts
      @forbidden_tags -= %w[meta style]
    end

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
