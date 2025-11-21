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
      :allow_self_close_in_attributes, :allowed_attributes, :allowed_tags,
      :allowed_namespaces, :allowed_uri_regexp, :custom_element_handling,
      :forbidden_attributes, :forbid_attributes, :forbid_contents, :add_forbid_contents, :forbidden_tags,
      :force_body, :html_integration_points, :in_place, :keep_content,
      :mathml_text_integration_points, :namespace, :parser_media_type,
      :return_dom_fragment, :return_dom, :return_trusted_type,
      :safe_for_templates, :safe_for_xml, :sanitize_dom, :sanitize_until_stable, :mutation_max_passes,
      :sanitize_named_props, :trusted_types_policy, :use_profiles, :allow_style_tags,
      :whole_document

    # Initializes a new configuration instance
    #
    # @param cfg [Hash] configuration options to apply
    def initialize(cfg = {})
      @allow_aria_attributes = true
      @allow_data_attributes = true
      @allow_data_uri = false
      @allow_unknown_protocols = false
      @allow_self_close_in_attributes = true
      @safe_for_templates = false
      @safe_for_xml = true
      @whole_document = false
      @force_body = false
      @return_dom = false
      @return_dom_fragment = false
      @return_trusted_type = false
      @sanitize_dom = true
      @sanitize_named_props = false
      @sanitize_until_stable = false
      @mutation_max_passes = 3
      @keep_content = true
      @in_place = false
      @use_profiles = {}
      @namespace = 'http://www.w3.org/1999/xhtml'
      @parser_media_type = 'text/html'
      @forbidden_tags = %w[base link meta style annotation-xml]
      @allow_style_tags = false

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
          'allow_style_tags' => :allow_style_tags=
        }
        setter = mapping[normalized] || :"#{normalized}="
        send(setter, value) if respond_to?(setter)
      end
    end

    # Processes profile configurations to set allowed tags and attributes
    #
    # @return [void]
    def process_profiles
      if @allowed_tags.nil?
        @allowed_tags = ['#text']
        @allowed_tags += Tags::HTML if @use_profiles[:html]
        @allowed_tags += Tags::SVG if @use_profiles[:svg]
        @allowed_tags += Tags::SVG_FILTERS if @use_profiles[:svg_filters]
        @allowed_tags += Tags::MATH_ML if @use_profiles[:math_ml]
      end
      return unless @allowed_attributes.nil?

      @allowed_attributes = []
      @allowed_attributes += Attributes::HTML if @use_profiles[:html]
      @allowed_attributes += Attributes::SVG + Attributes::XML if @use_profiles[:svg]
      @allowed_attributes += Attributes::SVG + Attributes::XML if @use_profiles[:svg_filters]
      return unless @use_profiles[:math_ml]

      @allowed_attributes += Attributes::MATH_ML + Attributes::XML
    end
  end
end
