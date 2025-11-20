# frozen_string_literal: true

module Scrubber
  # Utility functions for the Scrubber sanitizer
  module Utils
    module_function

    # Performs a deep duplicate of an object
    #
    # @param obj [Object] the object to duplicate
    # @return [Object] the deep duplicated object
    def deep_dup(obj)
      case obj
      when Hash
        obj.transform_values { |v| deep_dup(v) }
      when Array
        obj.map { |v| deep_dup(v) }
      else
        begin
          obj.dup
        rescue StandardError
          obj
        end
      end
    end
  end
end
