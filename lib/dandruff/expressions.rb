# frozen_string_literal: true

module Dandruff
  # Regular expressions for attribute matching and content validation
  #
  # This module contains regular expressions used throughout Dandruff for validating
  # attributes, detecting template expressions, and checking URI protocols. These patterns
  # are critical for security and should not be modified without careful consideration.
  #
  # @api private
  module Expressions
    # Matches HTML5 data attributes (data-*)
    #
    # Validates attribute names that follow the data attribute specification.
    # Data attributes must start with 'data-' followed by one or more word characters or hyphens.
    #
    # @example Matching data attributes
    #   'data-user-id' =~ Expressions::DATA_ATTR   # matches
    #   'data-toggle' =~ Expressions::DATA_ATTR    # matches
    #   'data' =~ Expressions::DATA_ATTR           # does not match
    #   'data-' =~ Expressions::DATA_ATTR          # does not match
    DATA_ATTR = /^data-[\w-]+$/

    # Matches ARIA accessibility attributes (aria-*)
    #
    # Validates attribute names that follow the ARIA specification.
    # ARIA attributes must start with 'aria-' followed by one or more word characters or hyphens.
    #
    # @example Matching aria attributes
    #   'aria-label' =~ Expressions::ARIA_ATTR      # matches
    #   'aria-hidden' =~ Expressions::ARIA_ATTR     # matches
    #   'aria' =~ Expressions::ARIA_ATTR            # does not match
    ARIA_ATTR = /^aria-[\w-]+$/

    # Matches Mustache/Handlebars template expressions
    #
    # Detects template expressions in the format `{{ expression }}`. Used when
    # `safe_for_templates` is enabled to prevent template injection attacks.
    #
    # @example Matching mustache expressions
    #   '{{ user.name }}' =~ Expressions::MUSTACHE_EXPR    # matches
    #   '{{value}}' =~ Expressions::MUSTACHE_EXPR          # matches
    #
    # @see Config#safe_for_templates
    MUSTACHE_EXPR = /\{\{[^}]+\}\}/

    # Matches ERB (Embedded Ruby) template expressions
    #
    # Detects ERB expressions in the format `<% expression %>`, `<%= expression %>`,
    # or `<%- expression %>`. Used when `safe_for_templates` is enabled.
    #
    # @example Matching ERB expressions
    #   '<%= user.name %>' =~ Expressions::ERB_EXPR    # matches
    #   '<% if admin? %>' =~ Expressions::ERB_EXPR     # matches
    #   '<%- value -%>' =~ Expressions::ERB_EXPR       # matches
    #
    # @see Config#safe_for_templates
    ERB_EXPR = /<%[=-]?[^%]+%>/

    # Matches JavaScript template literal expressions
    #
    # Detects template expressions in the format `${ expression }`. Used when
    # `safe_for_templates` is enabled to prevent template injection.
    #
    # @example Matching template literals
    #   '${user.name}' =~ Expressions::TMPLIT_EXPR    # matches
    #   '${value}' =~ Expressions::TMPLIT_EXPR        # matches
    #
    # @see Config#safe_for_templates
    TMPLIT_EXPR = /\$\{[^}]+\}/

    # Validates allowed URI protocols and relative URLs
    #
    # This is the default URI validation pattern, matching DOMPurify's IS_ALLOWED_URI.
    # Allows the http, https, ftp, ftps, mailto, tel, callto, sms, cid, xmpp and matrix
    # schemes plus relative URLs. A value without one of those schemes is only accepted
    # when it cannot be parsed as a scheme: it starts with a non-letter, or its leading
    # run of scheme characters (letters, `+`, `.`, `-`) is followed by anything but `:`.
    #
    # **Allowed:** the schemes above, relative URLs (`/`, `./`, `../`, `#`, `?`, `page2.html`,
    # `images/logo.png`), `cid:` references to inline email parts
    # **Blocked:** javascript, vbscript, data (handled separately) and other unknown schemes
    #
    # The pattern is anchored with `\A` (not `^`) so that only the start of the whole value counts.
    #
    # @example Valid URIs
    #   'https://example.com' =~ Expressions::IS_ALLOWED_URI    # matches
    #   'mailto:user@example.com' =~ Expressions::IS_ALLOWED_URI # matches
    #   'cid:image001.png@01D9C2A0' =~ Expressions::IS_ALLOWED_URI # matches
    #   '/path/to/page' =~ Expressions::IS_ALLOWED_URI         # matches
    #   'images/logo.png' =~ Expressions::IS_ALLOWED_URI       # matches
    #   'javascript:alert(1)' =~ Expressions::IS_ALLOWED_URI   # does not match
    #
    # @see Config#allowed_uri_regexp Custom URI pattern override
    IS_ALLOWED_URI = /
      \A(?:
        (?:(?:f|ht)tps?|mailto|tel|callto|sms|cid|xmpp|matrix): # allowed schemes
        | [^a-z]                                               # starts with a non-letter
        | [a-z+.-]+(?:[^a-z+.\-:]|\z)                          # scheme characters not followed by ':'
      )
    /ix

    # Detects dangerous JavaScript and data:text/html URIs
    #
    # Matches URIs that start with `javascript:` or `data:text/html` protocols,
    # which are common XSS attack vectors. These are always blocked regardless
    # of other configuration. Whitespace before the protocol is also detected.
    #
    # @example Dangerous URIs
    #   'javascript:alert(1)' =~ Expressions::IS_SCRIPT_OR_DATA      # matches
    #   '  javascript:void(0)' =~ Expressions::IS_SCRIPT_OR_DATA     # matches (whitespace)
    #   'data:text/html,<script>' =~ Expressions::IS_SCRIPT_OR_DATA # matches
    #   'data:image/png;base64' =~ Expressions::IS_SCRIPT_OR_DATA   # does not match
    IS_SCRIPT_OR_DATA = %r{^(?:\s*javascript:|\s*data:text/html)}i
  end
end
