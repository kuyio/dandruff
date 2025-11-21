# frozen_string_literal: true

module Scrubber
  module Expressions
    DATA_ATTR = /^data-[\w-]+$/
    ARIA_ATTR = /^aria-[\w-]+$/
    MUSTACHE_EXPR = /\{\{[^}]+\}\}/
    ERB_EXPR = /<%[=\-]?[^%]+%>/
    TMPLIT_EXPR = /\$\{[^}]+\}/
    # Default allowed URI protocols align with DOMPurify defaults: http(s), mailto, ftp, tel, and relative.
    IS_ALLOWED_URI = /^(?:(?:https?|mailto|ftp|tel):|[^a-z]|[a-z+.-]+(?:[^a-z+.-:]|$))/i
    IS_SCRIPT_OR_DATA = %r{^(?:\s*javascript:|\s*data:text/html)}i
  end
end
