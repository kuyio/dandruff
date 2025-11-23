# frozen_string_literal: true

module Scrubber
  # Tag allowlists for HTML sanitization
  #
  # This module defines comprehensive tag allowlists for different content types.
  # Each constant represents a curated set of safe tags that can be used based on
  # your sanitization requirements. These lists are based on DOMPurify's battle-tested
  # security model and regularly updated to reflect web standards.
  #
  # @example Using tag lists in configuration
  #   scrubber.configure do |config|
  #     config.allowed_tags = Scrubber::Tags::MINIMAL_HTML
  #   end
  #
  # @see Config Configuration class that uses these tag lists
  module Tags
    # Minimal HTML tag set for basic formatted text
    #
    # Use this for simple user-generated content where you only need basic formatting
    # like bold, italic, headings, links, and lists. This is the most restrictive
    # allowlist and provides the smallest attack surface.
    #
    # **Includes:** Text formatting (b, i, em, strong), headings (h1-h6), links (a),
    # lists (ul, ol, li), code blocks (code, pre), basic structure (div, span, p),
    # tables (table, tr, td, th, tbody, thead), images (img), quotes (blockquote)
    #
    # **Security:** Minimal surface area, excludes all form elements, scripts, and media
    #
    # @example Minimal blog comments
    #   scrubber.configure do |config|
    #     config.allowed_tags = Scrubber::Tags::MINIMAL_HTML
    #   end
    MINIMAL_HTML = %w[
      a b blockquote br code div em h1 h2 h3 h4 h5 h6 i img li ol p pre span strong table tbody td th thead tr ul
    ].freeze

    # Comprehensive HTML5 tag allowlist matching DOMPurify defaults
    #
    # This is the default allowlist used when no specific tags are configured. It includes
    # all standard HTML5 semantic and structural elements, media elements, and form controls.
    # Dangerous tags like raw script execution are still excluded even from this list.
    #
    # **Includes:** All semantic HTML5 (article, section, nav, aside, header, footer, main),
    # media elements (audio, video, picture, canvas), form elements (form, input, select, textarea),
    # interactive elements (button, details, dialog), and comprehensive text formatting
    #
    # **Security:** Comprehensive but safe - excludes actual script execution vectors while
    # allowing rich content. Note that script/iframe/object tags are removed during sanitization
    # even if listed here.
    #
    # @example Default rich content
    #   # This is used automatically when no allowed_tags are specified
    #   scrubber = Scrubber.new
    #   clean = scrubber.sanitize(html) # Uses HTML allowlist
    HTML = %w[
      a abbr address area article aside audio b bdi bdo blockquote body br button canvas caption cite code
      col colgroup data datalist dd del details dfn dialog div dl dt em embed fieldset figcaption figure footer form
      h1 h2 h3 h4 h5 h6 head header hgroup hr html i iframe img input ins kbd label legend li main map mark
      meter nav noscript object ol optgroup option output p param picture pre progress q rp rt ruby s samp
      script section search select small source span strong sub summary sup table tbody td template textarea tfoot
      th thead time title tr track u ul var video wbr
    ].freeze

    # SVG (Scalable Vector Graphics) tag allowlist
    #
    # Use this when you need to support inline SVG content. Includes core SVG elements
    # for shapes, paths, gradients, and basic filters. Combine with `use_profiles: { svg: true }`
    # configuration for complete SVG support including attributes.
    #
    # **Includes:** Basic shapes (rect, circle, ellipse, line, polygon, polyline, path),
    # grouping (g, defs, symbol, use), gradients (linearGradient, radialGradient),
    # text (text, tspan, textPath), and structural elements (svg, pattern, marker, mask, filter)
    #
    # **Security:** Safe for SVG rendering but requires corresponding attribute allowlist.
    # mXSS attacks via SVG are prevented through attribute sanitization.
    #
    # @example SVG icons and graphics
    #   scrubber.configure do |config|
    #     config.use_profiles = { html: true, svg: true }
    #   end
    SVG = %w[svg g path rect circle ellipse line polyline polygon text tspan textPath marker pattern defs desc mask
      linearGradient radialGradient stop use image view symbol feImage filter a title].freeze

    # SVG filter effects tag allowlist
    #
    # Advanced SVG filter primitives for visual effects like blur, color manipulation,
    # lighting, and compositing. Use this in addition to SVG tags when you need
    # filter effects support.
    #
    # **Includes:** All SVG filter primitives (feBlend, feColorMatrix, feGaussianBlur,
    # feDropShadow, feMorphology, etc.)
    #
    # **Security:** Safe when combined with proper attribute sanitization. Filter effects
    # cannot execute scripts but can be used for sophisticated visual rendering.
    #
    # @example SVG with filters
    #   scrubber.configure do |config|
    #     config.use_profiles = { svg: true, svg_filters: true }
    #   end
    SVG_FILTERS = %w[
      filter feBlend feColorMatrix feComponentTransfer feComposite feConvolveMatrix feDiffuseLighting
      feDisplacementMap feDropShadow feFlood feFuncA feFuncB feFuncG feFuncR feGaussianBlur feImage feMerge
      feMergeNode feMorphology feOffset feSpecularLighting feTile feTurbulence
    ].freeze

    # MathML (Mathematical Markup Language) tag allowlist
    #
    # Use this for mathematical and scientific content. Includes core MathML elements
    # for rendering mathematical notation and formulas.
    #
    # **Includes:** Numbers and identifiers (mi, mn, mo, ms, mtext), layout elements
    # (mrow, mfrac, msqrt, mroot, mstyle), tables (mtable, mtr, mtd), spacing (mspace, mpadding)
    #
    # **Security:** Safe for mathematical notation. Prevents mXSS attacks that can occur
    # with MathML namespace confusion.
    #
    # @example Mathematical content
    #   scrubber.configure do |config|
    #     config.use_profiles = { html: true, math_ml: true }
    #   end
    MATH_ML = %w[
      math mi mn mo ms mtext mspace menclose mstyle mfrac msqrt mroot mtable mtr mtd maligngroup malignmark
      mpadded mphantom mrow
    ].freeze

    # HTML Email tag allowlist (includes legacy presentational tags)
    #
    # Specialized tag list for HTML email rendering. Includes legacy presentational tags
    # (font, center) and document structure tags (head, meta, style) needed for email clients.
    # Excludes interactive elements (forms, buttons) and script execution vectors.
    #
    # **Includes:** HTML tags + head, meta, title, style, center, font
    # **Excludes:** script, form, input, select, textarea, button, object, embed, iframe, frame, frameset
    #
    # **Security:** Designed for sandboxed email rendering contexts. Allows style tags
    # (required for email) but with content sanitization. Removes all form and script elements.
    #
    # **Note:** Email clients have inconsistent rendering, so test thoroughly. Use with
    # `use_profiles: { html_email: true }` for complete email configuration including
    # per-tag attribute restrictions.
    #
    # @example Email content sanitization
    #   scrubber.configure do |config|
    #     config.use_profiles = { html_email: true }
    #   end
    HTML_EMAIL = (HTML + %w[
      head meta title style center font
    ] - %w[
      script form input select textarea button object embed iframe frame frameset
    ]).freeze

    # Text node marker
    #
    # Special marker for text nodes in the DOM. Used internally for text content handling.
    #
    # @api private
    TEXT = %w[#text].freeze
  end
end
