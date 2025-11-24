# frozen_string_literal: true

module Dandruff
  # Attribute allowlists and security denylists for HTML sanitization
  #
  # This module defines comprehensive attribute allowlists for different content types
  # (HTML, SVG, MathML) and security-focused denylists for dangerous attributes and
  # DOM clobbering attack vectors. These lists are based on DOMPurify's battle-tested
  # security model and web standards.
  #
  # @example Using attribute lists in configuration
  #   dandruff.configure do |config|
  #     config.allowed_attributes = Dandruff::Attributes::HTML
  #   end
  #
  # @see Config Configuration class that uses these attribute lists
  module Attributes
    # Standard HTML attribute allowlist
    #
    # Comprehensive list of safe HTML attributes for standard web content. These attributes
    # cover forms, media, accessibility, styling, and interactive elements while excluding
    # dangerous event handlers and script execution vectors.
    #
    # **Includes:** Layout and presentation (width, height, align, style, class, id),
    # links (href, target), forms (type, name, value, placeholder), media (src, controls, poster),
    # accessibility (alt, title, role, tabindex, lang), and HTML5 features (autocomplete, loading)
    #
    # **Excludes:** Event handlers (onclick, onload, onerror), javascript: URIs, and other XSS vectors
    #
    # **Security:** Safe for rich HTML content. All URI-like attributes (href, src) are validated
    # separately to prevent javascript: and data:text/html attacks. Style attributes are parsed
    # and sanitized to prevent CSS injection.
    #
    # @example Standard HTML content
    #   dandruff.configure do |config|
    #     config.allowed_attributes = Dandruff::Attributes::HTML
    #   end
    HTML = %w[
      accept action align alt autocapitalize autocomplete autopictureinpicture autoplay
      background bgcolor border capture cellpadding cellspacing checked cite class clear
      color cols colspan controls controlslist coords crossorigin datetime decoding
      default dir disabled disablepictureinpicture disableremoteplayback download
      draggable enctype enterkeyhint exportparts face for headers height hidden high
      href hreflang id inert inputmode integrity ismap kind label lang list loading
      loop low max maxlength media method min minlength multiple muted name nonce
      noshade novalidate nowrap open optimum part pattern placeholder playsinline
      popover popovertarget popovertargetaction poster preload pubdate radiogroup
      readonly rel required rev reversed role rows rowspan spellcheck scope selected
      shape size sizes slot span srclang start src srcset step style summary tabindex
      title translate type usemap valign value width wrap xmlns
    ].freeze

    # SVG attribute allowlist
    #
    # Comprehensive list of attributes for SVG (Scalable Vector Graphics) elements.
    # Includes presentation attributes, animation attributes, filter attributes, and
    # transformation attributes needed for full SVG functionality.
    #
    # **Includes:** Geometric properties (x, y, cx, cy, width, height, r, rx, ry),
    # styling (fill, stroke, opacity, color), transformations (transform, rotate, scale),
    # gradients (gradienttransform, spreadmethod), filters (fe* attributes), and
    # text rendering (font-*, text-*)
    #
    # **Security:** Safe for SVG rendering when combined with tag validation. Prevents
    # mXSS attacks through proper namespace handling and attribute validation.
    #
    # @example SVG graphics
    #   dandruff.configure do |config|
    #     config.use_profiles = { svg: true }  # Includes SVG attributes
    #   end
    SVG = %w[
      accent-height accumulate additive alignment-baseline amplitude ascent attributename
      attributetype azimuth basefrequency baseline-shift begin bias by class clip
      clippathunits clip-path clip-rule color color-interpolation color-interpolation-filters
      color-profile color-rendering cx cy d dx dy diffuseconstant direction display
      divisor dur edgemode elevation end exponent fill fill-opacity fill-rule filter
      filterunits flood-color flood-opacity font-family font-size font-size-adjust
      font-stretch font-style font-variant font-weight fx fy g1 g2 glyph-name
      glyphref gradientunits gradienttransform height href id image-rendering in in2
      intercept k k1 k2 k3 k4 kerning keypoints keysplines keytimes lang lengthadjust
      letter-spacing kernelmatrix kernelunitlength lighting-color local marker-end
      marker-mid marker-start markerheight markerunits markerwidth mask mask-type
      media method mode min name numoctaves offset operator opacity order orient
      orientation origin overflow paint-order path pathlength patterncontentunits
      patterntransform patternunits points preservealpha preserveaspectratio
      primitiveunits r rx ry radius refx refy repeatcount repeatdur restart result
      rotate scale seed shape-rendering slope specularconstant specularexponent
      spreadmethod startoffset stddeviation stitchtiles stop-color stop-opacity
      stroke-dasharray stroke-dashoffset stroke-linecap stroke-linejoin stroke-miterlimit
      stroke-opacity stroke stroke-width style surfacescale systemlanguage tabindex
      tablevalues targetx targety transform transform-origin text-anchor
      text-decoration text-rendering textlength type u1 u2 unicode values viewbox
      visibility version vert-adv-y vert-origin-x vert-origin-y width word-spacing
      wrap writing-mode xchannelselector ychannelselector x x1 x2 xmlns y y1 y2 z
      zoomandpan
    ].freeze

    # MathML attribute allowlist
    #
    # Comprehensive list of attributes for MathML (Mathematical Markup Language) elements.
    # Includes attributes for mathematical notation, spacing, alignment, and styling.
    #
    # **Includes:** Spacing and alignment (lspace, rspace, linethickness, rowspacing),
    # sizing (mathsize, minsize, maxsize), styling (mathcolor, mathbackground),
    # notation (notation, accent, fence), and structural (displaystyle, scriptlevel)
    #
    # **Security:** Safe for mathematical notation when properly namespaced. Prevents
    # MathML-based mXSS attacks through namespace validation.
    #
    # @example Mathematical formulas
    #   dandruff.configure do |config|
    #     config.use_profiles = { math_ml: true }  # Includes MathML attributes
    #   end
    MATH_ML = %w[
      accent accentunder align bevelled close columnsalign columnlines colspan denomalign
      depth dir display displaystyle encoding fence frame height href id largeop length
      linethickness lspace lquote mathbackground mathcolor mathsize mathvariant
      maxsize minsize movablelimits notation numalign open rowalign rowlines
      rowspacing rowspan rspace rquote scriptlevel scriptminsize scriptsizemultiplier
      selection separator separators stretchy subscriptshift supscriptshift symmetric
      voffset width xmlns
    ].freeze

    # XML namespace attributes
    #
    # Attributes used for XML namespace declarations and XLink href references.
    # Required for proper SVG linking and namespace handling.
    #
    # **Includes:** xlink:href, xml:id, xlink:title, xml:space, xmlns:xlink, xmlns
    #
    # **Security:** Namespace attributes are validated to prevent namespace confusion
    # attacks. xmlns: prefixed attributes are carefully checked to prevent injection.
    #
    # @api private
    XML = %w[
      xlink:href xml:id xlink:title xml:space xmlns:xlink xmlns
    ].freeze

    # HTML Email attribute allowlist (includes legacy presentation attributes)
    #
    # Extended attribute list for HTML email rendering. Includes legacy presentational
    # attributes required by email clients like bgcolor, align, valign, cellpadding, etc.
    #
    # **Includes:** HTML attributes + legacy table attributes (cellpadding, cellspacing,
    # bgcolor, valign), font attributes (face, size, color), layout attributes
    # (leftmargin, topmargin, marginwidth, marginheight), and meta attributes (content)
    #
    # **Security:** Designed for sandboxed email contexts. All attributes are still
    # validated for XSS vectors. Use with html_email profile for per-tag restrictions.
    #
    # **Note:** Email clients vary widely - test thoroughly across clients.
    #
    # @example Email sanitization
    #   dandruff.configure do |config|
    #     config.use_profiles = { html_email: true }
    #   end
    HTML_EMAIL = (HTML + %w[
      target bgcolor text link vlink alink background border cellpadding cellspacing
      width height align valign face size color content leftmargin topmargin marginwidth marginheight
    ]).freeze

    # Dangerous event handler and script protocol patterns
    #
    # List of dangerous attribute patterns that enable script execution. These are
    # ALWAYS blocked regardless of configuration to prevent XSS attacks.
    #
    # **Includes:**
    # - Event handlers: onclick, onload, onerror, onmouseover, onfocus, etc.
    # - URI protocols: javascript:, vbscript:, data:text/html
    #
    # **Security:** This is a security-critical denylist. These patterns enable direct
    # script execution and are blocked even if explicitly allowed elsewhere.
    #
    # @example Blocked patterns
    #   # <a onclick="alert(1)">  - onclick blocked
    #   # <img src="javascript:alert(1)">  - javascript: blocked
    #   # <link href="vbscript:msgbox(1)">  - vbscript: blocked
    #
    # @api private
    DANGEROUS = %w[
      onclick ondblclick onmousedown onmouseup onmouseover onmousemove
      onmouseout onkeypress onkeydown onkeyup onload onunload onabort
      onerror onfocus onblur onchange onsubmit onreset onselect
      onscroll onresize oncopy oncut onpaste ondrag ondrop
      javascript: vbscript: data:text/html
    ].freeze

    # DOM clobbering attack attribute values
    #
    # List of dangerous id/name attribute values that can be used for DOM clobbering
    # attacks. These values would allow attackers to override built-in DOM properties
    # and methods, potentially bypassing security checks.
    #
    # **Includes:** Browser object properties (window, document, location, alert),
    # DOM properties (innerHTML, outerHTML, attributes, children), prototype chain
    # (__proto__, constructor, prototype), and critical methods (getElementById,
    # createElement, setAttribute, etc.)
    #
    # **Security:** When `sanitize_dom: true` (default), these values are blocked in
    # id and name attributes to prevent DOM clobbering. Can be disabled for email
    # rendering where DOM clobbering is less critical.
    #
    # **Background:** DOM clobbering occurs when HTML attributes like id/name override
    # built-in browser objects, e.g., `<img id="document">` makes `document` refer to
    # the image instead of the DOM document object.
    #
    # @example Prevented attacks
    #   # <form name="document">  - blocked, would clobber window.document
    #   # <img id="location">     - blocked, would clobber window.location
    #   # <div id="alert">        - blocked, would clobber window.alert
    #
    # @see Config#sanitize_dom Configuration option to enable/disable DOM clobbering protection
    # @api private
    DOM_CLOBBERING = %w[
      __proto__ __parent__ constructor prototype contentwindow contentdocument parentnode ownerdocument location
      attributes nodevalue innerhtml outerhtml localname documenturi srcdoc url
      createelement renamenode appendchild insertbefore replacechild removechild normalize clonenode
      alert document window frames frame form forms elements children documentelement implementation
      cookie body adoptNode activeElement firstElementChild submit acceptCharset hasChildNodes namespaceURI
      getElementById setAttribute removeAttributeNode nodeType nodeName parentNode
    ].map(&:downcase).freeze
  end
end
