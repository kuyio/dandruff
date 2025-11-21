# frozen_string_literal: true

module Scrubber
  module Tags
    MINIMAL_HTML = %w[
      a b blockquote br code div em h1 h2 h3 h4 h5 h6 i img li ol p pre span strong table tbody td th thead tr ul
    ].freeze

    # HTML tags allowed by default, matching DOMPurify's comprehensive list
    HTML = %w[
      a abbr address area article aside audio b bdi bdo blockquote body br button canvas caption cite code
      col colgroup data datalist dd del details dfn dialog div dl dt em embed fieldset figcaption figure footer form
      h1 h2 h3 h4 h5 h6 head header hgroup hr html i iframe img input ins kbd label legend li main map mark
      meter nav noscript object ol optgroup option output p param picture pre progress q rp rt ruby s samp
      script section select small source span strong sub summary sup table tbody td template textarea tfoot
      th thead time title tr track u ul var video wbr
    ].freeze

    SVG = %w[svg g path rect circle ellipse line polyline polygon text tspan textPath marker pattern defs
      linearGradient radialGradient stop use image view symbol].freeze

    SVG_FILTERS = %w[
      filter feBlend feColorMatrix feComponentTransfer feComposite feConvolveMatrix feDiffuseLighting
      feDisplacementMap feDropShadow feFlood feFuncA feFuncB feFuncG feFuncR feGaussianBlur feImage feMerge
      feMergeNode feMorphology feOffset feSpecularLighting feTile feTurbulence
    ].freeze

    MATH_ML = %w[
      math mi mn mo ms mtext mspace menclose mstyle mfrac msqrt mroot mtable mtr mtd maligngroup malignmark
      mpadded mphantom mglyph
    ].freeze

    # Tags allowed in HTML emails (includes legacy tags, excludes scripts/forms)
    HTML_EMAIL = (HTML + %w[
      head meta title style center font
    ] - %w[
      script form input select textarea button object embed iframe frame frameset
    ]).freeze

    TEXT = %w[#text].freeze
  end
end
