# frozen_string_literal: true

module Dandruff
  # Sanitizes CSS text, i.e. the content of `<style>` elements
  #
  # The stylesheet is split into segments at the structural characters `;`, `{` and `}`
  # (outside strings, comments and unquoted `url()`). Each segment (a declaration, a selector or
  # an at-rule prelude) is checked on its own, with comments removed and CSS escapes decoded, so
  # obfuscations such as `@\69mport`, `u\rl(` or `exp/**/ression(` are recognised. Unsafe
  # segments are dropped; everything else, including the delimiters, is kept verbatim, so the
  # rest of the stylesheet keeps working and dropping text cannot join neighbouring tokens.
  #
  # A segment is dropped when it contains:
  # - an `@import` rule
  # - `expression(`, `behavior:` or `-moz-binding:` (legacy script-in-CSS vectors)
  # - `javascript:`, `vbscript:` or `livescript:`
  # - a `url()`, `src()` or `image-set()` URL that is not allowed: `data:` URLs are only allowed
  #   for images and only when `allow_data_uri` is set, other URLs must pass
  #   `allowed_uri_regexp` (when set) and the default URI allowlist, and remote URLs
  #   (`http(s):`, `ftp(s):`, `//host`) are dropped when `allow_remote_style_urls` is false
  #
  # @api private
  class Css
    ESCAPE = /\\(?:([0-9a-fA-F]{1,6})(?:\r\n|[ \t\r\n\f])?|(\r\n|[\r\n\f])|(.)|\z)/m
    DANGEROUS = /@import|expression\(|(?:behavior|binding):|(?:java|vb|live)script:/i
    URL_FUNCTION = /(?:url|src)\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))/i
    IMAGE_SET = /image-set\((.*)/im
    QUOTED = /"([^"]*)"|'([^']*)'/
    DATA_IMAGE = %r{\Adata:image/[a-z0-9.+-]+[;,]}i
    REMOTE = %r{\A(?:(?:f|ht)tps?:|[/\\]{2})}i
    SPACE = /[\s\u0085\u00a0\u1680\u180e\u2000-\u200b\u2028\u2029\u205f\u3000]+/
    CONTROL = /[\x00-\x1f\x7f]/
    DELIMITERS = %w[; { }].freeze

    # @param allow_data_uri [Boolean] allow `data:image/...` URLs
    # @param allowed_uri_regexp [Regexp, nil] custom URI allowlist
    # @param allow_remote_urls [Boolean] allow absolute remote URLs (http, https, ftp, //host)
    def initialize(allow_data_uri: true, allowed_uri_regexp: nil, allow_remote_urls: true)
      @allow_data_uri = allow_data_uri
      @allowed_uri_regexp = allowed_uri_regexp
      @allow_remote_urls = allow_remote_urls
    end

    # Returns the CSS with unsafe segments removed
    #
    # @param css [String] CSS text
    # @return [String] sanitized CSS text
    def sanitize(css)
      segments(css.to_s.scrub).map { |raw, code, delimiter| (safe?(code) ? raw : '') + delimiter }.join
    end

    private

    def safe?(code)
      code.strip.empty? || !dangerous?(decode(code))
    end

    # Splits CSS into [raw text, text without comments, delimiter] triples.
    #
    # Delimiters inside strings, comments and unquoted url() do not split; escapes are kept
    # together with the escaped character.
    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
    def segments(css)
      result = []
      raw = +''
      code = +''
      state = :normal
      i = 0
      while i < css.length
        ch = css[i]
        if state == :comment
          raw << ch
          if ch == '*' && css[i + 1] == '/'
            raw << '/'
            i += 1
            state = :normal
          end
        elsif ch == '\\'
          escaped = css[i, 2]
          raw << escaped
          code << escaped
          i += 1
        elsif state.is_a?(String) # inside a quoted string; the state is the quote character
          raw << ch
          code << ch
          state = :normal if ch == state || ch == "\n"
        elsif state == :url
          raw << ch
          code << ch
          state = :normal if ch == ')'
        elsif ch == '/' && css[i + 1] == '*'
          raw << '/*'
          i += 1
          state = :comment
        elsif DELIMITERS.include?(ch)
          result << [raw, code, ch]
          raw = +''
          code = +''
        else
          raw << ch
          code << ch
          if ['"', "'"].include?(ch)
            state = ch
          elsif ch == '(' && code.match?(/url\(\z/i) && !css[(i + 1)..].match?(/\A\s*["']/)
            state = :url
          end
        end
        i += 1
      end
      result << [raw, code, '']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

    def dangerous?(text)
      return true if text.gsub(SPACE, '').gsub(CONTROL, '').match?(DANGEROUS)

      urls(text).any? { |url| !allowed_url?(url) }
    end

    def urls(text)
      found = text.scan(URL_FUNCTION).flat_map(&:compact)
      text.scan(IMAGE_SET).flatten.each { |rest| found.concat(rest.scan(QUOTED).flat_map(&:compact)) }
      found
    end

    def allowed_url?(url)
      url = url.gsub(/\A#{SPACE}|#{SPACE}\z/o, '')
      return true if url.empty?
      return false if url.match?(CONTROL)
      return @allow_data_uri && url.match?(DATA_IMAGE) if url.match?(/\Adata:/i)
      return false if @allowed_uri_regexp && !url.match?(@allowed_uri_regexp)
      return false unless url.match?(Expressions::IS_ALLOWED_URI)

      @allow_remote_urls || !url.match?(REMOTE)
    end

    # Decodes CSS escapes (CSS Syntax Level 3, "consume an escaped code point")
    def decode(text)
      text.gsub(ESCAPE) do
        hex, newline, char = Regexp.last_match.captures
        if hex
          code_point(hex.to_i(16))
        elsif newline
          ''
        else
          char.to_s
        end
      end
    end

    def code_point(value)
      return "�" if value.zero? || value > 0x10FFFF || (0xD800..0xDFFF).cover?(value)

      [value].pack('U')
    end
  end
end
