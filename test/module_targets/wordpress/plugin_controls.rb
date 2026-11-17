# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'nokogiri'
require 'rex/mime/message'
require 'rex/zip'
require 'uri'

# Independent HTTP/native-API controls for owned WordPress plugin targets.
# Each component supplies chain_http, chain_identity, chain_save and probe bytes;
# these controls never call the Framework WordPress login/upload helpers under test.
module WordpressNativePluginControls
  ADMIN_REDIRECT_HOSTS = %w[module-target.test 127.0.0.1].freeze

  def wordpress_native_fields(response)
    Nokogiri::HTML(response.body).css('input[name]').to_h { |input| [input['name'], input['value'].to_s] }
  end

  def wordpress_native_cookies(response)
    Array(response.get_fields('set-cookie')).to_h { |text| text.split(';', 2).first.split('=', 2) }.map { |name, value| name + '=' + value }.join('; ')
  end

  def wordpress_native_cookie_id(label, response)
    values = Array(response.get_fields('set-cookie')).filter_map do |text|
      text.split(';', 2).first.split('=', 2).last if text.start_with?('wordpress_logged_in_')
    end
    cookie = URI.decode_www_form_component(values.reverse.find { |value| !value.empty? }.to_s)
    chain_identity(label + '-cookie', 'cookie', Base64.strict_encode64(cookie)).fetch('operation_result').fetch('validated_user_id')
  end

  def wordpress_native_login(label, name, password, agent)
    form = chain_http(label + '-form', @prefix + '/wp-login.php', headers: { 'User-Agent' => agent })
    expect(form.code).to eq('200')
    response = chain_http(label, @prefix + '/wp-login.php', { 'log' => name, 'pwd' => password, 'wp-submit' => 'Log In', 'testcookie' => '1' }, form: true, headers: { 'Cookie' => wordpress_native_cookies(form), 'User-Agent' => agent })
    expect(response.code).to eq('302')
    [wordpress_native_cookies(response), wordpress_native_cookie_id(label, response)]
  end

  def wordpress_native_admin_page(label, cookie, agent, identifier, name, allowed: true)
    8.times do |step|
      response = chain_http(label + '-' + step.to_s, @prefix + '/wp-admin/users.php', headers: { 'Cookie' => cookie, 'User-Agent' => agent })
      unless allowed
        expect(%w[302 403]).to include(response.code)
        return response
      end
      if response.code == '200'
        expect(Nokogiri::HTML(response.body).at_css('tr#user-' + identifier.to_s)&.text).to include(name)
        return response
      end
      expect(response.code).to eq('302')
      location = URI(response.fetch('location'))
      expect(ADMIN_REDIRECT_HOSTS).to include(location.host)
      expect(location.path).to start_with(@prefix + '/wp-admin/')
      route = location.path + (location.query ? '?' + location.query : '')
      chain_http(label + '-activation-' + step.to_s, route, headers: { 'Cookie' => cookie, 'User-Agent' => agent })
    end
    raise 'Native activation redirects did not reach the real users page'
  end

  def wordpress_native_plugin(label, cookie, agent, slug:, source:, marker:, filename:)
    path = @prefix + '/wp-content/plugins/' + slug + '/native-proof.php'
    expect(chain_http(label + '-absent', path).code).to eq('404')
    upload = chain_http(label + '-form', @prefix + '/wp-admin/plugin-install.php?tab=upload', headers: { 'Cookie' => cookie, 'User-Agent' => agent })
    expect(upload.code).to eq('200')
    archive = Rex::Zip::Archive.new
    archive.add_file(slug + '/native-proof.php', source)
    multipart = Rex::MIME::Message.new
    multipart.add_part(wordpress_native_fields(upload).fetch('_wpnonce'), nil, nil, 'form-data; name="_wpnonce"')
    multipart.add_part('Install Now', nil, nil, 'form-data; name="install-plugin-submit"')
    multipart.add_part(archive.pack, 'application/zip', 'binary', 'form-data; name="pluginzip"; filename="' + filename + '"')
    response = chain_http(label + '-upload', @prefix + '/wp-admin/update.php?action=upload-plugin', multipart.to_s, raw: true, headers: { 'Cookie' => cookie, 'User-Agent' => agent, 'Content-Type' => 'multipart/form-data; boundary=' + multipart.bound })
    expect(response.code).to eq('200')
    proof = chain_http(label + '-execution', path)
    expect(proof.code).to eq('200')
    data = JSON.parse(proof.body)
    expect(data.values_at('marker', 'uid', 'bash')).to eq([marker, 33, true])
    expect(data.fetch('shell')).to start_with('uid=33(')
    (@chain[:native_execution] ||= []) << { label: label, **data }
    chain_identity(label + '-removed', 'delete-plugin', Digest::SHA256.hexdigest(source))
  end
end
