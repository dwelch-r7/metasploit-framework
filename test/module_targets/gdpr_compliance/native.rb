# frozen_string_literal: true

require_relative '../wordpress/plugin_controls'
require_relative '../wp_batch_desync_rce/native'

# Independent vendor settings, mail/reset, permissions and owned-state controls.
module GdprComplianceNative
  include WordpressBatchChainTarget
  include WordpressNativePluginControls

  RESET_PASSWORD = 'Gdpr-reset+2026!'

  def chain_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-gdpr.json'), JSON.pretty_generate(@chain)) if @chain
  end

  def chain_http(...)
    chain_request(...)
  end

  def chain_identity(label, *)
    output, = chain_command(label, 'app', 'php', '/opt/module-target/control.php', *)
    data = JSON.parse(output)
    (@chain[:identities] ||= []) << { label: label, data: data }
    chain_save
    expect(data.values_at('core', 'php', 'uid', 'selected_release', 'version')).to eq(['6.8.3', '8.3.28', 33, @release, @release])
    expect(data.fetch('active_plugins')).to eq(['wp-gdpr-compliance/wp-gdpr-compliance.php'])
    expect(data.values_at('guest_action_handler', 'guest_settings_handler', 'authenticated_settings_handler')).to eq([true, false, !@affected])
    expect(data.values_at('database', 'table_prefix', 'role')).to eq(['wp_root', 'wp_', 'module_target@%'])
    expect(data.fetch('server')).to start_with('11.2.2-MariaDB')
    expect(data.fetch('grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
    expect(data.fetch('archive_sha256')).to eq(@catalog.fetch('sha256'))
    expect(data.fetch('installed_sha256')).to eq(@catalog.fetch('installed_sha256'))
    expect(data.values_at('db_error', 'table_errors', 'bootstrap_output_base64')).to eq(['', [], ''])
    expect(data.values_at('home', 'siteurl')).to eq(['http://module-target.test' + @prefix] * 2)
    expect(data.fetch('permalink_structure')).to eq(ENV.fetch('GDPR_PLAIN', '0') == '1' ? '' : '/%postname%/')
    expect(data.fetch('mail_command')).to eq('/opt/module-target/sendmail -t -i')
    expect(data.fetch('filesystem').values_at('writable', 'upload_error')).to eq([true, false])
    expect(data.fetch('filesystem').fetch('free_bytes')).to be > 16_777_216
    data
  end

  def gdpr_selected(data)
    data.except('filesystem', 'operation_result', 'bootstrap_output_base64')
  end

  def gdpr_assert_restored(data, baseline = @baseline)
    expect(gdpr_selected(data)).to eq(gdpr_selected(baseline))
  end

  def gdpr_nonce(label)
    response = chain_request(label, @prefix + '/')
    expect(response.code).to eq('200')
    script = Nokogiri::HTML(response.body).css('script').map(&:text).find { |value| value.include?('var wpgdprcData =') }
    expect(script).not_to be_nil
    nonce = JSON.parse(script[/var\s+wpgdprcData\s*=\s*(\{[^\r\n]+\})\s*;/, 1]).fetch('ajaxSecurity')
    expect(nonce).to match(/\A[a-f0-9]{10}\z/)
    nonce
  end

  def gdpr_options(label, expected, replacement)
    changes = replacement.to_h { |key, value| [key, { expected: expected.fetch(key), value: value }] }
    chain_identity(label, 'options', Base64.strict_encode64(changes.to_json))
    # WordPress caches sanitized numeric values as integers in the writing request.
    # A fresh process independently proves the exact persisted option values.
    data = chain_identity(label + '-persisted')
    replacement.each { |key, value| expect(data.fetch('options').fetch(key)).to eq(value) }
    data
  end

  def gdpr_clear_mail(label, data)
    hashes = data.fetch('mail').to_h.transform_values { |value| value.fetch('sha256') }
    cleared = chain_identity(label, 'clear-mail', Base64.strict_encode64(hashes.to_json))
    expect(cleared.fetch('operation_result').fetch('mail_removed')).to eq(hashes.length)
    expect(cleared.fetch('mail')).to eq([])
    cleared
  end

  def gdpr_route(value)
    address = URI(value)
    if address.absolute? || address.host
      expect([address.scheme, address.host]).to eq(['http', 'module-target.test'])
      # Framework's Host header includes the published port; native requests
      # use the default port. Both observed forms address this same owned app.
      expect([80, target_endpoint('app').fetch('port')]).to include(address.port)
    else
      expect(value).to start_with('/')
      expect(value).not_to start_with('//')
    end
    expect(address.path).to eq(@prefix + '/wp-login.php')
    address.path + (address.query ? '?' + address.query : '')
  end

  def gdpr_mail_link(data, name, email)
    links = data.fetch('mail').filter_map do |filename, entry|
      message = Rex::MIME::Message.new(Base64.strict_decode64(entry.fetch('base64')))
      next unless message.to == email

      expect(message.header.find('Content-Type').last).to eq('text/plain; charset=UTF-8')
      expect(message.header.find('Content-Transfer-Encoding')).to be_nil
      message.content.scan(%r{https?://[^\s<>]+}).filter_map do |value|
        query = URI.decode_www_form(URI(value).query.to_s).to_h
        { filename: filename, url: value, key: query.fetch('key') } if query['action'] == 'rp' && query['login'] == name && query['key']
      end
    end.flatten
    expect(links.length).to eq(1)
    links.first
  end

  def gdpr_account(label, name, email, admin:, agent:, public_account: false)
    current = chain_identity(label + '-created')
    users = current.fetch('users').select { |user| user.fetch('user_login') == name }
    expect(users.length).to eq(1)
    user = users.first
    expect(user.fetch('ID')).to be > 4
    expect(user.fetch('user_email')).to eq(email)
    actual_admin = user.fetch('install_plugins') && user.fetch('promote_users')
    owned = { id: user.fetch('ID'), name: name, email: email, password: RESET_PASSWORD, agent: agent, label: label, public: public_account, password_set: false, roles: user.fetch('roles') }
    @chain.fetch(:accounts) << owned
    chain_save
    link = gdpr_mail_link(current, name, email)
    cookies = {}
    path = gdpr_route(link.fetch(:url))
    response = nil
    5.times do |step|
      response = chain_request(label + '-reset-' + step.to_s, path, headers: { 'User-Agent' => agent, 'Cookie' => cookies.map { |key, value| key + '=' + value }.join('; ') })
      Array(response.get_fields('set-cookie')).each do |cookie|
        key, value = cookie.split(';', 2).first.split('=', 2)
        cookies[key] = value
      end
      break if response.code == '200'

      expect(response.code).to eq('302')
      path = gdpr_route(response.fetch('location'))
    end
    expect(response.code).to eq('200')
    page = Nokogiri::HTML(response.body)
    expect(page.at_css('input#user_login')['value']).to eq(name)
    form = page.at_css('form#resetpassform')
    expect(form).not_to be_nil
    values = form.css('input[name]').to_h { |input| [input['name'], input['value'].to_s] }
    expect(values.fetch('rp_key')).to eq(link.fetch(:key))
    values.merge!('pass1' => RESET_PASSWORD, 'pass2' => RESET_PASSWORD, 'wp-submit' => 'Save Password')
    submitted = chain_request(label + '-password-submit', gdpr_route(form['action']), values, form: true, headers: { 'User-Agent' => agent, 'Cookie' => cookies.map { |key, value| key + '=' + value }.join('; ') })
    expect(submitted.code).to eq('200')
    operation = public_account ? 'password-public' : 'password'
    expect(chain_identity(label + '-password-proven', operation, Base64.strict_encode64(owned.to_json)).fetch('operation_result').fetch('valid_password')).to be(true)
    owned[:password_set] = true
    cookie, identifier = wordpress_native_login(label + '-login', name, RESET_PASSWORD, agent)
    expect(identifier).to eq(user.fetch('ID'))
    response = wordpress_native_admin_page(label + '-permission', cookie, agent, identifier, name, allowed: actual_admin)
    owned.merge!(actual_login: true, admin: actual_admin, mail_filename: link.fetch(:filename))
    chain_save
    expect(user.values_at('roles', 'install_plugins', 'promote_users')).to eq([admin ? ['administrator'] : ['subscriber'], admin, admin])
    expect(response.code).to eq(admin ? '200' : '403')
    owned
  end

  def gdpr_restore(label, baseline = @baseline)
    restored = false
    current = chain_identity(label + '-before-recovery')
    added = current.fetch('users').reject { |user| baseline.fetch('users').any? { |initial| initial.fetch('ID') == user.fetch('ID') } }
    expect(added.length).to be <= 1
    added.each do |user|
      owned = @chain.fetch(:accounts).reverse.find { |entry| entry.fetch(:id) == user.fetch('ID') && entry.fetch(:name) == user.fetch('user_login') && entry.fetch(:email) == user.fetch('user_email') }
      expect(owned).not_to be_nil
      expect(owned.fetch(:password_set)).to be(true)
      operation = owned.fetch(:public) ? 'delete-public' : 'delete-user'
      deleted = chain_identity(label + '-delete-account', operation, Base64.strict_encode64(owned.to_json))
      expect(deleted.fetch('operation_result').fetch('deleted_user_id')).to eq(owned.fetch(:id))
      @chain.fetch(:operator_cleanup) << { label: label, id: owned.fetch(:id), name: owned.fetch(:name), public: owned.fetch(:public) }
    end
    current = chain_identity(label + '-option-recovery')
    gdpr_options(label + '-restore-options', current.fetch('options'), baseline.fetch('options'))
    final = gdpr_clear_mail(label + '-clear-mail', chain_identity(label + '-mail-captured'))
    gdpr_assert_restored(final, baseline)
    restored = true
    chain_save
    final
  ensure
    @chain[:target_contaminated] = true unless restored
    chain_save
  end

  def gdpr_setting(label, nonce, name, value, action: 'wpgdprc_process_action')
    data = { 'action' => action, 'data' => { type: 'save_setting', append: false, option: name, value: value }.to_json }
    data['security'] = nonce if nonce
    chain_request(label, @prefix + '/wp-admin/admin-ajax.php', data, form: true)
  end

  def gdpr_ordinary(label, baseline)
    gdpr_options(label + '-enable', baseline.fetch('options'), { 'users_can_register' => '1' })
    name = 'native_gdpr_' + label
    email = name.tr('_', '-') + '@example.test'
    response = chain_request(label + '-register', @prefix + '/wp-login.php?action=register', { 'user_login' => name, 'user_email' => email, 'redirect_to' => 'http://module-target.test' + @prefix + '/native-complete' }, form: true)
    expect(response.code).to eq('302')
    expect(response.fetch('location')).to eq('http://module-target.test' + @prefix + '/native-complete')
    gdpr_account(label, name, email, admin: false, agent: 'module-target-gdpr-native-' + label)
    gdpr_restore(label, baseline)
  end

  def chain_native_gate(phase)
    boot = chain_identity(phase + '-boot')
    expect(boot.fetch('users').length).to eq(4)
    expect(boot.fetch('users').map { |user| user.fetch('sessions') }).to all(eq([]))
    expect(boot.fetch('options')).to eq('users_can_register' => '0', 'default_role' => 'subscriber', 'admin_email' => 'module-admin@example.test')
    expect(boot.fetch('mail')).to eq([])
    nonce = gdpr_nonce(phase + '-frontend')
    agent = 'module-target-gdpr-native-control'
    cookie, identifier = wordpress_native_login(phase + '-control', 'module_admin', 'module-target-password', agent)
    expect(identifier).to eq(1)
    wordpress_native_admin_page(phase + '-control-admin', cookie, agent, 1, 'module_admin')
    initialized = chain_identity(phase + '-control-clear', 'clear-sessions', agent)
    before = gdpr_ordinary('ordinary', initialized)
    (@chain[:initialization] ||= []) << { phase: phase, changed_keys: gdpr_selected(boot).keys.reject { |key| gdpr_selected(boot)[key] == gdpr_selected(before)[key] } }
    [nil, 'wrong-native-nonce'].each_with_index do |value, index|
      response = gdpr_setting(phase + '-nonce-' + index.to_s, value, 'default_role', 'administrator')
      expect([response.code, response.body.strip]).to eq(['403', '-1'])
      gdpr_assert_restored(chain_identity(phase + '-nonce-unchanged-' + index.to_s), before)
    end
    { 'users_can_register' => '1', 'default_role' => 'administrator', 'admin_email' => 'native-gdpr-owned@example.test' }.each do |name, value|
      response = gdpr_setting(phase + '-boundary-' + name, nonce, name, value)
      expect(response.code).to eq('200')
      expect(JSON.parse(response.body)).to be_a(Hash)
    end
    changed = chain_identity(phase + '-actual-options')
    if @affected
      expect(changed.fetch('options')).to eq('users_can_register' => '1', 'default_role' => 'administrator', 'admin_email' => 'native-gdpr-owned@example.test')
      name = 'native_gdpr_privilege'
      email = name.tr('_', '-') + '@example.test'
      response = chain_request(phase + '-boundary-register', @prefix + '/wp-login.php?action=register', { 'user_login' => name, 'user_email' => email }, form: true)
      expect(response.code).to eq('302')
      gdpr_account('privilege', name, email, admin: true, agent: 'module-target-gdpr-native-privilege')
      gdpr_restore(phase + '-boundary', before)
    else
      gdpr_assert_restored(changed, before)
      response = gdpr_setting(phase + '-new-guest-handler', nonce, 'default_role', 'administrator', action: 'wpgdprc_process_settings')
      expect([response.code, response.body.strip]).to eq(['400', '0'])
      gdpr_assert_restored(chain_identity(phase + '-fixed-unchanged'), before)
    end
    after = gdpr_ordinary('post', before)
    gdpr_assert_restored(after, before)
    chain_resources(phase, %w[app db reporting_db])
    @chain.fetch(:controls) << { phase: phase, native_passed: true, admin_boundary: @affected, restored: true }
    chain_save
    after
  end
end
