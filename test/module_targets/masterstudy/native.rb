# frozen_string_literal: true

require_relative '../wordpress/plugin_controls'
require_relative '../wp_batch_desync_rce/native'

# Native registration and permissions use vendor/WordPress APIs, not the owner.
module MasterstudyNative
  include WordpressBatchChainTarget
  include WordpressNativePluginControls

  NATIVE_PASSWORD = 'Native-study+2026!'

  def chain_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-masterstudy.json'), JSON.pretty_generate(@chain)) if @chain
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
    expect(data.values_at('version', 'constant_version')).to eq([@release] * 2)
    expect(data.fetch('table_prefix')).to eq(@db_prefix)
    expect(data.fetch('active_plugins')).to eq(['masterstudy-lms-learning-management-system/masterstudy-lms-learning-management-system.php'])
    expect(data.values_at('registration_handler', 'users_can_register', 'premoderation', 'recaptcha')).to eq([true, true, false, false])
    expect(data.fetch('archive_sha256')).to eq(@catalog.fetch('sha256'))
    expect(data.fetch('installed_sha256')).to eq(@catalog.fetch('installed_sha256'))
    expect(data.values_at('home', 'siteurl')).to eq(['http://module-target.test' + @prefix] * 2)
    expect(data.fetch('permalink_structure')).to eq(ENV.fetch('MASTERSTUDY_PLAIN', '0') == '1' ? '' : '/%postname%/')
    expect(data.fetch('server')).to start_with('11.2.2-MariaDB')
    expect(data.fetch('grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
    expect(data.values_at('db_error', 'bootstrap_output_base64', 'table_errors')).to eq(['', '', []])
    expect(data.fetch('filesystem').values_at('writable', 'upload_error')).to eq([true, false])
    expect(data.fetch('filesystem').fetch('free_bytes')).to be > 16_777_216
    data
  end

  def master_selected(data)
    data.except('filesystem', 'operation_result', 'bootstrap_output_base64')
  end

  def chain_assert_restored(current, original = @baseline)
    expect(master_selected(current)).to eq(master_selected(original))
  end

  def master_nonce(label)
    response = chain_request(label, @prefix + '/')
    expect(response.code).to eq('200')
    script = Nokogiri::HTML(response.body).css('script').map(&:text).find { |text| text.include?('var stm_lms_nonces =') }
    expect(script).not_to be_nil
    values = JSON.parse(script[/var\s+stm_lms_nonces\s*=\s*(\{[^\r\n]+\})\s*;/, 1])
    nonce = values.fetch('stm_lms_register')
    expect(nonce).to match(/\A[a-f0-9]{10}\z/)
    nonce
  end

  def master_register(label, name, nonce, privileged: false, patch: {})
    body = {
      'user_login' => name, 'user_email' => name.tr('_', '-') + '@example.test',
      'user_password' => NATIVE_PASSWORD, 'user_password_re' => NATIVE_PASSWORD,
      'become_instructor' => '', 'privacy_policy' => true, 'degree' => '', 'expertize' => '', 'auditory' => '',
      'additional' => [], 'additional_instructors' => []
    }
    body['profile_default_fields_for_register'] = { @db_prefix + 'capabilities' => { 'value' => { 'administrator' => 1 } } } if privileged
    body.merge!(patch)
    query = { 'action' => 'stm_lms_register' }
    query['nonce'] = nonce if nonce
    chain_request(label, @prefix + '/wp-admin/admin-ajax.php?' + URI.encode_www_form(query), body, headers: { 'User-Agent' => 'module-target-masterstudy-native-' + label })
  end

  def master_user(data, name)
    users = data.fetch('users').select { |user| user.fetch('user_login') == name }
    expect(users.length).to eq(1)
    users.first
  end

  def master_auth(label, name, password, expected_admin, agent)
    cookie, identifier = wordpress_native_login(label, name, password, agent)
    current = chain_identity(label + '-identity')
    user = master_user(current, name)
    expect(identifier).to eq(user.fetch('ID'))
    expect(user.values_at('roles', 'install_plugins', 'promote_users')).to eq([expected_admin ? ['administrator'] : ['subscriber'], expected_admin, expected_admin])
    response = wordpress_native_admin_page(label + '-admin', cookie, agent, identifier, name, allowed: expected_admin)
    expect(response.code).to eq(expected_admin ? '200' : '403')
    (@chain[:authenticated_accounts] ||= []) << { label: label, name: name, id: identifier, admin: expected_admin, password_valid: true, admin_status: response.code }
    chain_save
    user
  end

  def master_native_case(label, name, nonce, privileged: false)
    response = master_register(label, name, nonce, privileged: privileged)
    if privileged && !@affected
      expect(response.code).to eq('500')
      expect(response.body).to include('There has been a critical error')
      (@chain[:fixed_partial_errors] ||= []) << { label: label, code: response.code }
    else
      expect(response.code).to eq('200')
      expect(JSON.parse(response.body).fetch('status')).to eq('success')
    end
    agent = 'module-target-masterstudy-native-' + label
    master_auth(label, name, NATIVE_PASSWORD, privileged && @affected, agent)
    current = chain_identity(label + '-deleted', 'delete-user', name, NATIVE_PASSWORD, agent)
    expect(current.fetch('operation_result').fetch('deleted_user_id')).to be > 4
    expect(current.fetch('users').map { |user| user.fetch('user_login') }).not_to include(name)
    current
  end

  def chain_native_gate(phase)
    boot = chain_identity(phase + '-boot')
    expect(boot.fetch('users').length).to eq(4)
    expect(boot.fetch('users').map { |user| user.fetch('sessions') }).to all(eq([]))
    nonce = master_nonce(phase + '-frontend')
    agent = 'module-target-masterstudy-native-control'
    cookie, identifier = wordpress_native_login(phase + '-control', 'module_admin', 'module-target-password', agent)
    expect(identifier).to eq(1)
    wordpress_native_admin_page(phase + '-control-admin', cookie, agent, 1, 'module_admin')
    expect(chain_identity(phase + '-control-clear', 'clear-sessions', agent).fetch('operation_result').fetch('tokens_removed')).to be > 0
    original = master_native_case('ordinary', 'native_masterstudy_ordinary', nonce)
    (@chain[:initialization] ||= []) << { phase: phase, changed_keys: master_selected(boot).keys.reject { |key| master_selected(boot)[key] == master_selected(original)[key] } }
    %w[missing wrong].each do |kind|
      response = master_register(kind, 'native_masterstudy_' + kind, kind == 'missing' ? nil : 'wrong-native-nonce')
      expect([response.code, response.body.strip]).to eq(['403', '-1'])
      chain_assert_restored(chain_identity(phase + '-' + kind + '-nonce'), original)
    end
    boundary = master_native_case('privilege', 'native_masterstudy_privilege', nonce, privileged: true)
    chain_assert_restored(boundary, original)
    final = master_native_case('post', 'native_masterstudy_post', master_nonce(phase + '-post-nonce'))
    chain_assert_restored(final, original)
    chain_resources(phase, %w[app db reporting_db])
    @chain.fetch(:controls) << { phase: phase, native_passed: true, expected_admin_boundary: @affected, restored: true }
    chain_save
    final
  end
end
