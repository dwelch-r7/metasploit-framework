# frozen_string_literal: true

require_relative '../wordpress/plugin_controls'
require_relative '../wp_batch_desync_rce/native'

# Keep vendor action/key/state controls independent from the module under test.
# Reuse bounded native HTTP, callback, command, reporting and resource controls.
module SureTriggersNative
  include WordpressBatchChainTarget
  include WordpressNativePluginControls

  def chain_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-suretriggers.json'), JSON.pretty_generate(@chain)) if @chain
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
    expect(data.values_at('version', 'constant_version', 'active_plugins')).to eq([@release, @release, ['suretriggers/suretriggers.php']])
    expect(data.fetch('server')).to start_with('11.2.2-MariaDB')
    expect(data.fetch('grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
    expect(data.values_at('db_error', 'bootstrap_output_base64')).to eq(['', ''])
    expect(data.fetch('archive_sha256')).to eq(@catalog.fetch('sha256'))
    expect(data.fetch('installed_sha256')).to eq(@catalog.fetch('installed_sha256'))
    { 'action' => 'run_action', 'connection' => 'create_wp_connection' }.each do |name, method|
      route = name == 'action' ? '/sure-triggers/v1/automation/action' : '/sure-triggers/v1/connection/create-wp-connection'
      expect(data.fetch('routes').fetch(route).map { |entry| entry.fetch('callback') }).to include('SureTriggers\\Controllers\\RestController::' + method)
    end
    expect(data.values_at('home', 'siteurl')).to eq(['http://module-target.test' + @prefix] * 2)
    expect(data.fetch('permalink_structure')).to eq(@plain ? '' : '/%postname%/')
    %w[plugins upload_base upload_current].each do |key|
      expect(data.fetch('filesystem').fetch(key).values_at('uid', 'writable')).to eq([33, true])
    end
    expect(data.fetch('filesystem').fetch('upload_error')).to be(false)
    expect(data.fetch('filesystem').fetch('disk_free_bytes')).to be > 16_777_216
    data
  end

  def sure_selected_state(identity)
    identity.except('filesystem', 'operation_result')
  end

  def chain_assert_restored(current, original = @baseline)
    expect(sure_selected_state(current)).to eq(sure_selected_state(original))
  end

  def sure_native_plugin(label, cookie, agent)
    wordpress_native_plugin(
      label, cookie, agent,
      slug: 'native_sure_probe', source: File.binread(File.join(__dir__, 'probe-plugin.php')),
      marker: 'MODULE_TARGET_NATIVE_SURE_PROOF', filename: 'native-sure.zip'
    )
  end

  def sure_creation_body
    {
      'integration' => 'WordPress', 'type_event' => 'create_user_if_not_exists', 'wp_user_id' => 0, 'automation_id' => 0,
      'selected_options' => {
        'user_name' => 'native_sure_probe', 'password' => 'Module-target-sure+2026!', 'user_email' => 'native-sure@example.test',
        'role' => 'administrator', 'first_name' => 'Native', 'last_name' => 'Sure',
        'force_update_user_role' => false, 'add_user_roles' => false, 'show_password' => 'no', 'exclude_role' => []
      },
      'fields' => [], 'context' => {}
    }
  end

  def sure_prove_created(label, original)
    name = 'native_sure_probe'
    agent = "module-target-sure-native-#{Process.pid}-#{label}-created"
    current = chain_identity(label + '-password', 'password', name, 'Module-target-sure+2026!')
    user = current.fetch('users').find { |entry| entry['user_login'] == name }
    expect(user).not_to be_nil
    expect(user.values_at('roles', 'install_plugins')).to eq([['administrator'], true])
    expect(current.fetch('operation_result').fetch('valid')).to be(true)
    cookie, identifier = wordpress_native_login(label + '-login', name, 'Module-target-sure+2026!', agent)
    expect(identifier).to eq(user.fetch('ID'))
    wordpress_native_admin_page(label + '-admin', cookie, agent, identifier, name)
    sure_native_plugin(label + '-execution', cookie, agent)
    cleaned = chain_identity(label + '-user-removed', 'delete-user', name, 'Module-target-sure+2026!')
    chain_assert_restored(cleaned, original)
  end

  def chain_native_gate(phase)
    boot = chain_identity(phase + '-boot')
    expect(boot.fetch('users').length).to eq(4)
    expect(boot.fetch('users').map { |user| user.fetch('sessions') }).to all(eq([]))
    expect(chain_http(phase + '-home', @prefix + '/').code).to eq('200')
    readme = chain_http(phase + '-readme', @prefix + '/wp-content/plugins/suretriggers/readme.txt')
    expect(readme.code).to eq('200')
    expect(readme.body).to include('Stable tag: ' + @release)
    expect(chain_http(phase + '-namespace', boot.fetch('route_urls').fetch('namespace')).code).to eq('200')
    agent = "module-target-sure-native-#{Process.pid}-#{phase}-control"
    cookie, identifier = wordpress_native_login(phase + '-control', 'module_admin', 'module-target-password', agent)
    expect(identifier).to eq(1)
    wordpress_native_admin_page(phase + '-control-admin', cookie, agent, 1, 'module_admin')
    sure_native_plugin(phase + '-control-native', cookie, agent)
    chain_identity(phase + '-control-restored', 'clear-sessions', 'module_admin', agent)
    original = chain_identity(phase + '-baseline', 'record-options')
    expect(original.fetch('logical_token')).to eq(@configured ? 'fixture-sure-configured-secret' : nil)
    (@chain[:initialization_deltas] ||= []) << { phase: phase, keys: sure_selected_state(boot).keys.reject { |key| boot[key] == original[key] } }
    action_route = original.fetch('route_urls').fetch('action')
    connection_route = original.fetch('route_urls').fetch('connection')
    payload = sure_creation_body
    empty_allowed = @release == '1.0.78' && !@configured
    response = chain_http(phase + '-empty-bearer', action_route, payload, headers: { 'St-Authorization' => 'Bearer ' })
    if empty_allowed
      expect(response.code).to eq('200')
      expect(JSON.parse(response.body).fetch('success')).to be(true)
      sure_prove_created(phase + '-empty', original)
    else
      expect(%w[401 403]).to include(response.code)
      chain_assert_restored(chain_identity(phase + '-empty-denied'), original)
    end
    if @configured
      response = chain_http(phase + '-configured-valid-key', action_route, payload, headers: { 'St-Authorization' => 'Bearer fixture-sure-configured-secret' })
      expect(response.code).to eq('200')
      expect(JSON.parse(response.body).fetch('success')).to be(true)
      sure_prove_created(phase + '-configured', original)
    end
    token = "native-sure-key-#{Process.pid}-#{phase}"
    reset = { 'sure-triggers-access-key' => token, 'wp-username' => 'native_sure_probe', 'wp-password' => 'Module-target-sure+2026!', 'connection-status' => 'ok', 'connected_email' => 'native-sure@example.test' }
    response = chain_http(phase + '-wrong-agent', connection_route, reset, headers: { 'User-Agent' => 'module-target-sure-wrong-agent' })
    expect(response.code).to eq('403')
    expect(JSON.parse(response.body).fetch('success')).to be(false)
    chain_assert_restored(chain_identity(phase + '-wrong-agent-unchanged'), original)
    agent = %w[1.0.78 1.0.79].include?(@release) ? 'SureTriggers' : 'OttoKit'
    response = chain_http(phase + '-missing-credentials', connection_route, {}, headers: { 'User-Agent' => agent })
    expect(%w[400 401]).to include(response.code)
    expect(JSON.parse(response.body).fetch('success')).to be(false)
    chain_assert_restored(chain_identity(phase + '-missing-unchanged'), original)
    response = chain_http(phase + '-native-key-reset', connection_route, reset, headers: { 'User-Agent' => agent })
    reset_allowed = @release != '1.0.83'
    if reset_allowed
      expect(response.code).to eq('200')
      expect(JSON.parse(response.body).fetch('success')).to be(true)
      changed = chain_identity(phase + '-key-reset-state')
      expect(changed.fetch('logical_token')).to eq(token)
      expect(changed.fetch('option_value').fetch('connected_email_key')).to eq('native-sure@example.test')
      invalid = payload.merge('selected_options' => payload.fetch('selected_options').merge('user_name' => '!!!', 'user_email' => 'native-sure-invalid@example.test'))
      response = chain_http(phase + '-native-invalid-user', action_route, invalid, headers: { 'St-Authorization' => 'Bearer ' + token })
      expect(response.code).to eq('200')
      rejection = JSON.parse(response.body)
      expect(rejection.fetch('success')).to be(true)
      expect(rejection.dig('data', 'result', 'empty_user_login')).to eq(['Cannot create a user with an empty login name.'])
      chain_assert_restored(chain_identity(phase + '-invalid-user-unchanged'), changed)
      (@chain[:native_rejections] ||= []) << { phase: phase, response: rejection, no_user_created: true }
      response = chain_http(phase + '-reset-key-action', action_route, payload, headers: { 'St-Authorization' => 'Bearer ' + token })
      expect(response.code).to eq('200')
      expect(JSON.parse(response.body).fetch('success')).to be(true)
      sure_prove_created(phase + '-reset-key', changed)
      final = chain_identity(phase + '-native-cleanup', 'restore-options', token, 'native-sure@example.test')
    else
      expect(response.code).to eq('403')
      expect(JSON.parse(response.body).fetch('success')).to be(false)
      final = chain_identity(phase + '-native-cleanup')
    end
    chain_assert_restored(final, original)
    callback = chain_callback_probe
    chain_resources(phase, %w[app db reporting_db])
    @chain.fetch(:controls) << { phase: phase, empty_bearer_allowed: empty_allowed, key_reset_allowed: reset_allowed, configured_key: @configured, selected_state_restored: true, passed: true }
    chain_save
    [original, callback]
  end

  def sure_cached_payload(identifier, label)
    output = console_command(%(irb -e 'session=framework.sessions[#{Integer(identifier)}]; exploit=session&.exploit; cached=exploit&.payload; raise "Missing actual EncodedPayload" unless cached.is_a?(Msf::EncodedPayload) && cached.encoded.is_a?(String); raw=cached.encoded.dup; path=File.join(Msf::Config.config_directory,"sure-cached-#{Integer(identifier)}.bin"); File.open(path,"wb",0o600){|file|file.write(raw)}; puts "SURE_CACHED=" + {sid:session.sid,owner:exploit.fullname,exploit_id:exploit.object_id,payload_ref:exploit.payload_instance.refname,extensions:exploit.datastore["EXTENSIONS"],path:path,bytes:raw.bytesize,sha256:Digest::SHA256.hexdigest(raw)}.to_json'))
    capture = JSON.parse(output.match(/^SURE_CACHED=(.+)$/)[1])
    expect(capture.values_at('sid', 'owner', 'payload_ref')).to eq([Integer(identifier), sure_fullname, 'php/meterpreter_reverse_tcp'])
    path = capture.fetch('path')
    expect(File.realpath(path)).to start_with(File.realpath(ENV.fetch('MSF_CFGROOT_CONFIG')) + '/')
    raw = File.binread(path)
    expect([raw.bytesize, Digest::SHA256.hexdigest(raw)]).to eq(capture.values_at('bytes', 'sha256'))
    @chain.fetch(:cached_payloads) << capture.merge('label' => label)
    chain_save
  end
end
