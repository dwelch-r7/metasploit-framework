require 'acceptance_spec_helper'
require 'English'
require 'time'
require_relative '../../../../../test/module_targets/gdpr_compliance/native'

RSpec.describe 'WP GDPR Compliance real settings and registration', acceptance: true, order: :defined do
  include_context 'module target'
  include GdprComplianceNative

  before(:all) do
    @chain = { commands: [], requests: [], controls: [], calls: [], reports: [], accounts: [], operator_cleanup: [] }
    @release = ENV.fetch('GDPR_RELEASE', '1.4.2')
    @prefix = ENV.fetch('GDPR_PREFIX', '')
    @affected = @release == '1.4.2'
    @catalog = JSON.parse(File.read('test/module_targets/gdpr_compliance/releases.json')).fetch(@release)
    @workspace_base = "wordpress_chain_#{Process.pid}"
    begin
      @baseline = chain_native_gate('before')
      expect(chain_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      expect(chain_sql('SELECT usesuper FROM pg_user WHERE usename=current_user').strip).to eq('f')
      endpoint = target_endpoint('reporting_db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets')
      gdpr_workspace(@workspace_base)
      expect(chain_reports.values).to all(eq([]))
      console_command('use ' + gdpr_fullname)
      output = console_command(%q{irb -e 'puts "GDPR_PROVENANCE=" + {ruby:RUBY_VERSION,config:Msf::Config.config_directory,owner_sha256:Digest::SHA256.file("modules/auxiliary/admin/http/wp_gdpr_compliance_privesc.rb").hexdigest,methods:[:check,:run,:set_wp_option].to_h{|name|[name,active_module.method(name).source_location]}}.to_json'})
      @chain[:provenance] = JSON.parse(output.match(/^GDPR_PROVENANCE=(.+)$/)[1])
      expect(@chain.fetch(:provenance).fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@chain.fetch(:provenance).fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/auxiliary/admin/http/wp_gdpr_compliance_privesc.rb').hexdigest)
      @chain.fetch(:provenance).fetch('methods').each_value do |location|
        expect(File.realpath(location.first)).to eq(File.realpath('modules/auxiliary/admin/http/wp_gdpr_compliance_privesc.rb'))
      end
      @chain[:preflight] = 'passed'
    ensure
      chain_save
    end
  end

  before do
    skip 'The prior call lost console/target state; use a fresh profile' if @chain[:console_unresponsive] || @chain[:target_contaminated]
  end

  after(:all) do
    if @chain&.key?(:preflight) && !@chain[:target_contaminated]
      gdpr_assert_restored(chain_native_gate('after'))
      expect(console_command(%q{irb -e 'puts "GDPR_IDLE=" + {sessions:framework.sessions.keys,jobs:framework.jobs.keys}.to_json'})).to include('GDPR_IDLE={"sessions":[],"jobs":[]}') unless @chain[:console_unresponsive]
      expect(Dir.glob(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*'))).to eq([])
    end
  ensure
    chain_save
  end

  it 'checks the actual plugin release without creating accounts or credentials' do
    call = gdpr_call('check', 'check', {})
    expect(gdpr_output(call)).to include(@affected ? 'appears to be vulnerable' : 'is not exploitable')
    expect(chain_reports.fetch('credentials')).to eq([])
    gdpr_assert_restored(chain_identity('after-check'))
  end

  if ENV.fetch('GDPR_RELEASE', '1.4.2') == '1.4.2'
    %w[explicit repeat].each_with_index do |label, index|
      it "creates a real administrator on #{label} execution" do
        gdpr_success(label, {}, reuse: index.positive?)
      end
    end
  else
    it 'leaves fixed settings unchanged and fails registration while it remains disabled' do
      call = gdpr_call('closed', 'run', {})
      expect(gdpr_output(call)).to include('Failed to register user')
      expect(chain_reports.fetch('credentials')).to eq([])
      gdpr_assert_restored(chain_identity('fixed-closed-unchanged'))
    ensure
      gdpr_public_recover('closed')
    end

    it 'registers only a subscriber when fixed native registration is already enabled' do
      gdpr_options('fixed-open-registration', @baseline.fetch('options'), { 'users_can_register' => '1' })
      gdpr_success('subscriber', {}, admin: false)
    end
  end

  if ENV['GDPR_EXTRA'] == '1'
    {
      'adminemail' => { 'WPEMAIL' => 'module-gdpr-admin-owned@example.test' },
      'ignoredemail' => { 'WPEMAIL' => 'not-an-email' },
      'longvalid' => { 'USER' => 'g' * 60 }
    }.each do |label, values|
      it "creates an administrator with #{label} options and recovers the actual settings" do
        gdpr_success(label, values)
      end
    end

    {
      'bademail' => { 'EMAIL' => 'not-an-email' },
      'duplicateuser' => { 'USER' => 'module_subscriber' },
      'duplicateemail' => { 'EMAIL' => 'module-subscriber@example.test' },
      'baduser' => { 'USER' => '!!!' },
      'longinvalid' => { 'USER' => 'g' * 61 }
    }.each do |label, values|
      it "reports #{label} registration failure while retaining its earlier settings changes" do
        gdpr_refusal(label, values, 'Failed to register user')
      end
    end

    it 'rejects a genuine missing base before changing settings' do
      path = @prefix + '/module-target-missing-gdpr/'
      expect(chain_request('missing-independent', path).code).to eq('404')
      gdpr_refusal('missing', { 'TARGETURI' => path }, 'Unable to access Wordpress', changed: false)
    end

    it 'rejects a real login-page base without changing settings' do
      path = @prefix + '/wp-login.php'
      response = chain_request('loginbase-independent', path)
      expect(response.code).to eq('200')
      expect(response.body).not_to include('"ajaxSecurity":')
      # This is an invalid base URL: the owner appends wp-admin/admin-ajax.php.
      # Native gates separately prove missing/incorrect nonce rejection there.
      gdpr_refusal('loginbase', { 'TARGETURI' => path }, /Failed to (?:enable user registrations|set the default user role|register user)/, changed: false)
    end
  end

  def gdpr_fullname
    'auxiliary/admin/http/wp_gdpr_compliance_privesc'
  end

  def gdpr_workspace(name)
    expect(name).to match(/\Awordpress_chain_\d+(?:_[a-z]+)?\z/)
    @workspace = name
    expect(console_command('workspace -a ' + name)).to include(name)
  end

  def gdpr_call(label, action, overrides, reuse: false)
    gdpr_workspace(@workspace_base + '_' + label)
    options = { 'TARGETURI' => @prefix + '/', 'VHOST' => 'module-target.test', 'SSL' => false, 'HttpClientTimeout' => 5, 'USER' => 'module_gdpr_owned', 'EMAIL' => 'module-gdpr-owned@example.test', 'WPEMAIL' => '', 'UserAgent' => "module-target-gdpr-public-#{Process.pid}-#{label}" }
    options.merge!(overrides)
    call = { label: label, action: action, options: options, workspace: @workspace, state: 'started', started_at: Time.now.utc.iso8601(6) }
    @chain.fetch(:calls) << call
    chain_save
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    run_target_module(gdpr_fullname, 'app', options, action: action, allow_errors: true, command_timeout: 60, reuse_module: reuse) do |output|
      call.merge!(state: 'returned', finished_at: Time.now.utc.iso8601(6), seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, output_base64: Base64.strict_encode64(output.b))
      metadata = console_command(%q{irb -e 'puts "GDPR_MODULE=" + {id:active_module.object_id,fullname:active_module.fullname}.to_json'})
      call[:module] = JSON.parse(metadata.match(/^GDPR_MODULE=(.+)$/)[1])
      expect(call.fetch(:module).fetch('fullname')).to eq(gdpr_fullname)
      expect(call.fetch(:module).fetch('id')).to eq(@chain.fetch(:previous_module_id)) if reuse
      @chain[:previous_module_id] = call.fetch(:module).fetch('id')
      chain_save
    end
    call
  rescue Acceptance::ChildProcessRecvError, Acceptance::ChildProcessTimeoutError, EOFError => e
    @chain[:console_unresponsive] = true
    call[:console_error] = e.message if call
    raise
  ensure
    call[:console_base64] = Base64.strict_encode64(console.all_data.b) if call
    chain_save
  end

  def gdpr_output(call)
    Base64.strict_decode64(call.fetch(:output_base64)).force_encoding(Encoding::UTF_8)
  end

  def gdpr_success(label, options, reuse: false, admin: true)
    call = gdpr_call(label, 'run', options, reuse: reuse)
    output = gdpr_output(call)
    state = chain_identity(label + '-actual-settings')
    expected = @baseline.fetch('options').merge('users_can_register' => '1', 'default_role' => admin ? 'administrator' : 'subscriber')
    expected['admin_email'] = options.fetch('WPEMAIL') if options.fetch('WPEMAIL', '').match?(URI::MailTo::EMAIL_REGEXP)
    gdpr_account(label, call.fetch(:options).fetch('USER'), call.fetch(:options).fetch('EMAIL'), admin: admin, agent: call.fetch(:options).fetch('UserAgent'), public_account: true)
    expect(state.fetch('options')).to eq(expected)
    expect(output).to include("Registering #{call.fetch(:options).fetch('USER')} with email #{call.fetch(:options).fetch('EMAIL')}")
    expect(output).not_to include('Failed to register user', 'Auxiliary aborted', 'Running automatic check')
    reports = chain_reports
    expect(reports.fetch('credentials')).to eq([])
    expect(reports.fetch('loot')).to eq([])
    call[:assertions] = 'passed'
  ensure
    gdpr_public_recover(label)
  end

  def gdpr_refusal(label, options, message, changed: true)
    call = gdpr_call(label, 'run', options)
    state = chain_identity(label + '-actual-refusal-state')
    pattern = message.is_a?(Regexp) ? message : Regexp.new(Regexp.escape(message))
    expect(gdpr_output(call)).to match(pattern)
    expect(state.fetch('users')).to eq(@baseline.fetch('users'))
    expected = @baseline.fetch('options')
    expected = expected.merge('users_can_register' => '1', 'default_role' => 'administrator') if changed
    expect(state.fetch('options')).to eq(expected)
    expect(chain_reports.fetch('credentials')).to eq([])
    expect(chain_reports.fetch('loot')).to eq([])
    call[:assertions] = 'passed'
  ensure
    gdpr_public_recover(label)
  end

  def gdpr_public_recover(label)
    original = $ERROR_INFO
    if original
      (@chain[:failed_states] ||= []) << { label: label, error: { class: original.class.name, message: original.message, backtrace: original.backtrace }, identity: chain_identity(label + '-failed-state'), reports: chain_reports }
    end
    gdpr_restore(label)
  rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
    (@chain[:recovery_errors] ||= []) << { label: label, class: e.class.name, message: e.message }
    raise(original || e)
  ensure
    chain_save
  end
end
