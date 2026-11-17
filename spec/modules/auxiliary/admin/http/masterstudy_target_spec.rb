require 'acceptance_spec_helper'
require 'English'
require 'time'
require_relative '../../../../../test/module_targets/masterstudy/native'

RSpec.describe 'MasterStudy genuine administrator registration', acceptance: true, order: :defined do
  include_context 'module target'
  include MasterstudyNative

  before(:all) do
    @chain = { commands: [], requests: [], controls: [], calls: [], reports: [], operator_cleanup: [], public_accounts: [] }
    @release = ENV.fetch('MASTERSTUDY_RELEASE', '2.7.5')
    @prefix = ENV.fetch('MASTERSTUDY_PREFIX', '')
    @db_prefix = ENV.fetch('MASTERSTUDY_DB_PREFIX', 'wp_')
    @affected = @release == '2.7.5'
    @autocheck = ENV.fetch('MASTERSTUDY_AUTOCHECK', '1') == '1'
    @catalog = JSON.parse(File.read('test/module_targets/masterstudy/releases.json')).fetch(@release)
    @workspace_base = "wordpress_chain_#{Process.pid}"
    begin
      @baseline = chain_native_gate('before')
      expect(chain_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      expect(chain_sql('SELECT usesuper FROM pg_user WHERE usename=current_user').strip).to eq('f')
      endpoint = target_endpoint('reporting_db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets')
      master_workspace(@workspace_base)
      expect(chain_reports.values).to all(eq([]))
      console_command('use ' + master_fullname)
      output = console_command(%q{irb -e 'puts "MASTER_PROVENANCE=" + {ruby:RUBY_VERSION,config:Msf::Config.config_directory,owner_sha256:Digest::SHA256.file("modules/auxiliary/admin/http/wp_masterstudy_privesc.rb").hexdigest,owner_methods:[:check,:get_username,:get_password,:get_email].to_h{|name|[name,active_module.method(name).source_location]},run_source:active_module.method(:run).super_method.source_location}.to_json'})
      @chain[:provenance] = JSON.parse(output.match(/^MASTER_PROVENANCE=(.+)$/)[1])
      expect(@chain.fetch(:provenance).fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@chain.fetch(:provenance).fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/auxiliary/admin/http/wp_masterstudy_privesc.rb').hexdigest)
      (@chain.fetch(:provenance).fetch('owner_methods').values + [@chain.fetch(:provenance).fetch('run_source')]).each do |location|
        expect(File.realpath(location.first)).to eq(File.realpath('modules/auxiliary/admin/http/wp_masterstudy_privesc.rb'))
      end
      @chain[:preflight] = 'passed'
    ensure
      chain_save
    end
  end

  before do
    skip 'A previous call lost the console or target state; use a fresh profile' if @chain[:console_unresponsive] || @chain[:target_contaminated]
  end

  after(:all) do
    if @chain&.key?(:preflight)
      final = chain_native_gate('after')
      chain_assert_restored(final)
      expect(console_command(%q{irb -e 'puts "MASTER_IDLE=" + {sessions:framework.sessions.keys,jobs:framework.jobs.keys}.to_json'})).to include('MASTER_IDLE={"sessions":[],"jobs":[]}') unless @chain[:console_unresponsive]
      expect(Dir.glob(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*'))).to eq([])
    end
  ensure
    chain_save
  end

  it 'checks the genuine installed release without credentials or account changes' do
    call = master_call('check', 'check', {})
    expect(master_output(call)).to include(@affected ? 'appears to be vulnerable' : 'MasterStudy LMS version is not vulnerable (>= 2.7.6)')
    expect(chain_reports.fetch('credentials')).to eq([])
    chain_assert_restored(chain_identity('after-public-check'))
  end

  if ENV.fetch('MASTERSTUDY_RELEASE', '2.7.5') == '2.7.6'
    it 'blocks the fixed release through normal AutoCheck without an account' do
      call = master_call('blocked', 'run', {})
      expect(master_output(call)).to include('not-vulnerable:')
      expect(master_output(call)).not_to include('Account Created Successfully', 'Attempting with username:')
      expect(chain_reports.fetch('credentials')).to eq([])
      chain_assert_restored(chain_identity('after-fixed-block'))
    end

    it 'observes the genuine fixed vendor error and recovers the resulting subscriber with AutoCheck disabled' do
      call = master_call('partial', 'run', { 'AutoCheck' => false })
      expect(master_output(call)).to include('Request Failed to return a successful response')
      expect(master_output(call)).not_to include('Account Created Successfully')
      expect(chain_reports.fetch('credentials')).to eq([])
      master_prove_account(call, false)
    ensure
      master_recover(call)
    end
  else
    %w[explicit repeat].each_with_index do |label, index|
      it "creates and records an actual administrator on #{label} execution" do
        master_success(label, {}, reuse: index.positive?)
      end
    end

    if ENV.fetch('MASTERSTUDY_GENERATED', '1') == '1'
      {
        'username' => { 'USERNAME' => '' },
        'password' => { 'PASSWORD' => '' },
        'email' => { 'EMAIL' => '' },
        'defaults' => { 'USERNAME' => '', 'PASSWORD' => '', 'EMAIL' => '' }
      }.each do |label, options|
        it "creates an administrator using actual generated #{label} values" do
          master_success(label, options)
        end
      end
    end
  end

  if ENV['MASTERSTUDY_EXTRA'] == '1'
    { 'minimum' => 'Abcd1234', 'maximum' => 'Aa1xxxxxxxxxxxxxxxxx' }.each do |label, password|
      it "preserves a valid explicit password at the #{label} length boundary" do
        master_success(label, { 'PASSWORD' => password })
      end
    end

    {
      'duplicateuser' => [{ 'USERNAME' => 'module_subscriber' }, 'username already exists'],
      'duplicateemail' => [{ 'EMAIL' => 'module-subscriber@example.test' }, 'email address is already used'],
      'bademail' => [{ 'EMAIL' => 'not-an-email' }, 'E-mail'],
      'badusername' => [{ 'USERNAME' => '!!!' }, 'remove tags'],
      'shortpassword' => [{ 'PASSWORD' => 'Abcd12!' }, 'at least 8'],
      'longpassword' => [{ 'PASSWORD' => 'Aa1xxxxxxxxxxxxxxxxxx' }, 'too long'],
      # The genuine original getter produced this value without a required digit.
      'missingnumber' => [{ 'PASSWORD' => 'lrMIJLFPAQ' }, 'at least one number']
    }.each do |label, (options, reason)|
      it "reports the real #{label} refusal without an account or credential" do
        master_refusal(label, options, 'Account Creation Failed:', reason)
      end
    end

    it 'checks a genuine missing WordPress base without reporting an administrator' do
      route = @prefix + '/module-target-missing-masterstudy/'
      expect(chain_request('missing-base-independent', route).code).to eq('404')
      call = master_call('missingcheck', 'check', { 'TARGETURI' => route })
      expect(master_output(call)).to include('Server not online or not detected as wordpress')
      expect(chain_reports.fetch('credentials')).to eq([])
      chain_assert_restored(chain_identity('missing-check-restored'))
    end

    it 'rejects a genuine missing page before registration with AutoCheck disabled' do
      route = @prefix + '/module-target-missing-masterstudy/'
      expect(chain_request('missing-run-independent', route).code).to eq('404')
      master_refusal('missingrun', { 'TARGETURI' => route, 'AutoCheck' => false }, 'Request failed to return a successful response')
    end

    it 'rejects a real 200 WordPress login page without the registration nonce' do
      route = @prefix + '/wp-login.php'
      response = chain_request('nonce-absent-independent', route)
      expect(response.code).to eq('200')
      expect(response.body).not_to include('"stm_lms_register":')
      master_refusal('missingnonce', { 'TARGETURI' => route, 'AutoCheck' => false }, 'Unabled to retrieve MasterStudy Nonce from page')
    end
  end

  def master_refusal(label, options, *messages)
    call = master_call(label, 'run', options)
    expect(master_output(call)).to include(*messages)
    expect(master_output(call)).not_to include('Account Created Successfully')
    reports = chain_reports
    expect(reports.fetch('credentials')).to eq([])
    expect(reports.fetch('loot')).to eq([])
    chain_assert_restored(chain_identity(label + '-unchanged'))
    call[:assertions] = 'passed'
  ensure
    if $ERROR_INFO
      (@chain[:failed_states] ||= []) << { label: label, identity: chain_identity('failed-' + label), reports: chain_reports }
    end
    master_recover(call)
  end

  if ENV['MASTERSTUDY_WRONG_PREFIX'] == '1'
    it 'creates only a subscriber when the supplied database prefix differs from the installation' do
      master_success('wrongprefix', { 'DB_PREFIX' => 'wp_' }, admin: false)
    end
  end

  def master_fullname
    'auxiliary/admin/http/wp_masterstudy_privesc'
  end

  def master_workspace(name)
    expect(name).to match(/\Awordpress_chain_\d+(?:_[a-z]+)?\z/)
    @workspace = name
    expect(console_command('workspace -a ' + name)).to include(name)
  end

  def master_call(label, action, overrides, reuse: false)
    master_workspace(@workspace_base + '_' + label)
    options = {
      'TARGETURI' => @prefix + '/', 'VHOST' => 'module-target.test', 'SSL' => false, 'HttpClientTimeout' => 5,
      'USERNAME' => 'module_masterstudy_owned', 'PASSWORD' => 'Module-study+2026!', 'EMAIL' => 'module-masterstudy-owned@example.test',
      'UserAgent' => "module-target-masterstudy-public-#{Process.pid}-#{label}", 'AutoCheck' => @autocheck
    }
    options['DB_PREFIX'] = @db_prefix if ENV.key?('MASTERSTUDY_DB_PREFIX')
    options.merge!(overrides)
    call = { label: label, action: action, options: options, workspace: @workspace, state: 'started', started_at: Time.now.utc.iso8601(6) }
    @chain.fetch(:calls) << call
    chain_save
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    run_target_module(master_fullname, 'app', options, action: action, allow_errors: true, command_timeout: 60, reuse_module: reuse) do |output|
      call.merge!(state: 'returned', finished_at: Time.now.utc.iso8601(6), seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, output_base64: Base64.strict_encode64(output.b))
      actual = output.match(/Attempting with username: (\S+) password: (.*?) email: (\S+)/)
      call[:actual_credentials] = { name: actual[1], password: actual[2], email: actual[3] } if actual
      metadata = console_command(%q{irb -e 'puts "MASTER_MODULE=" + {id:active_module.object_id,fullname:active_module.fullname}.to_json'})
      call[:module] = JSON.parse(metadata.match(/^MASTER_MODULE=(.+)$/)[1])
      expect(call.fetch(:module).fetch('fullname')).to eq(master_fullname)
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

  def master_output(call)
    Base64.strict_decode64(call.fetch(:output_base64)).force_encoding(Encoding::UTF_8)
  end

  def master_prove_account(call, admin)
    values = call.fetch(:actual_credentials)
    { 'USERNAME' => :name, 'PASSWORD' => :password, 'EMAIL' => :email }.each do |option, field|
      configured = call.fetch(:options).fetch(option)
      expect(values.fetch(field)).to eq(configured) unless configured.blank?
    end
    user = master_auth('public-' + call.fetch(:label), values.fetch(:name), values.fetch(:password), admin, call.fetch(:options).fetch('UserAgent'))
    @chain.fetch(:public_accounts) << { label: call.fetch(:label), id: user.fetch('ID'), name: values.fetch(:name), email: values.fetch(:email), admin: admin, actual_login: true }
    expect(user.fetch('user_email')).to eq(values.fetch(:email))
    chain_save
    user
  end

  def master_success(label, options, reuse: false, admin: true)
    call = master_call(label, 'run', options, reuse: reuse)
    expect(master_output(call)).to include('Account Created Successfully')
    expect(master_output(call)).not_to include('Account Creation Failed:', 'Auxiliary aborted')
    expect(master_output(call)).not_to include('Running automatic check') unless @autocheck
    values = call.fetch(:actual_credentials)
    master_prove_account(call, admin)
    reports = chain_reports
    expect(reports.fetch('loot')).to eq([])
    expect(reports.fetch('credentials').length).to eq(1)
    credential = reports.fetch('credentials').first
    endpoint = target_endpoint('app')
    expect(credential.values_at('username', 'private_data', 'address', 'port', 'proto', 'service', 'module_full_name')).to eq([values.fetch(:name), values.fetch(:password), endpoint.fetch('host'), endpoint.fetch('port'), 'tcp', 'wordpress', master_fullname])
    expect(credential.fetch('private_type')).to eq('Metasploit::Credential::Password')
    # Service-origin core creation also persists an Untried login. Native authentication is independent.
    expect(credential.fetch('login_id')).to be_a(Integer)
    expect(credential.values_at('status', 'last_attempted_at')).to eq(['Untried', nil])
    call[:assertions] = 'passed'
  ensure
    if $ERROR_INFO
      (@chain[:failed_states] ||= []) << { label: label, identity: chain_identity('failed-' + label), reports: chain_reports }
    end
    master_recover(call)
  end

  def master_recover(call)
    current = chain_identity('before-public-recovery')
    added = current.fetch('users').reject { |user| @baseline.fetch('users').any? { |initial| initial.fetch('ID') == user.fetch('ID') } }
    expect(added.length).to be <= 1
    added.each do |user|
      values = call.fetch(:actual_credentials)
      expect(user.values_at('user_login', 'user_email')).to eq(values.values_at(:name, :email))
      owned = values.merge(id: user.fetch('ID'), agent: call.fetch(:options).fetch('UserAgent'))
      result = chain_identity('owned-public-delete', 'delete-public', Base64.strict_encode64(owned.to_json)).fetch('operation_result')
      expect(result.fetch('deleted_user_id')).to eq(user.fetch('ID'))
      @chain.fetch(:operator_cleanup) << { label: call.fetch(:label), id: user.fetch('ID'), name: user.fetch('user_login'), reason: 'Owner retains accounts; native operator recovery after identity/password/token validation' }
    end
    current = chain_identity('after-public-recovery')
    @chain[:target_contaminated] = master_selected(current) != master_selected(@baseline)
    chain_assert_restored(current)
    chain_save
  end
end
