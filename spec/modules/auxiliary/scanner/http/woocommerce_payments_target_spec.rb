require 'acceptance_spec_helper'
require 'socket'
require_relative '../../../../../test/module_targets/woocommerce_payments/native'

RSpec.describe 'WooCommerce Payments genuine administrator creation targets', acceptance: true, order: :defined do
  include_context 'module target'
  include WoocommercePaymentsNative

  before(:all) do
    @payments = { commands: [], identities: [], requests: [], controls: [], resources: [], calls: [], reports: [], operator_cleanup: [] }
    @release = ENV.fetch('WOO_PAYMENTS_RELEASE', '5.6.1')
    @mode = ENV.fetch('WOO_PAYMENTS_MODE', 'enabled')
    @prefix = ENV.fetch('WOO_PAYMENTS_PREFIX', '')
    @vulnerable = @release == '5.6.1' && @mode == 'enabled'
    @appears = @release == '5.6.1' && @mode != 'absent'
    @catalog = JSON.parse(File.read('test/module_targets/woocommerce_payments/releases.json')).fetch(@release)
    begin
      @baseline = payments_native_gate('before')
      expect(@baseline.fetch('users').length).to eq(4)
      expect(payments_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      expect(payments_sql('SELECT usesuper FROM pg_user WHERE usename=current_user').strip).to eq('f')
      endpoint = target_endpoint('reporting_db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets')
      payments_workspace("payments_#{Process.pid}_initial")
      expect(payments_reports.values).to all(eq([]))
      output = console_command(%q{irb -e 'puts "PAYMENTS_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/scanner/http/wp_woocommerce_payments_add_user.rb").hexdigest, successful_status: Metasploit::Model::Login::Status::SUCCESSFUL}.to_json'})
      @payments[:provenance] = JSON.parse(output.match(/^PAYMENTS_PROVENANCE=(.+)$/)[1])
      expect(@payments.fetch(:provenance).fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@payments.fetch(:provenance).fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/' + payments_fullname + '.rb').hexdigest)
      @payments[:preflight] = 'passed'
    ensure
      payments_save
    end
  end

  before do
    skip 'A previous call lost the console or left target state; use a fresh profile' if @payments[:console_lost] || @payments[:contaminated]
  end

  after(:all) do
    if @payments&.key?(:preflight)
      expect(payments_native_gate('after')).to eq(@baseline) unless @payments[:contaminated]
      unless @payments[:console_lost]
        expect(console_command(%q{irb -e 'puts "PAYMENTS_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json'})).to include('PAYMENTS_STATE={"sessions":[],"jobs":[]}')
      end
      expect(Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '**', '*')].select { |path| File.file?(path) }).to eq([])
    end
  ensure
    payments_resources('failure-final') if @payments && @payments.fetch(:resources).none? { |row| row.fetch(:phase) == 'after' }
    payments_save
  end

  it 'checks the actual installed release through public check' do
    output, reports = payments_call('check', {}, action: 'check')
    expect(output).to include(@appears ? 'WooCommerce-Payments version is exploitable' : 'WooCommerce-Payments version not vulnerable or plugin not installed')
    expect(reports.fetch('credentials')).to eq([])
    expect(reports.fetch('loot')).to eq([])
    if @appears
      expect(reports.fetch('vulns').length).to eq(1)
      expect(reports.fetch('vulns').first.values_at('name', 'port', 'address')).to eq([
        'Wordpress Plugin WooCommerce Payments Unauthenticated Admin Creation', target_endpoint('app').fetch('port'), target_endpoint('app').fetch('host')
      ])
      expect(reports.fetch('vulns').first.fetch('refs')).to include('CVE-2023-28121')
    else
      expect(reports.fetch('vulns')).to eq([])
    end
  end

  Integer(ENV.fetch('WOO_PAYMENTS_REPEATS', '1')).times do |index|
    it "validates administrator creation or refusal on public run #{index + 1}" do
      payments_case('normal_' + index.to_s, { 'USERNAME' => 'module_payments_repeat', 'EMAIL' => 'module-payments-repeat@example.test' }, success: @vulnerable, reuse: index.positive?)
    end
  end

  if ENV['WOO_PAYMENTS_NEGATIVES'] == '1'
    it 'creates an administrator with generated password and email' do
      payments_case('generated', { 'PASSWORD' => '', 'EMAIL' => '' }, success: true, generated: true)
    end

    it 'creates and reports a valid plus-address email' do
      payments_case('plus_email', { 'EMAIL' => 'module-payments+plus@example.test' }, success: true)
    end

    it 'runs without AutoCheck and still creates a usable administrator' do
      payments_case('no_autocheck', { 'AutoCheck' => false }, success: true)
    end

    { 'author' => 2, 'missing_user' => 99999 }.each do |label, identifier|
      it "refuses the #{label} identity without credentials" do
        payments_case(label, { 'ADMINID' => identifier }, success: false)
      end
    end

    it 'preserves an existing account when the username is duplicated' do
      payments_case('duplicate', { 'USERNAME' => 'module_admin' }, success: false)
    end

    it 'handles a reserved non-listening local port without reporting credentials' do
      socket = Socket.new(:INET, :STREAM, 0)
      socket.bind(Socket.sockaddr_in(0, '127.0.0.1'))
      output, reports = payments_call('closed', { 'RPORT' => socket.local_address.ip_port, 'AutoCheck' => false })
      expect(output).to include('Connection failed')
      expect(reports.values).to all(eq([]))
      expect(payments_identity('after-closed')).to eq(@baseline)
    ensure
      socket&.close
    end
  end

  if ENV['WOO_PAYMENTS_FORCE'] == '1'
    it 'refuses a forced public run on the independently fixed application' do
      payments_case('forced', { 'ForceExploit' => true }, success: false)
    end
  end

  def payments_fullname
    'auxiliary/scanner/http/wp_woocommerce_payments_add_user'
  end

  def payments_call(label, overrides, action: 'run', reuse: false)
    payments_workspace("payments_#{Process.pid}_#{label}")
    expect(payments_reports.values).to all(eq([]))
    options = {
      'TARGETURI' => @prefix + '/', 'VHOST' => 'module-target.test', 'HttpClientTimeout' => 5,
      'USERNAME' => 'module_payments_' + label, 'PASSWORD' => 'Module-target-public+2026!',
      'EMAIL' => 'module-payments-' + label.tr('_', '-') + '@example.test', 'ADMINID' => 1,
      'AutoCheck' => true, 'ForceExploit' => false
    }.merge(overrides)
    endpoint = target_endpoint('app')
    call = { label: label, options: options, action: action, workspace: @payments.fetch(:workspace), started_at: Time.now.utc.iso8601(6), state: 'started' }
    @payments.fetch(:calls) << call
    payments_save
    output = run_target_module(payments_fullname, 'app', options, action: action, allow_errors: true, endpoint_options: { 'RHOST' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port') }, command_timeout: 90, reuse_module: reuse) do |returned|
      call.merge!(output_base64: Base64.strict_encode64(returned.b), finished_at: Time.now.utc.iso8601(6), state: 'returned')
      payments_save
    end
    identity = console_command(%q{irb -e 'puts "PAYMENTS_INSTANCE=" + active_module.object_id.to_s'})
    call[:module_object_id] = Integer(identity.match(/^PAYMENTS_INSTANCE=(\d+)$/)[1])
    expect(call.fetch(:module_object_id)).to eq(@payments.fetch(:module_object_id)) if reuse
    @payments[:module_object_id] = call.fetch(:module_object_id)
    reports = payments_reports
    call[:reports] = reports
    payments_save
    expect(output).not_to match(/Unknown datastore option|Auxiliary failed|Exception|NoMethodError/)
    [output, reports, options, call]
  rescue Acceptance::ChildProcessRecvError, Acceptance::ChildProcessTimeoutError, EOFError
    @payments[:console_lost] = true
    payments_save
    raise
  end

  def payments_case(label, overrides, success:, reuse: false, generated: false)
    output, reports, options, call = payments_call(label, overrides, reuse: reuse)
    rows = reports.fetch('credentials')
    if success
      expect(output).to include('User was created successfully')
      expect(rows.length).to eq(1)
      credential = rows.first
      endpoint = target_endpoint('app')
      expect(credential.values_at('username', 'private_type', 'origin_type', 'module_full_name', 'address', 'port', 'proto', 'access_level', 'status')).to eq([
        options.fetch('USERNAME'), 'Metasploit::Credential::Password', 'Metasploit::Credential::Origin::Service', payments_fullname,
        endpoint.fetch('host'), endpoint.fetch('port'), 'tcp', 'administrator', @payments.fetch(:provenance).fetch('successful_status')
      ])
      expect(credential.fetch('service')).to match(/\Awordpress\z/i)
      expect(credential.fetch('login_id')).to be_a(Integer)
      expect(Time.parse(credential.fetch('last_attempted_at'))).to be_between(Time.parse(call.fetch(:started_at)) - 1, Time.parse(call.fetch(:finished_at)) + 1)
      if generated
        expect(credential.fetch('private_data')).to match(/\A[A-Za-z0-9]{10,15}\z/)
        email = output.match(/Attempting to create an administrator user -> .+ \(([^\n]+)\)/)[1]
      else
        expect(credential.fetch('private_data')).to eq(options.fetch('PASSWORD'))
        email = options.fetch('EMAIL')
      end
      account = payments_verify_account(label + '-public', options.fetch('USERNAME'), credential.fetch('private_data'), email)
      call[:created_user_id] = account.fetch('ID')
      if reuse
        previous = @payments.fetch(:calls).reverse.find { |entry| entry != call && entry[:created_user_id] && entry.fetch(:options).fetch('USERNAME') == options.fetch('USERNAME') }
        expect(previous).not_to be_nil
        expect(call.fetch(:created_user_id)).to be > previous.fetch(:created_user_id)
      end
    else
      expect(output).not_to include('User was created successfully')
      expect(rows).to eq([])
      expect(payments_identity(label + '-refused')).to eq(@baseline)
      if !@appears && !options.fetch('ForceExploit')
        expect(output).to include('Auxiliary aborted', 'not vulnerable or plugin not installed')
      else
        expect(output).to include('Server response:')
      end
    end
    expect(reports.fetch('loot')).to eq([])
    if @appears && options.fetch('AutoCheck')
      expect(reports.fetch('vulns').length).to eq(1)
      expect(reports.fetch('vulns').first.values_at('name', 'port', 'address')).to eq([payments_fullname, target_endpoint('app').fetch('port'), target_endpoint('app').fetch('host')])
      expect(reports.fetch('vulns').first.fetch('refs')).to include('CVE-2023-28121')
    else
      expect(reports.fetch('vulns')).to eq([])
    end
    call[:assertions] = 'passed'
    payments_save
  ensure
    options ||= @payments&.fetch(:calls)&.reverse&.find { |entry| entry.fetch(:label) == label }&.fetch(:options)
    if options
      # Preserve the actual account/report state before test-owned removal.
      current = payments_identity(label + '-before-cleanup')
      @payments[:operator_cleanup] << { label: label, before: current }
      username = options.fetch('USERNAME')
      if username.start_with?('module_payments_') && current.fetch('users').any? { |user| user.fetch('user_login') == username }
        current = payments_identity(label + '-delete-owned', 'delete', username)
      end
      @payments[:contaminated] = current != @baseline
      payments_save
      expect(current).to eq(@baseline)
    end
  end
end
