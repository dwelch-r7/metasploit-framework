require 'acceptance_spec_helper'
require 'socket'
require_relative '../../../../../test/module_targets/ti_wishlist/native'

RSpec.describe 'TI WooCommerce Wishlist genuine SQLi targets', acceptance: true, order: :defined do
  include_context 'module target'
  include TiWishlistNative

  before(:all) do
    @wl = { commands: [], identities: [], requests: [], controls: [], resources: [], reports: [], calls: [], loot: [] }
    @release = ENV.fetch('TI_WISHLIST_RELEASE', '2.8.2')
    @mode = ENV.fetch('TI_WISHLIST_MODE', 'enabled')
    @prefix = ENV.fetch('TI_WISHLIST_PREFIX', '')
    @vulnerable = @release == '2.8.2' && @mode == 'enabled'
    @count = Integer(ENV.fetch('TI_WISHLIST_COUNT', '1'))
    begin
      @baseline = wl_identity('before')
      wl_controls('before')
      expect(wl_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      expect(wl_sql('SELECT usesuper FROM pg_user WHERE usename=current_user').strip).to eq('f')
      endpoint = target_endpoint('reporting_db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets')
      wl_workspace("ti_wishlist_#{Process.pid}")
      expect(wl_reports.values).to all(eq([]))
      output = console_command('irb -e \'puts "WISHLIST_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/scanner/http/wp_ti_woocommerce_wishlist_sqli.rb").hexdigest, helper_sha256: Digest::SHA256.file("lib/msf/core/exploit/remote/http/wordpress/sqli.rb").hexdigest}.to_json\'')
      @wl[:provenance] = JSON.parse(output.match(/^WISHLIST_PROVENANCE=(.+)$/)[1])
      expect(@wl.fetch(:provenance).fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@wl.fetch(:provenance).fetch('owner_sha256')).to eq(Digest::SHA256.file("modules/#{wl_fullname}.rb").hexdigest)
      expect(@wl.fetch(:provenance).fetch('helper_sha256')).to eq(Digest::SHA256.file('lib/msf/core/exploit/remote/http/wordpress/sqli.rb').hexdigest)
      @wl[:preflight] = 'passed'
    ensure
      wl_save
    end
  end

  after(:all) do
    if @baseline
      after = wl_identity('after')
      keys = @baseline.keys - ['native_tables']
      expect(after.slice(*keys)).to eq(@baseline.slice(*keys))
      wl_controls('after') if @wl[:preflight]
    end
    if @wl && @wl[:preflight] && !@wl[:console_lost]
      expect(console_command('irb -e \'puts "WISHLIST_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('WISHLIST_STATE={"sessions":[],"jobs":[]}')
    end
  ensure
    begin
      wl_resources('failure-final') if @wl && @wl.fetch(:resources).none? { |row| row.fetch(:phase) == 'after' }
    ensure
      wl_save
    end
  end

  Integer(ENV.fetch('TI_WISHLIST_REPEATS', '1')).times do |iteration|
    it "verifies complete native data or refusal on public run #{iteration + 1}" do
      wl_call("normal-#{iteration + 1}", {}, expected: @vulnerable ? :credentials : :refusal, reuse: iteration.positive?)
    end
  end

  if ENV['TI_WISHLIST_NEGATIVES'] == '1'
    it 'refuses a bounded missing product without reporting credentials' do
      wl_workspace("ti_wishlist_#{Process.pid}_missing")
      wl_call('missing', { 'PRODUCT_ID_MIN' => 0, 'PRODUCT_ID_MAX' => 0 }, expected: :missing)
    end

    it 'refuses a reversed product range without reporting credentials' do
      wl_workspace("ti_wishlist_#{Process.pid}_reversed")
      wl_call('reversed', { 'PRODUCT_ID_MIN' => 1, 'PRODUCT_ID_MAX' => 0 }, expected: :missing)
    end

    it 'refuses a reserved non-listening loopback port without findings' do
      socket = Socket.new(:INET, :STREAM, 0)
      socket.bind(Socket.sockaddr_in(0, '127.0.0.1'))
      wl_workspace("ti_wishlist_#{Process.pid}_closed")
      wl_call('closed', { 'RPORT' => socket.local_address.ip_port, 'PRODUCT_ID_MIN' => 0, 'PRODUCT_ID_MAX' => 0 }, expected: :missing)
    ensure
      socket&.close
    end
  end

  def wl_fullname
    'auxiliary/scanner/http/wp_ti_woocommerce_wishlist_sqli'
  end

  def wl_call(label, overrides, expected:, reuse: false)
    skip 'Console was lost during a previous public call' if @wl[:console_lost]

    options = { 'TARGETURI' => @prefix + '/', 'VHOST' => 'module-target.test', 'SqliDelay' => 0.5, 'HttpClientTimeout' => 5, 'THREADS' => 1, 'VERBOSE' => true }
    options['COUNT'] = @count if ENV.key?('TI_WISHLIST_COUNT')
    options.merge!(overrides)
    if @mode == 'no_products' || %w[inactive absent].include?(@mode)
      options.merge!('PRODUCT_ID_MIN' => 0, 'PRODUCT_ID_MAX' => 0)
    end
    previous_reports = wl_reports
    previous = previous_reports.fetch('credentials')
    call = { label: label, options: options, expected: expected, workspace: @wl.fetch(:workspace), state: 'started' }
    @wl.fetch(:calls) << call
    wl_save
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    output = run_target_module(wl_fullname, 'app', options, allow_errors: true, command_timeout: 900, reuse_module: reuse) do |returned|
      call.merge!(state: 'returned', seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, output_base64: Base64.strict_encode64(returned.b))
      wl_save
    end
    provenance = console_command('irb -e \'puts "WISHLIST_INSTANCE=" + active_module.object_id.to_s\'')
    call[:module_object_id] = Integer(provenance.match(/^WISHLIST_INSTANCE=(\d+)$/)[1])
    expect(call.fetch(:module_object_id)).to eq(@wl.fetch(:module_object_id)) if reuse
    @wl[:module_object_id] = call.fetch(:module_object_id)
    reports = wl_reports
    rows = reports.fetch('credentials')
    expect(output).not_to match(/Unknown datastore option|Auxiliary failed|Exception|NoMethodError/)
    if expected == :credentials
      expect(output).not_to include('Auxiliary aborted', 'Connection failed')
      expect(output).to include('Share key found:', 'SQL Injection successful, retrieving user credentials...', 'Loot saved to:')
      expect(rows.length).to eq(@count)
      expect(rows.map { |row| row.fetch('username') }.uniq.length).to eq(@count)
      native = @baseline.fetch('users').to_h { |row| row.values_at('user_login', 'user_pass') }
      endpoint = target_endpoint('app')
      rows.each do |row|
        expect(row.fetch('private_data')).to eq(native.fetch(row.fetch('username')))
        expect(row.values_at('private_type', 'origin_type', 'module_full_name', 'address', 'port', 'proto')).to eq(['Metasploit::Credential::NonreplayableHash', 'Metasploit::Credential::Origin::Service', wl_fullname, endpoint.fetch('host'), endpoint.fetch('port'), 'tcp'])
        expect(row.fetch('service')).to match(/\Awordpress\z/i)
      end
      expect(rows).to eq(previous) if reuse
      expect(reports.fetch('vulns').map { |row| row.values_at('name', 'address', 'port', 'proto') }).to eq([[wl_fullname, endpoint.fetch('host'), endpoint.fetch('port'), 'tcp']])
      path = output.match(/Loot saved to: (.+)$/)[1].strip
      expect(File.expand_path(path)).to start_with(File.expand_path(ENV.fetch('MSF_CFGROOT_CONFIG')) + '/')
      expected_lines = rows.map { |row| "Username: #{row.fetch('username')}, Password Hash: #{row.fetch('private_data')}\n".b }
      expect(File.binread(path).lines.sort).to eq(expected_lines.sort)
      new_loot = reports.fetch('loot').reject { |row| previous_reports.fetch('loot').any? { |old| old.fetch('id') == row.fetch('id') } }
      expect(new_loot.map { |row| row.values_at('path', 'ltype', 'content_type', 'address') }).to eq([[path, 'wordpress.users', 'text/plain', endpoint.fetch('host')]])
      @wl.fetch(:loot) << { path: path, bytes: File.size(path), sha256: Digest::SHA256.file(path).hexdigest, content_base64: Base64.strict_encode64(File.binread(path)) }
    else
      expect(output).to include(expected == :missing || @mode != 'enabled' ? 'No valid product ID found.' : 'Target is not vulnerable to SQL injection.')
      expect(output).not_to include('Loot saved to:', 'SQL Injection successful')
      expect(reports.values).to all(eq([]))
    end
    wl_save
  rescue Acceptance::ChildProcessRecvError, Acceptance::ChildProcessTimeoutError, EOFError => e
    @wl[:console_lost] = { type: e.class.name, message: e.message }
    raise
  ensure
    call[:console_base64] = Base64.strict_encode64(console.all_data.b) if call
    wl_save
  end
end
