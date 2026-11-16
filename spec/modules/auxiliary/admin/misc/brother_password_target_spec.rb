require 'acceptance_spec_helper'
require 'base64'
require 'digest'
require 'json'
require 'socket'

RSpec.describe 'Brother supplied-serial generation and reporting', acceptance: true, order: :defined do
  include_context 'module target'

  cases = JSON.parse(File.read('test/module_targets/brother_password/cases.json')).fetch('cases')

  before(:all) do
    @brother = { scope: 'Provided synthetic serial, ValidatePassword=false; no device authentication qualification', calls: [], reports: [], network_checks: [], resources: [] }
    @tcp = TCPServer.new('127.0.0.1', 0)
    @udp = UDPSocket.new
    @udp.bind('127.0.0.1', 0)
    @device_port = @tcp.local_address.ip_port
    @snmp_port = @udp.local_address.ip_port
    begin
      brother_resources('before')
      expect(brother_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      expect(brother_sql('SELECT usesuper FROM pg_user WHERE usename=current_user').strip).to eq('f')
      endpoint = target_endpoint('reporting_db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets')
      output = console_command("irb -e 'puts \"BROTHER_PROVENANCE=\" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file(\"modules/#{brother_fullname}.rb\").hexdigest}.to_json'")
      @brother[:provenance] = JSON.parse(output.match(/^BROTHER_PROVENANCE=(.+)$/)[1])
      expect(@brother.fetch(:provenance).fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@brother.fetch(:provenance).fetch('owner_sha256')).to eq(Digest::SHA256.file("modules/#{brother_fullname}.rb").hexdigest)
      @brother[:preflight] = 'passed'
    ensure
      brother_save
    end
  end

  after(:all) do
    if @brother&.key?(:preflight)
      brother_resources('after')
      expect(console_command('irb -e \'puts "BROTHER_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('BROTHER_STATE={"sessions":[],"jobs":[]}')
      expect(Dir.glob(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*'))).to eq([])
    end
  ensure
    @tcp&.close
    @udp&.close
    brother_save
  end

  cases.each do |entry|
    it "handles #{entry.fetch('case')} through the public run method" do
      brother_run(entry)
    end
  end

  def brother_fullname
    'auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978'
  end

  def brother_run(entry)
    @workspace = "brother_target_#{Process.pid}_#{entry.fetch('workspace')}"
    expect(@workspace).to match(/\Abrother_target_[0-9]+_[a-z0-9]+\z/)
    expect(console_command("workspace -a #{@workspace}")).to include(@workspace)
    before = brother_reports
    expect(before).to eq([]) unless entry.fetch('case') == 'repeat-same-serial'
    options = { 'TargetSerial' => entry.fetch('serial'), 'ValidatePassword' => false, 'PJL_RPORT' => @device_port, 'SNMP_RPORT' => @snmp_port, 'HttpClientTimeout' => 3 }
    %w[SaltLookupIndex SaltData SSL DiscoverSerialVia].each { |key| options[key] = entry[key] if entry.key?(key) }
    call = { case: entry.fetch('case'), workspace: @workspace, options: options, state: 'started' }
    @brother.fetch(:calls) << call
    brother_save
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    output = run_target_module(brother_fullname, 'reporting_db', options, endpoint_options: { 'RHOSTS' => '127.0.0.1', 'RPORT' => @device_port }, allow_errors: true)
    call.merge!(state: 'returned', seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, output_base64: Base64.strict_encode64(output.b))
    brother_save
    brother_no_device_traffic(entry.fetch('case'))
    rows = brother_reports
    expect(output).not_to match(/Unknown datastore option|Auxiliary failed|Exception|NoMethodError/)
    expect(output).not_to match(/Attempting to leak|Attempting to validate|Leaked target serial|Successfully validated/)
    if entry.key?('error')
      expect(output).to include('Auxiliary aborted due to failure: bad-config', entry.fetch('error'))
      expect(output).not_to include('Generated default password value:')
      expect(rows).to eq([])
    else
      expect(output).not_to include('Auxiliary aborted', '[-]')
      expect(output).to include("Generated default password value: #{entry.fetch('expected_password')}")
      expect(rows.length).to eq(1)
      row = rows.first
      expect(row).to include('username' => 'admin', 'private_data' => entry.fetch('expected_password'), 'private_type' => 'Metasploit::Credential::Password',
                             'origin_type' => 'Metasploit::Credential::Origin::Service', 'module_full_name' => brother_fullname,
                             'address' => '127.0.0.1', 'port' => @device_port, 'proto' => 'tcp', 'service' => entry.fetch('SSL', true) ? 'https' : 'http')
      expect(row.fetch('logins')).to contain_exactly(include('status' => 'Untried', 'service_id' => row.fetch('service_id'), 'last_attempted_at' => nil))
      ids = [row.fetch('id'), row.fetch('service_id'), row.fetch('logins').first.fetch('id')]
      if entry.fetch('case') == 'repeat-same-serial'
        previous = before.fetch(0)
        expect(ids).to eq([previous.fetch('id'), previous.fetch('service_id'), previous.fetch('logins').first.fetch('id')])
      end
    end
  ensure
    call[:console_base64] = Base64.strict_encode64(console.all_data.b) if call
    brother_save
  end

  def brother_no_device_traffic(label)
    # These reserved listeners never answer a vendor protocol. Their queues
    # catch an accidental discovery/login branch without emulating a printer.
    connection = @tcp.accept_nonblock(exception: false)
    datagram = @udp.recv_nonblock(1, exception: false)
    @brother.fetch(:network_checks) << { case: label, tcp: connection == :wait_readable ? 'empty' : 'unexpected_connection', udp: datagram == :wait_readable ? 'empty' : 'unexpected_datagram' }
    brother_save
    expect(connection).to eq(:wait_readable)
    expect(datagram).to eq(:wait_readable)
  ensure
    connection.close if connection.is_a?(TCPSocket)
  end

  def brother_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'functional-brother-password.json'), JSON.pretty_generate(@brother)) if @brother
  end

  def brother_resources(phase)
    %w[memory.events pids.events].each do |key|
      text = target_exec('reporting_db', 'cat', '/sys/fs/cgroup/' + key)
      values = text.lines.to_h do |line|
        name, value = line.split
        [name, Integer(value)]
      end
      @brother.fetch(:resources) << { phase: phase, key: key, values: values }
      brother_save
      expect(values.values_at('oom', 'oom_kill')).to eq([0, 0]) if key == 'memory.events'
      expect(values.fetch('max')).to eq(0) if key == 'pids.events'
    end
  end

  def brother_sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def brother_reports
    raise ArgumentError, 'Invalid Brother test workspace' unless @workspace.match?(/\Abrother_target_[0-9]+_[a-z0-9]+\z/)

    rows = JSON.parse(brother_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT c.id,p.username,secret.data AS private_data,secret.type AS private_type,c.origin_type,
          o.module_full_name,s.id AS service_id,s.port,s.proto,s.name AS service,host(h.address::inet) AS address,
          (SELECT coalesce(json_agg(json_build_object('id',l.id,'status',l.status,'service_id',l.service_id,'last_attempted_at',l.last_attempted_at)),'[]'::json)
            FROM metasploit_credential_logins l WHERE l.core_id=c.id) AS logins
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        LEFT JOIN services s ON s.id=o.service_id LEFT JOIN hosts h ON h.id=s.host_id
        WHERE w.name='#{@workspace}'
      ) row
    SQL
    @brother.fetch(:reports) << { workspace: @workspace, rows: rows }
    brother_save
    rows
  end
end
