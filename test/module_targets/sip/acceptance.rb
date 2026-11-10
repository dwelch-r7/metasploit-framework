# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'metasploit_data_models'
require 'open3'

# Native controls and ordinary database API assertions for this owned SIP lab.
module ModuleTargetSip
  def native_action(action, **options)
    argv = ['python3', '-B', 'test/module_targets/sip/native_action.py']
    request = { action: action }.merge(options)
    stdout, stderr, status = Open3.capture3(*argv, stdin_data: JSON.generate(request))
    File.open(File.join(target_runtime.fetch('artifacts'), 'native-actions.jsonl'), 'a') do |file|
      file.puts(JSON.generate(argv: argv, request: request, exitstatus: status.exitstatus, stdout_base64: Base64.strict_encode64(stdout), stderr: stderr))
    end
    expect(status.success?).to be(true), stderr
    expect(stderr).to eq('')
    JSON.parse(stdout)
  end

  def endpoint(service)
    target_runtime.fetch('module_endpoints').fetch(service)
  end

  def native_reply(service, transport, method, account)
    row = @native.fetch('matrix').find do |entry|
      request = entry.fetch('operation')
      request.fetch('role') == service && request.fetch('transport') == transport && request.fetch('method') == method && request.fetch('account') == account
    end
    row.fetch('result').fetch('responses').first
  end

  def scan(fullname, service, options = {}, allow_errors: false, port: nil)
    connection = { 'RHOSTS' => endpoint(service).fetch('host'), 'RPORT' => port || endpoint(service).fetch('port') }
    output = run_target_module(fullname, service, options, allow_errors: allow_errors, endpoint_options: connection)
    expect(output).not_to include('Unknown datastore option:')
    output
  end

  def sip_sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def services
    query = <<~SQL
      SELECT COALESCE(json_agg(row),'[]') FROM (
        SELECT s.id,host(h.address) AS address,s.port,s.proto,s.name,s.info
        FROM services s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id
        WHERE w.name='#{@workspace}' ORDER BY s.port,s.proto,s.name
      ) row
    SQL
    JSON.parse(sip_sql(query))
  end

  def notes
    query = <<~SQL
      SELECT COALESCE(json_agg(row),'[]') FROM (
        SELECT n.id,host(h.address) AS address,s.port,s.proto,n.ntype,n.data
        FROM notes n LEFT JOIN hosts h ON h.id=n.host_id LEFT JOIN services s ON s.id=n.service_id
        JOIN workspaces w ON w.id=n.workspace_id WHERE w.name='#{@workspace}' ORDER BY n.id
      ) row
    SQL
    rows = JSON.parse(sip_sql(query))
    return rows if rows.empty?

    serializer = MetasploitDataModels::Base64Serializer.new
    rows.map do |row|
      data = serializer.load(row.fetch('data'))
      expect(data).to be_a(Hash)
      row.merge('data' => JSON.parse(JSON.generate(data)))
    end
  end

  def credentials
    query = <<~SQL
      SELECT COALESCE(json_agg(row),'[]') FROM (
        SELECT c.id AS core_id,p.username,secret.data AS private_data,secret.type AS private_type,secret.jtr_format,
               l.id AS login_id,l.status,host(h.address) AS address,s.port,s.proto,s.name,
               o.module_full_name AS module_fullname
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_logins l ON l.core_id=c.id
        LEFT JOIN services s ON s.id=l.service_id LEFT JOIN hosts h ON h.id=s.host_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        WHERE w.name='#{@workspace}' ORDER BY c.id,l.id
      ) row
    SQL
    JSON.parse(sip_sql(query))
  end

  def inactive(service)
    native_action('inactive', service: service)
  end

  def ami_frames(text)
    text.split("\r\n\r\n").map do |block|
      block.split("\r\n").filter_map do |line|
        name, separator, value = line.partition(':')
        [name.downcase, value.delete_prefix(' ')] unless separator.empty?
      end.to_h
    end
  end

  def manager_wire_proof(username, password, source_host: listener_host)
    native_row = @native.fetch('ami').find { |entry| entry.fetch('operation').slice('username', 'password') == { 'username' => username, 'password' => password } }
    expect(native_row).not_to be_nil
    native = native_row.fetch('result')
    banner = Base64.decode64(native.fetch('banner_base64'))
    expected = ami_frames(native.fetch('reply')).first.slice('response', 'message')
    proof = nil
    wait_for_expect(30, 0.1) do
      capture = native_action('wire', service: 'exposed', label: @workspace)
      streams = capture.fetch('streams')
      matches = streams.filter_map do |request|
        next unless request.fetch('source') == source_host && request.fetch('target') == endpoint('exposed').fetch('host') && request.fetch('target_port') == 5038

        attempts = ami_frames(request.fetch('text')).count { |frame| frame.slice('action', 'username', 'secret') == { 'action' => 'Login', 'username' => username, 'secret' => password } }
        next if attempts.zero?

        response = streams.find { |row| row.values_at('source', 'source_port', 'target', 'target_port') == request.values_at('target', 'target_port', 'source', 'source_port') }
        expect(response).not_to be_nil
        expect(response.fetch('text')).to start_with(banner)
        expect(ami_frames(response.fetch('text')).count { |frame| frame.slice('response', 'message') == expected }).to eq(attempts)
        { attempts: attempts, request: request, response: response }
      end
      expect(matches.sum { |row| row.fetch(:attempts) }).to eq(2)
      proof = capture.merge('matched_exchanges' => matches)
    end
    File.write(File.join(target_runtime.fetch('artifacts'), "#{@workspace}-ami-wire-proof.json"), JSON.pretty_generate(proof))
    proof
  end

  def state(service)
    native_action('state', service: service)
  end

  def unregister(service, account = '1000')
    native_action('unregister', service: service, account: account)
  end

  def live_binding?(snapshot, account)
    !['(null)', '(Unspecified)'].include?(snapshot.fetch('peers').fetch(account).fetch('address'))
  end

  def state_content(snapshot)
    snapshot.except('observed')
  end

  def same_binding_state(before, after)
    # AMI reports remaining lease seconds; preserve its actual observation interval.
    # CLI Expire is a scheduler ID, not this countdown (chan_sip.c: sip_show_peer).
    expect(after.fetch('registry')).to eq(before.fetch('registry'))
    expect(after.fetch('channels')).to eq(before.fetch('channels'))
    before.fetch('peers').each do |account, peer|
      current = after.fetch('peers').fetch(account)
      expect(current.except('remaining_seconds')).to eq(peer.except('remaining_seconds'))
      if peer.fetch('remaining_seconds').negative?
        expect(current.fetch('remaining_seconds')).to eq(peer.fetch('remaining_seconds'))
      else
        before_interval = [before.fetch('observed').fetch('started') + peer.fetch('remaining_seconds'), before.fetch('observed').fetch('finished') + peer.fetch('remaining_seconds') + 1]
        after_interval = [after.fetch('observed').fetch('started') + current.fetch('remaining_seconds'), after.fetch('observed').fetch('finished') + current.fetch('remaining_seconds') + 1]
        expect([before_interval.first, after_interval.first].max).to be <= [before_interval.last, after_interval.last].min
      end
    end
  end

  def start_recorders
    @recorders = {}
    services = %w[exposed protected client]
    services << 'permissive' if target_runtime.fetch('module_endpoints').key?('permissive')
    services.each do |service|
      # Deliver short exchanges without waiting for a kernel packet-buffer block.
      command = %q{tcpdump --immediate-mode -U -nn -i eth0 -s 0 -w /tmp/module-target-sip.pcap 'udp port 5060 or tcp port 5060 or tcp port 5061 or tcp port 5038' >/tmp/module-target-sip.tcpdump.log 2>&1 & echo $!}
      process = Integer(target_exec(service, 'sh', '-c', command).strip)
      @recorders[service] = process
      wait_for_expect(30, 0.1) do
        ready = target_exec(service, 'sh', '-c', "test -s /tmp/module-target-sip.pcap && kill -0 #{process}; echo $?").strip
        expect(ready).to eq('0')
      end
    end
  end

  def stop_recorders
    @recorders&.each do |service, process|
      target_exec(service, 'kill', '-INT', process.to_s)
      wait_for_expect(30, 0.1) do
        status = target_exec(service, 'sh', '-c', "test ! -e /proc/#{process}/stat || test \"$(cut -d ' ' -f 3 /proc/#{process}/stat)\" = Z; echo $?").strip
        expect(status).to eq('0')
      end
      %w[pcap tcpdump.log].each do |suffix|
        bytes = target_exec(service, 'cat', "/tmp/module-target-sip.#{suffix}")
        File.binwrite(File.join(target_runtime.fetch('artifacts'), "#{service}.#{suffix}"), bytes)
      end
      text = target_exec(service, 'tcpdump', '-nn', '-A', '-r', '/tmp/module-target-sip.pcap')
      File.binwrite(File.join(target_runtime.fetch('artifacts'), "#{service}-packets.txt"), text)
      target_exec(service, 'rm', '--', '/tmp/module-target-sip.pcap', '/tmp/module-target-sip.tcpdump.log')
    end
  end
end

RSpec.shared_context 'real SIP targets' do
  include_context 'module target'
  include_context 'wait_for_expect'
  include ModuleTargetSip

  before(:all) do
    argv = ['python3', '-B', 'test/module_targets/sip/native_probe.py']
    stdout, stderr, status = Open3.capture3(*argv)
    File.binwrite(File.join(target_runtime.fetch('artifacts'), 'native-probe.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-probe-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    expect(stderr).to eq('')
    @native = JSON.parse(stdout)
    expect(@native.fetch('matrix').length).to eq(36)
    expect(sip_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    output = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(output).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-reporting-schema.txt'), sip_sql("SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position"))
    start_recorders
  end

  before do |example|
    @workspace = "sip_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(services).to eq([])
    expect(notes).to eq([])
    expect(credentials).to eq([])
  end

  after(:all) do
    stop_recorders
  end
end
