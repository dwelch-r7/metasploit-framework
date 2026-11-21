# frozen_string_literal: true

require 'net/http'
require 'shellwords'
require_relative '../rsync_creds/native'

# Native SQL, graph rendering and real exec controls precede owning verdicts.
module OpenDcimTarget
  include RsyncCredentialTarget

  OWNER = 'exploit/linux/http/opendcim_install_sqli_rce'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'opendcim-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    %w[target database]
  end

  def od_native(action, *arguments)
    argv = ['python3', '-B', 'test/module_targets/opendcim/native_probe.py', action, *arguments]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { action: action, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def od_registry
    value = od_native('snapshot')
    expect(value).to eq('config' => @rc.fetch(:readiness).fetch('baseline'), 'tables' => @rc.fetch(:readiness).fetch('tables'), 'vendor' => @rc.fetch(:readiness).fetch('vendor'))
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
  end

  def od_ready
    @rc[:readiness] = od_native('before')
    expect(@rc.fetch(:readiness)).to include('passed' => true, 'version' => '24.01', 'uid' => 33)
    @rc[:observer] = rc_json("begin;load 'test/module_targets/opendcim/observe.rb';OpenDcimObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:calibrated] = true
    rc_resources('before')
    od_registry
  end

  def od_call(label, options = {}, action: 'check', reuse: false)
    offset = rc_json('framework.instance_variable_get(:@opendcim_events).length')
    call = { label: label, options: options, action: action }
    @rc[:calls] << call
    settings = { 'SSL' => false }.merge(options)
    if options.key?('CMD')
      unless reuse
        console_command('back')
        expect(console_command('use ' + OWNER)).not_to match(/Failed to load|Unknown command|No results/)
      end
      %w[TARGET PAYLOAD].each do |name|
        expect(console_command("set #{name} #{options.fetch(name)}")).not_to match(/Failed|Invalid|not found/)
      end
      # Reuse the established Laravel command pattern so the console's line
      # parser cannot split physical CR/LF bytes before the owner sees them.
      call[:datastore_assignment] = rc_json("begin;active_module.datastore['CMD']=#{options.fetch('CMD').inspect};true;end")
      settings = settings.except('CMD', 'TARGET', 'PAYLOAD')
      reuse = true
    end
    run_target_module(OWNER, 'target', settings, action: action, reuse_module: reuse, allow_errors: true, command_timeout: 60) do |output|
      call[:output] = output
      call[:events] = rc_json("framework.instance_variable_get(:@opendcim_events).drop(#{offset})")
      call[:selection] = rc_json('active_module.object_id')
      rc_save
    end
    call
  end

  def od_check
    call = od_call('check')
    expect(call.fetch(:events).filter_map { |row| row['check'] }).to eq([{ 'code' => 'vulnerable', 'reason' => 'Successfully tested SQL injection (3/3 delay checks passed).' }])
    expect(call.fetch(:events).select { |row| row['owner_exploit_body'] }).to eq([])
    od_registry
  end

  def od_closed_port
    server = TCPServer.new('127.0.0.1', 0)
    port = server.local_address.ip_port
    server.close
    expect { TCPSocket.new('127.0.0.1', port) }.to raise_error(Errno::ECONNREFUSED)
    call = od_call('closed-port', { 'RPORT' => port, 'HttpClientTimeout' => 2 })
    expect(call.fetch(:events).filter_map { |row| row['check'] }).to eq([{ 'code' => 'unknown', 'reason' => 'Could not connect to the target.' }])
    expect(call.fetch(:events).filter_map { |row| row['response'] }).to eq([])
    od_registry
  ensure
    server&.close unless server&.closed?
  end

  def od_prefix_ready
    endpoint = target_endpoint('target')
    client = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    client.open_timeout = 5
    client.read_timeout = 10
    response = client.get('/dcim/report_network_map.php?format=0&containerid=1')
    document = Nokogiri::XML(response.body) { |config| config.strict.nonet }
    @rc[:prefix_native] = { status: response.code, sha256: Digest::SHA256.hexdigest(response.body), root: document.root.name }
    rc_save
    expect(response.code).to eq('200')
    expect(document.root.name).to eq('svg')
    od_registry
  end

  def od_commands(label, marker, prefix: false)
    od_prefix_ready if prefix
    2.times do |iteration|
      path = "/tmp/module-target-opendcim-owner-#{Process.pid}-#{label}-#{iteration}"
      expected = marker + iteration.to_s + "\n"
      expect(od_native('file', path)).to eq('exists' => false)
      command = 'printf %s ' + Shellwords.escape(expected) + ' > ' + path
      control = od_native('command-control', Base64.strict_encode64(command.b), path, Base64.strict_encode64(expected.b), prefix ? '/dcim' : '')
      expect(control).to include('passed' => true, 'command_base64' => Base64.strict_encode64(command.b))
      expect(od_native('file', path)).to eq('exists' => false)
      call = od_call(label + '-' + iteration.to_s,
                     { 'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command, 'TARGETURI' => prefix ? '/dcim/' : '/', 'AutoCheck' => false, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 },
                     action: 'run -z', reuse: iteration.positive?)
      expect(call.fetch(:selection)).to eq(@rc[:selection]) if iteration.positive?
      @rc[:selection] = call.fetch(:selection)
      events = call.fetch(:events)
      expect(events.count { |row| row['owner_exploit_body'] }).to eq(1)
      expect(events.filter_map { |row| row['command_base64'] }).to eq([Base64.strict_encode64((command + ' #').b)])
      expect(call.fetch(:output)).not_to include('Exploit failed', 'Exploit aborted')
      proof = rc_poll(5) do
        value = od_native('file', path)
        value if value.fetch('exists')
      end
      expect(proof).to eq('exists' => true, 'uid' => 33, 'base64' => Base64.strict_encode64(expected.b))
      backup = events.select { |row| row['event'] == 'call' && row['method'] == 'backup_config' }.filter_map { |row| row['backup_table'] }.uniq
      expect(backup.length).to eq(1)
      expect(backup.first).to match(/\A[a-z]{8}\z/)
      od_registry
    ensure
      od_native('remove', path) if path
    end
  end
end
