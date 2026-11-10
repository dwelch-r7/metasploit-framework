require 'acceptance_spec_helper'
require 'shellwords'
require 'rex/parser/arguments'
require 'rex/proto/http/packet'
require 'rex/proto/http/packet/header'
require 'rex/proto/http/request'
require 'timeout'

profile = ENV.fetch('DRUID_TARGET_PROFILE', 'js')
raise ArgumentError, "Unknown Druid profile: #{profile}" unless %w[js jndi].include?(profile)

RSpec.describe 'Native Apache Druid sampler targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    @profile = profile
    argv = ['python3', '-B', 'test/module_targets/druid/native_probe.py']
    output, error, status = Open3.capture3(*argv)
    File.write(artifact('native-probe-status.json'), JSON.pretty_generate(argv: argv, stderr: error, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), error
    @native = JSON.parse(output)
    expect(@native.fetch('counts')).to eq('commands' => profile == 'js' ? 37 : 46, 'requests' => profile == 'js' ? 25 : 21)
    endpoints = JSON.parse(File.read(artifact('native-endpoints.json'))).fetch('module_endpoints')
    # Framework stays internal; the real dual-bridge frontend intentionally
    # stays outside the canonical runner's one-network published endpoint map.
    target_runtime.fetch('module_endpoints').merge!(endpoints)
    expect(@native.fetch('targets').transform_values { |value| value.fetch('version') }).to eq('vulnerable' => '0.20.0', 'fixed' => profile == 'jndi' ? '26.0.0' : '0.20.1')
    installed = console_command("irb -e 'load \"test/module_targets/druid/input_audit.rb\"; puts \"DRUID_CATALOG=\" + DruidTargetInputs.install(framework, \"#{listener_host}\").to_json'")
    catalog = JSON.parse(installed[/DRUID_CATALOG=(\{.*\})/, 1])
    @command_target = catalog.fetch(owner).fetch('command_target')
    expect(catalog.fetch(owner).fetch('generic_in_compatible_list')).to be(true)
    expect(catalog.fetch(owner).fetch('callback_host')).to eq(listener_host)
  end

  before do |example|
    @wire_expected = example.metadata.fetch(:capture_expected, false)
    @case_id = example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command('sessions -l')).to include('No active sessions')
    expect(console_command('jobs -l')).to include('No active jobs')
    prove_ports_removed
    @before_files = target_files
    @intended_commands = []
    start_wire_capture
  end

  after do
    stop_wire_capture
    next unless @before_files

    console_command('jobs -K') unless @console_broken
    console_command('sessions -K') unless @console_broken
    restore_files
    prove_ports_removed unless @console_broken
    @before_files = nil
  end

  {
    'direct affected endpoint' => ['vulnerable', {}, true],
    'genuine proxy prefix' => ['gateway', { 'TARGETURI' => '/prefix/' }, true],
    'valid HTTP Basic frontend' => ['gateway', { 'TARGETURI' => '/auth/', 'HttpUsername' => 'admin', 'HttpPassword' => 'module-target-druid-password' }, true],
    'fixed release' => ['fixed', {}, false],
    'missing HTTP credentials' => ['gateway', { 'TARGETURI' => '/auth/' }, false],
    'wrong HTTP password' => ['gateway', { 'TARGETURI' => '/auth/', 'HttpUsername' => 'admin', 'HttpPassword' => 'wrong' }, false],
    'authenticated denied frontend role' => ['gateway', { 'TARGETURI' => '/denied/', 'HttpUsername' => 'viewer', 'HttpPassword' => 'module-target-viewer-password' }, false],
    'missing application path' => ['vulnerable', { 'TARGETURI' => '/module-target-no-druid/' }, false],
    'unrelated genuine Apache HTTP' => ['unrelated', {}, false]
  }.each do |label, (service, options, positive)|
    it "checks #{label} twice without a false positive", capture_expected: positive do
      2.times do
        output = invoke(service, options, action: 'check', allow_errors: true)
        if positive
          expect(output).to include('The target is vulnerable')
          if @profile == 'jndi'
            expect(output).to include('Successfully verified JNDI injection via an LDAP search callback')
            expect(output).not_to include('Successfully verified code execution')
          end
        else
          expect(output).not_to include('The target is vulnerable', 'The target appears to be vulnerable')
        end
        expect(target_files).to eq(@before_files)
        prove_ports_removed
      end
    end
  end

  {
    'plain command' => ['vulnerable', 'plain-command', {}],
    'quoted characters' => ['vulnerable', %(Double " and single ' : spaces), {}],
    'literal backslashes' => ['vulnerable', 'backslash\\t\\path', {}],
    'delimiter text' => ['vulnerable', 'before`@~after', {}],
    'authenticated prefixed command' => ['gateway', 'authenticated-command', { 'TARGETURI' => '/auth/', 'HttpUsername' => 'admin', 'HttpPassword' => 'module-target-druid-password' }]
  }.each do |label, (service, bytes, options)|
    it "executes #{label} twice with exact bytes and independent cleanup", capture_expected: true do
      2.times do |iteration|
        path = "/tmp/module-target-druid-command-#{@case_id}-#{iteration}"
        expect(target_exec('vulnerable', 'test', '!', '-e', path)).to eq('')
        command = label == 'plain command' ? "printf${IFS}%s${IFS}#{bytes}>#{path}" : "printf '%s' #{Shellwords.escape(bytes)} > #{path}"
        expect(command).not_to include("\n")
        native_command_proof(command, path, bytes)
        output = invoke(service, generic_options(command).merge(options), allow_errors: true)
        prove_executing_input(command)
        begin
          wait_for_expect(20, 0.1) { expect(target_exec('vulnerable', 'sh', '-c', 'if test -f "$1"; then cat "$1"; fi', 'sh', path)).to eq(bytes) }
          expect(target_exec('vulnerable', 'stat', '-c', '%u:%g', path).strip).to eq('1000:1000')
          expect(output).not_to include('[-]')
        ensure
          capture_created_files
        end
        restore_files
      end
    end
  end

  if profile == 'js'
    it 'executes a quiet command twice even when its stdout is empty', capture_expected: true do
      2.times do |iteration|
        path = "/tmp/module-target-druid-empty-#{@case_id}-#{iteration}"
        command = ": > #{path}"
        native_command_proof(command, path, '')
        output = invoke('vulnerable', generic_options(command), allow_errors: true)
        prove_executing_input(command)
        wait_for_expect(20, 0.1) { expect(target_exec('vulnerable', 'sh', '-c', 'if test -f "$1"; then printf present; else printf absent; fi', 'sh', path)).to eq('present') }
        expect(target_exec('vulnerable', 'stat', '-c', '%u:%g:%s', path).strip).to eq('1000:1000:0')
        expect(output).not_to include('[-]')
        capture_created_files
        restore_files
      end
    end
  end

  def artifact(name)
    File.join(target_runtime.fetch('artifacts'), name)
  end

  def owner
    @profile == 'jndi' ? 'exploit/multi/http/apache_druid_cve_2023_25194' : 'exploit/linux/http/apache_druid_js_rce'
  end

  def native_command_proof(command, path, bytes)
    expect(target_exec('vulnerable', '/bin/sh', '-c', command)).to eq('')
    expect(target_exec('vulnerable', 'cat', path)).to eq(bytes)
    expect(target_exec('vulnerable', 'stat', '-c', '%u:%g', path).strip).to eq('1000:1000')
    target_exec('vulnerable', 'rm', '--', path)
    expect(target_exec('vulnerable', 'test', '!', '-e', path)).to eq('')
    File.open(artifact('intended-commands.jsonl'), 'a') { |log| log.puts(JSON.generate(command_base64: Base64.strict_encode64(command), proof_base64: Base64.strict_encode64(bytes), native_producer: '/bin/sh -c', exact_bytes: true, marker_absent_before_framework: true)) }
  end

  def prove_executing_input(command)
    rows = File.readlines(artifact('executing-inputs.jsonl')).map { |line| JSON.parse(line) }
    encoded = Base64.strict_encode64(command)
    matching = rows.select { |row| row['kind'] == 'exploit' && row['fullname'] == owner && row['command_base64'] == encoded }
    expect(matching).not_to be_empty
    expect(matching.last.fetch('target_index')).to eq(@command_target)
    expect(matching.last.fetch('payload')).to eq('cmd/unix/generic')
    expect(matching.last.fetch('callback_host')).to eq(listener_host) if @profile == 'jndi'
    if @profile == 'js'
      expect(rows).to include(hash_including('kind' => 'execute_command', 'fullname' => owner, 'argument_base64' => encoded))
    end
    @intended_commands << command
  end

  def invoke(service, options, action: 'run -z', allow_errors: false)
    defaults = { 'TARGETURI' => '/', 'SSL' => false, 'HttpClientTimeout' => 8, 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true }
    defaults.merge!('SRVHOST' => listener_host, 'SRVPORT' => 3389, 'WfsDelay' => 2) if @profile == 'jndi'
    output = run_target_module(owner, service, defaults.merge(options), action: action, allow_errors: allow_errors, command_timeout: 55)
    expect(output).not_to include('Unknown datastore option', 'Invalid option', 'Parse error:', 'not a compatible payload')
    output
  end

  def generic_options(command)
    { 'TARGET' => @command_target, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command, 'WfsDelay' => 2, 'DisablePayloadHandler' => false }
  end

  def target_files
    target_exec('vulnerable', 'find', '/tmp', '-mindepth', '1', '-maxdepth', '1', '-print').lines.map(&:strip).sort
  end

  def capture_created_files
    (target_files - @before_files).each do |path|
      type = target_exec('vulnerable', 'stat', '-c', '%F', path).strip
      name = "target-#{@case_id}-#{File.basename(path)}"
      if type == 'regular file'
        output, status = Open3.capture2e(*target_runtime.fetch('compose'), 'cp', "vulnerable:#{path}", artifact(name))
        File.open(artifact('native-copies.jsonl'), 'a') { |log| log.puts(JSON.generate(source: path, destination: name, exitstatus: status.exitstatus, output: output)) }
        expect(status.success?).to be(true), output
      else
        File.open(artifact('native-other-artifacts.jsonl'), 'a') { |log| log.puts(JSON.generate(path: path, type: type)) }
      end
    end
  end

  def restore_files
    created = target_files - @before_files
    created.each { |path| target_exec('vulnerable', 'rm', '-rf', '--', path) }
    expect(target_files).to eq(@before_files)
    File.open(artifact('restorations.jsonl'), 'a') { |log| log.puts(JSON.generate(case: @case_id, removed: created, exact_inventory_restored: true)) }
  end

  def start_wire_capture
    @wire_lines = []
    @wire_argv = target_runtime.fetch('compose') + ['exec', '-T', 'wire', 'sh', '-c', "printf 'TCPDUMP_PID=%s\\n' \"$$\"; exec tcpdump -i eth0 --immediate-mode -U -s 0 -Z root -w /artifacts/case-#{@case_id}.pcap 'tcp port 8081 or tcp port 3389'"]
    @wire_stdin, @wire_output, @wire_waiter = Open3.popen2e(*@wire_argv)
    Timeout.timeout(8) do
      loop do
        line = @wire_output.gets
        raise 'Packet capture exited before readiness' unless line

        @wire_lines << line
        @wire_pid ||= line[/TCPDUMP_PID=(\d+)/, 1]
        break if line.include?('listening on eth0')
      end
    end
    expect(@wire_pid).not_to be_nil, @wire_lines.join
  end

  def stop_wire_capture
    return unless @wire_waiter

    if @wire_waiter.alive? && @wire_pid
      output, status = Open3.capture2e(*target_runtime.fetch('compose'), 'exec', '-T', 'wire', 'kill', '-INT', @wire_pid)
      expect(status.success?).to be(true), output
    end
    expect(@wire_waiter.join(8)).not_to be_nil
    @wire_stdin.close
    @wire_lines << @wire_output.read
    @wire_output.close
    File.write(artifact("wire-#{@case_id}.json"), JSON.pretty_generate(argv: @wire_argv, pid: @wire_pid, exitstatus: @wire_waiter.value.exitstatus, output: @wire_lines.join))
    expect(@wire_waiter.value.success?).to be(true), @wire_lines.join
    expect(File.size(artifact("case-#{@case_id}.pcap"))).to be >= 24
    expect(File.size(artifact("case-#{@case_id}.pcap"))).to be > 24 if @wire_expected
    parser = "import sys,json; sys.path.insert(0,'test/module_targets/capture_core'); from native_client import tcp_streams; print(json.dumps(tcp_streams(sys.argv[1]),indent=2))"
    decoded, status = Open3.capture2e('python3', '-B', '-c', parser, artifact("case-#{@case_id}.pcap"))
    expect(status.success?).to be(true), decoded
    File.write(artifact("case-#{@case_id}.wire.json"), decoded)
    streams = JSON.parse(decoded)
    expect(streams).not_to be_empty if @wire_expected
    prove_wire_commands(streams)
  ensure
    @wire_waiter = @wire_pid = nil
  end

  def prove_wire_commands(streams)
    return if @intended_commands.empty?

    functions = []
    if @profile == 'js'
      streams.select { |stream| stream.fetch('target_port') == 8081 }.each do |stream|
        remaining = Base64.strict_decode64(stream.fetch('base64'))
        until remaining.empty?
          request = Rex::Proto::Http::Request.new
          expect(request.parse(remaining)).to eq(Rex::Proto::Http::Packet::ParseCode::Completed)
          document = JSON.parse(request.body)
          functions << document.dig('spec', 'dataSchema', 'parser', 'parseSpec', 'function')
          expect(request.bufq.bytesize).to be < remaining.bytesize
          remaining = request.bufq
        end
      end
    end
    @intended_commands.each do |command|
      matched = if @profile == 'js'
                  functions.compact.any? { |function| function.include?(command) || function.include?(command.to_json) }
                else
                  streams.any? { |stream| Base64.strict_decode64(stream.fetch('base64')).include?(command.b) }
                end
      File.open(artifact('wire-command-audit.jsonl'), 'a') { |log| log.puts(JSON.generate(command_base64: Base64.strict_encode64(command), actual_packet_bytes_matched: matched)) }
      expect(matched).to be(true), "Intended command missing from actual #{@profile} wire data"
    end
  end

  def prove_ports_removed
    script = "require 'socket'; require 'json'; print JSON.generate([3389,4445,8081].to_h{|port| begin; socket=TCPSocket.new('#{listener_host}',port); socket.close; [port,'LISTENING']; rescue Errno::ECONNREFUSED; [port,'CLOSED']; end})"
    argv = target_runtime.fetch('compose') + ['exec', '-T', 'framework', 'ruby', '-e', script]
    output, status = Open3.capture2e(*argv)
    File.open(artifact('listener-audit.jsonl'), 'a') { |log| log.puts(JSON.generate(argv: argv, exitstatus: status.exitstatus, output: output)) }
    expect(status.success?).to be(true), output
    expect(JSON.parse(output)).to eq('3389' => 'CLOSED', '4445' => 'CLOSED', '8081' => 'CLOSED')
  end
end

# Stop after console transport loss so later case labels cannot be misclassified.
module DruidConsoleTransportGuard
  def format_datastore_options(datastore)
    return super unless datastore.key?('CMD')

    command = datastore.fetch('CMD')
    rendered = "CMD=#{Shellwords.escape(command)}"
    expect(Rex::Parser::Arguments.from_s(rendered)).to eq(["CMD=#{command}"])
    "#{super(datastore.except('CMD'))} #{rendered}"
  end

  def console_command(command, timeout: 40)
    raise Acceptance::ChildProcessTimeoutError, 'Console transport failed; Druid diagnostic stopped' if @console_broken

    super
  rescue Acceptance::ChildProcessTimeoutError, Acceptance::ChildProcessRecvError, EOFError, Errno::EPIPE
    @console_broken = true
    RSpec.world.wants_to_quit = true
    raise
  end
end

RSpec.world.example_groups.find { |group| group.description == 'Native Apache Druid sampler targets' }.prepend(DruidConsoleTransportGuard)
