require 'acceptance_spec_helper'
require 'net/http'

RSpec.describe 'Genuine Log4j HTTP lookup detection', acceptance: true, order: :defined do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    command = ['python3', '-B', 'test/module_targets/log4shell_http/native_probe.py']
    output, error, status = Open3.capture3(*command)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-probe-status.json'), JSON.pretty_generate(argv: command, stderr: error, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), error
    @native = JSON.parse(output)
    @files = { 'empty' => '', 'single' => "# Ignored comment\n\nX-Log4j-Input\n", 'multiple' => "# Two real logging sinks\nUser-Agent\n\nX-Log4j-Input\n", 'query' => "# Query insertion\n\n?q=${jndi:uri}\n" }.to_h do |name, content|
      path = File.join(target_runtime.fetch('artifacts'), "#{name}.txt")
      File.write(path, content)
      [name, path]
    end
    expect(report_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  before do |example|
    @workspace = "log4shell_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(vulnerabilities).to eq([])
  end

  after(:all) do
    expect(http_json('/meta')).to eq(@native.fetch('metadata')) if @native
    %w[target framework reporting_db].each do |role|
      memory = target_exec(role, 'cat', '/sys/fs/cgroup/memory.events')
      expect(memory).to include("oom 0\n", "oom_kill 0\n")
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end

  {
    'single header GET' => ['/header/', 'single', 'empty', 'GET', false, 1],
    'multiple headers POST with leaked values' => ['/header/', 'multiple', 'empty', 'POST', true, 2],
    'both obfuscated path variants' => ['/path/', 'empty', 'empty', 'GET', false, 2],
    'query template GET' => ['/query/', 'empty', 'query', 'GET', true, 1],
    'query template POST' => ['/query/', 'empty', 'query', 'POST', false, 1],
    'unlogged HTTP input' => ['/unlogged/', 'single', 'query', 'POST', true, 0]
  }.each do |label, (path, headers, uris, method, leaks, successful_points)|
    it "handles #{label} twice using the actual configured logger" do
      2.times do
        before = http_json('/events').fetch('sequence')
        options = {
          'TARGETURI' => path, 'HTTP_METHOD' => method, 'HEADERS_FILE' => @files.fetch(headers), 'URIS_FILE' => @files.fetch(uris),
          'LEAK_PARAMS' => leaks ? '${env:MSF_MODULE_TARGET_LEAK}^${sys:msf.module.target.value}' : '',
          'SRVHOST' => listener_host, 'SRVPORT' => 1389, 'LDAP_TIMEOUT' => 1, 'THREADS' => 1
        }
        output = run_target_module('auxiliary/scanner/http/log4shell_scanner', 'target', options, command_timeout: 45)
        vulnerable = ENV.fetch('LOG4SHELL_VERSION') == '2.14.1' && ENV.fetch('LOG4SHELL_MODE') == 'log4j'
        expected = vulnerable ? successful_points : 0
        expect(output.scan('Log4Shell found via').length).to eq(expected), output
        events = http_json("/events?after=#{before}").fetch('events')
        expect(events.select { |row| %w[http_error collector_error native_ldap].include?(row.fetch('kind')) }).to eq([])
        requests = events.select { |row| row.fetch('kind') == 'http_request' }
        # The independent baseline probe is GET; all subsequent requests use HTTP_METHOD.
        expect(requests.map { |row| row.fetch('method') }).to eq(['GET'] + Array.new(requests.length - 1, method))
        header_points = { 'empty' => 0, 'single' => 1, 'multiple' => 2 }.fetch(headers)
        expect(requests.length).to eq(3 + header_points + (uris == 'query' ? 1 : 0))
        rows = vulnerabilities
        if expected.positive?
          expect(rows.length).to eq(1)
          row = rows.first
          expect(row.slice('address', 'port', 'name')).to eq('address' => target_runtime.fetch('module_endpoints').fetch('target').fetch('host'), 'port' => 8080, 'name' => 'Log4Shell HTTP Scanner')
          expect(row.fetch('info')).to include('Module auxiliary/scanner/http/log4shell_scanner detected Log4Shell vulnerability via', "(os: #{@native.fetch('metadata').fetch('java_os_lookup')})", "(java: #{@native.fetch('metadata').fetch('java_vendor')}_#{@native.fetch('metadata').fetch('java_version')})")
          expect(row.fetch('refs')).to include('CVE-2021-44228', 'CVE-2021-45046')
          if leaks
            expect(output).to include('${env:MSF_MODULE_TARGET_LEAK}=module-target-environment', '${sys:msf.module.target.value}=module-target-property')
            expect(row.fetch('info')).to include('${env:MSF_MODULE_TARGET_LEAK}=module-target-environment', '${sys:msf.module.target.value}=module-target-property')
          end
        else
          expect(rows).to eq([])
        end
        expect(console_command('jobs -l')).to include('No active jobs')
        expect(console_command('sessions -l')).to include('No active sessions')
        wait_for_expect(5, 0.1) do
          sockets = target_exec('framework', 'ruby', '-rjson', '-e', 'puts JSON.generate(%w[/proc/net/tcp /proc/net/tcp6].flat_map { |path| File.readlines(path).drop(1).map(&:split) }.select { |row| row[3] == "0A" && row[1].split(":").last.to_i(16) == 1389 })')
          expect(JSON.parse(sockets)).to eq([])
        end
      end
    end
  end

  def http_json(path)
    endpoint = target_endpoint('target')
    response = Net::HTTP.get_response(URI("http://#{endpoint.fetch('host')}:#{endpoint.fetch('port')}#{path}"))
    expect(response.code).to eq('200')
    JSON.parse(response.body)
  end

  def report_sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def vulnerabilities
    query = <<~SQL
      SELECT COALESCE(json_agg(record), '[]'::json) FROM (
        SELECT host(host.address) AS address, service.port, vuln.name, vuln.info,
          ARRAY(SELECT reference.name FROM refs reference JOIN vulns_refs vr ON vr.ref_id=reference.id WHERE vr.vuln_id=vuln.id ORDER BY reference.name) refs
        FROM vulns vuln JOIN hosts host ON host.id=vuln.host_id
        JOIN workspaces workspace ON workspace.id=host.workspace_id
        LEFT JOIN services service ON service.id=vuln.service_id
        WHERE workspace.name='#{@workspace}' ORDER BY vuln.id
      ) record;
    SQL
    rows = JSON.parse(report_sql(query))
    File.open(File.join(target_runtime.fetch('artifacts'), 'vulnerability-rows.jsonl'), 'a') { |log| log.puts(JSON.generate(workspace: @workspace, rows: rows)) }
    rows
  end
end
