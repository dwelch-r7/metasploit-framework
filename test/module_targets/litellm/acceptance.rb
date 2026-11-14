# frozen_string_literal: true

require 'base64'
require_relative '../../../tools/dev/module_target_endpoint'

# Compare real owner checks, API controls and PostgreSQL reports without stubs.
module LiteLLMAcceptance
  OWNER = 'auxiliary/scanner/http/litellm_proxy_sqli'

  def record(name, data)
    File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |stream| stream.puts(JSON.generate(data)) }
  end

  def native(action, *arguments)
    argv = ['python3', '-B', 'test/module_targets/litellm/native_probe.py', action, *arguments.map(&:to_s)]
    output, error, status = Open3.capture3(*argv)
    record('litellm-native-processes.jsonl', argv: argv, actual_exit: status.exitstatus, stdout: output, stderr: error)
    expect(status.exitstatus).to eq(0), error
    JSON.parse(output)
  end

  def inspected(kind, identifier)
    argv = ['docker', kind, 'inspect', identifier]
    output, error, status = Open3.capture3(*argv)
    record('litellm-endpoint-inspections.jsonl', argv: argv, actual_exit: status.exitstatus, stdout: output, stderr: error)
    expect(status.exitstatus).to eq(0), error
    JSON.parse(output).fetch(0)
  end

  def select_endpoint
    compose = target_runtime.fetch('compose')
    project = compose.fetch(compose.index('--project-name') + 1)
    selector = ModuleTargetEndpoint.new(project: project, network: 'default', container: lambda { |service|
      output, error, status = Open3.capture3(*compose, 'ps', '-q', service)
      expect(status.exitstatus).to eq(0), error
      inspected('container', output.strip)
    }, network_inspection: ->(identifier) { inspected('network', identifier) })
    target_runtime.fetch('module_endpoints')['target'] = { 'host' => selector.address('target'), 'port' => 4000 }
  end

  def owner_rows
    path = File.join(target_runtime.fetch('artifacts'), 'litellm-owner-calls.jsonl')
    File.file?(path) ? File.readlines(path).map { |line| JSON.parse(line) } : []
  end

  def invoke(action: 'check', options: {}, reuse: false, expected: nil, statuses: [401])
    before = native('state')
    offset = owner_rows.length
    defaults = { 'SqliDelay' => 1.0, 'HttpClientTimeout' => 5, 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true }
    if reuse
      endpoint = target_runtime.fetch('module_endpoints').fetch('target')
      values = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'MODEL' => 'gpt-3.5-turbo', 'TARGETURI' => '/v1/chat/completions' }.merge(defaults).merge(options)
      output = console_command("#{action} #{format_datastore_options(values)}", timeout: 90)
    else
      output = run_target_module(OWNER, 'target', defaults.merge(options), action: action, allow_errors: true, command_timeout: 90)
    end
    rows = owner_rows.drop(offset)
    record('litellm-invocations.jsonl', action: action, options: options, reuse: reuse, output: output, rows: rows)
    expect(output).not_to match(/Unknown datastore option|Invalid option|undefined method|Encoding::/)
    returns = rows.select { |row| row.fetch('kind') == 'check-return' }
    expect(returns.length).to eq(1), output
    expect(returns.fetch(0).fetch('code')).to eq(expected) if expected
    expect(returns.fetch(0).fetch('reason')).not_to be_empty
    posts = rows.select { |row| row.fetch('kind') == 'http' && row.fetch('method') == 'POST' }
    expect(posts.length).to eq(2) if statuses == [401]
    expect(posts.map { |row| row.fetch('status') }.uniq - statuses).to eq([])
    posts.each do |row|
      body = JSON.parse(Base64.strict_decode64(row.fetch('data_base64')))
      expect(body.fetch('model')).to eq(options.fetch('MODEL', 'gpt-3.5-turbo'))
    end
    expect(native('state').fetch('business_sha256')).to eq(before.fetch('business_sha256'))
    idle
    returns.fetch(0)
  end

  def reports
    raise ArgumentError, 'Invalid controlled workspace' unless @workspace.match?(/\Alitellm_[0-9_]+\z/)

    query = <<~SQL
      SELECT coalesce(json_agg(row_to_json(rows) ORDER BY rows.id),'[]') FROM (
        SELECT v.id,v.name,v.info,host(h.address::inet) AS host,s.port,s.proto,
          ARRAY(SELECT r.name FROM refs r JOIN vulns_refs vr ON vr.ref_id=r.id WHERE vr.vuln_id=v.id ORDER BY r.name) AS refs
        FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id
        LEFT JOIN services s ON s.id=v.service_id WHERE w.name='#{@workspace}'
      ) rows
    SQL
    output = target_exec('reporting_db', 'psql', '-X', '-U', 'module_framework', '-d', 'module_targets', '-Atc', query)
    rows = JSON.parse(output)
    record('litellm-report-snapshots.jsonl', workspace: @workspace, rows: rows)
    rows
  end

  def idle
    output = console_command(%q{irb -e 'puts "LITELLM_IDLE="+{jobs:framework.jobs.keys,sessions:framework.sessions.keys}.to_json'})
    expect(output).to include('LITELLM_IDLE={"jobs":[],"sessions":[]}')
  end
end
