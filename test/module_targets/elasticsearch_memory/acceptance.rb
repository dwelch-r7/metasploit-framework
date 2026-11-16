# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require 'socket'
require_relative 'profiles'

RSpec.shared_context 'native Elasticsearch memory target' do
  include_context 'module target'

  before(:all) do
    @esm_profile = ElasticsearchMemoryProfiles.fetch
    @esm_native = { requests: [], commands: [], calls: [], reports: [], controls: [], loots: [] }
    begin
      esm_counters('before')
      esm_native_setup
      esm_native_controls('before')
      endpoint = target_endpoint('db')
      expect(esm_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets')
      output = console_command('irb -e \'puts "ESM_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/scanner/http/elasticsearch_memory_disclosure.rb").hexdigest}.to_json\'')
      @esm_native[:provenance] = JSON.parse(output.match(/^ESM_PROVENANCE=(.+)$/)[1])
      expect(@esm_native[:provenance].fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@esm_native[:provenance].fetch('owner_sha256')).to eq(Digest::SHA256.file("modules/#{ElasticsearchMemoryProfiles::OWNER}.rb").hexdigest)
      @esm_native[:preflight] = 'passed'
    ensure
      esm_save
    end
  end

  before do
    @esm_workspace = "esm_#{Process.pid}_#{@esm_native.fetch(:calls).length}"
    expect(console_command("workspace -a #{@esm_workspace}")).to include(@esm_workspace)
    expect(esm_reports.values).to all(eq([]))
  end

  after(:all) do
    esm_native_controls('after') if @esm_native&.key?(:preflight)
    expect(console_command('irb -e \'puts "ESM_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('ESM_STATE={"sessions":[],"jobs":[]}') if @esm_native&.key?(:provenance)
  ensure
    esm_counters('after') if @esm_profile
    esm_save
  end

  def esm_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-elasticsearch-memory.json'), JSON.pretty_generate(@esm_native)) if @esm_native
  end

  def esm_command(role, *arguments)
    argv = target_runtime.fetch('compose') + ['exec', '-T', role, *arguments]
    output, error, status = Open3.capture3(*argv)
    @esm_native.fetch(:commands) << { argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exitstatus: status.exitstatus }
    esm_save
    raise "Native Elasticsearch command failed: #{role}: #{error}" unless status.success?

    output
  end

  def esm_request(label, method, path, body = nil, username: 'elastic', password: 'module-target-password')
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 15
    http.max_retries = 0
    request = Net::HTTP.const_get(method.capitalize).new(path)
    request['Content-Type'] = 'application/json'
    request.basic_auth(username, password) if @esm_profile.fetch('security') && username
    request.body = body.is_a?(Hash) ? JSON.generate(body) : body
    response = http.request(request)
    @esm_native.fetch(:requests) << { label: label, method: method, path: path, request_body_base64: request.body && Base64.strict_encode64(request.body.b), code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    esm_save
    response
  ensure
    http&.finish if http&.started?
  end

  def esm_native_setup
    return if @esm_profile.fetch('mode') == 'unrelated'

    expect(esm_request('create-index', 'put', '/module_target_memory', { 'settings' => { 'number_of_shards' => 1, 'number_of_replicas' => 0 } }).code).to eq('200')
    @esm_document = { 'marker' => 'Module native café document', 'kind' => 'ordinary-control' }
    expect(esm_request('ordinary-put', 'put', '/module_target_memory/_doc/ordinary?refresh=true', @esm_document).code).to eq('201')
    return unless @esm_profile.fetch('security')

    %w[writer reader limited].each do |kind|
      privileges = kind == 'writer' ? %w[read write] : ['read']
      role = { 'cluster' => kind == 'limited' ? [] : ['monitor'], 'indices' => [{ 'names' => ['module_target_memory'], 'privileges' => privileges }] }
      expect(esm_request("create-#{kind}-role", 'put', "/_security/role/module_#{kind}", role).code).to eq('200')
      expect(esm_request("create-#{kind}-user", 'put', "/_security/user/module_#{kind}", { 'password' => 'module-target-password', 'roles' => ["module_#{kind}"] }).code).to eq('200')
    end
  end

  def esm_native_controls(phase)
    root = esm_request(phase + '-root', 'get', '/')
    expect(root.code).to eq('200')
    if @esm_profile.fetch('mode') == 'unrelated'
      expect(root.body).to include('module-target-http-marker')
      unrelated_bulk = esm_request(phase + '-unrelated-bulk', 'post', '/_bulk', "@\n")
      expect(%w[404 405 501]).to include(unrelated_bulk.code)
      @esm_unrelated_bulk_status ||= unrelated_bulk.code.to_i
      expect(unrelated_bulk.code.to_i).to eq(@esm_unrelated_bulk_status)
    else
      process = esm_command('app', 'sh', '-c', 'for status in /proc/[0-9]*/status; do read -r label task < "$status"; if [ "$task" = java ]; then cat "$status"; fi; done; exit 0')
      uids = process.lines.select { |line| line.start_with?('Uid:') }.map { |line| line.split.drop(1) }
      expect(uids).to eq([%w[1000 1000 1000 1000]])
      document = JSON.parse(root.body)
      expect(document.dig('version', 'number')).to eq(@esm_profile.fetch('version'))
      expect(document.fetch('cluster_name')).to eq('module-target-memory')
      jvm = JSON.parse(esm_request(phase + '-jvm', 'get', '/_nodes/_local/jvm').body).fetch('nodes').values
      expect(jvm.length).to eq(1)
      expect(jvm.first.dig('jvm', 'mem', 'heap_max_in_bytes')).to eq(@esm_profile.fetch('heap_mb') * 1024 * 1024)
      ordinary = esm_request(phase + '-ordinary', 'get', '/module_target_memory/_doc/ordinary')
      expect(ordinary.code).to eq('200')
      expect(JSON.parse(ordinary.body).fetch('_source')).to eq(@esm_document)
      malformed = esm_request(phase + '-malformed', 'post', '/_bulk', "@\n")
      expect(malformed.code).to eq('400')
      reasons = esm_reasons(JSON.parse(malformed.body))
      expect(reasons.length).to eq(2)
      if @esm_profile.fetch('mode') == 'affected'
        expect(reasons).to all(include('(byte[])"'))
        # A backing array containing HTTP framing exceeds the two-byte JSON
        # body. Prior response data is separately recorded when it occurs.
        expect(reasons).to all(match(%r{HTTP/1\.[01]}))
      elsif @esm_profile.fetch('mode') == 'fixed'
        expect(reasons.join).not_to include('module_target_memory', 'HTTP/1.1 200 OK')
      end
      if @esm_profile.fetch('security')
        expect(esm_request(phase + '-anonymous', 'get', '/', nil, username: nil).code).to eq('401')
        expect(esm_request(phase + '-reader-root', 'get', '/', nil, username: 'module_reader').code).to eq('200')
        expect(esm_request(phase + '-limited-root', 'get', '/', nil, username: 'module_limited').code).to eq('403')
        %w[reader limited].each do |kind|
          refused = esm_request(phase + "-#{kind}-write", 'put', '/module_target_memory/_doc/module_denied', { 'marker' => 'denied' }, username: "module_#{kind}")
          expect(refused.code).to eq('403')
          malformed = esm_request(phase + "-#{kind}-malformed", 'post', '/_bulk', "@\n", username: "module_#{kind}")
          expect(malformed.code).to eq('400')
        end
        expect(esm_request(phase + '-denied-document', 'get', '/module_target_memory/_doc/module_denied').code).to eq('404')
        identity = JSON.parse(esm_request(phase + '-security-identity', 'get', '/_security/user/module_writer,module_reader,module_limited').body)
        @esm_security_baseline ||= identity
        expect(identity).to eq(@esm_security_baseline)
        roles = JSON.parse(esm_request(phase + '-role-identity', 'get', '/_security/role/module_writer,module_reader,module_limited').body)
        %w[writer reader limited].each do |kind|
          role = roles.fetch("module_#{kind}")
          expect(role.fetch('cluster')).to eq(kind == 'limited' ? [] : ['monitor'])
          expect(role.fetch('indices').first.values_at('names', 'privileges')).to eq([['module_target_memory'], kind == 'writer' ? %w[read write] : ['read']])
        end
        @esm_role_baseline ||= roles
        expect(roles).to eq(@esm_role_baseline)
      end
    end
    @esm_native.fetch(:controls) << { phase: phase, status: 'passed' }
    esm_save
  end

  def esm_reasons(document)
    error = document.fetch('error')
    [error.fetch('root_cause').first.fetch('reason'), error.fetch('reason')]
  end

  def esm_sql(query)
    esm_command('db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def esm_reports
    raise ArgumentError, 'Invalid Elasticsearch workspace' unless @esm_workspace.match?(/\Aesm_[0-9_]+\z/)

    result = {}
    { 'vulns' => 'v', 'services' => 's', 'loots' => 'l' }.each do |table, item|
      columns = "#{item}.*,host(h.address::inet) AS target_address"
      columns += ", (SELECT coalesce(json_agg(r.name ORDER BY r.name),'[]'::json) FROM refs r JOIN vulns_refs vr ON vr.ref_id=r.id WHERE vr.vuln_id=v.id) AS refs" if table == 'vulns'
      rows = esm_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT #{columns} FROM #{table} #{item} JOIN hosts h ON h.id=#{item}.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@esm_workspace}' ORDER BY #{item}.id) row")
      result[table] = JSON.parse(rows)
    end
    @esm_native.fetch(:reports) << { workspace: @esm_workspace, rows: result }
    esm_save
    result
  end

  def esm_loot_paths
    Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')].select { |path| File.file?(path) }
  end

  def esm_owner(options = {}, action: 'run')
    defaults = { 'SSL' => false, 'HttpClientTimeout' => 5, 'HttpTrace' => true, 'HttpTraceColors' => '/', 'HttpTraceHeadersOnly' => false }
    defaults.merge!('USERNAME' => 'elastic', 'PASSWORD' => 'module-target-password') if @esm_profile.fetch('security')
    call = { action: action, workspace: @esm_workspace, options: options, state: 'started' }
    @esm_native.fetch(:calls) << call
    esm_save
    output = run_target_module(ElasticsearchMemoryProfiles::OWNER, 'app', defaults.merge(options), action: action, allow_errors: true, command_timeout: 65)
    call.merge!(state: 'returned', output_base64: Base64.strict_encode64(output.b))
    esm_save
    expect(output).not_to match(/Unknown datastore option|LocalJumpError/)
    output
  ensure
    call[:console_base64] = Base64.strict_encode64(console.all_data.b) if call
    esm_save
  end

  def esm_traces(output)
    output.split("# Response:\n####################\n").drop(1).map do |block|
      block = block.b
      match = block.match(%r{\AHTTP/1\.[01] ([0-9]{3})[^\r\n]*\r?\n(.*?)\r?\n\r?\n}m)
      next unless match

      headers = match[2].lines.to_h { |line| line.strip.split(/:\s*/, 2) }
      length = Integer(headers.find { |key, _| key.downcase == 'content-length' }.last)
      body = block.b.byteslice(match.end(0), length)
      expect(body.bytesize).to eq(length)
      { status: Integer(match[1]), body: body }
    end.compact
  end

  def esm_counters(phase)
    counters = %w[app db].to_h do |role|
      values = %w[memory.events pids.events].to_h do |key|
        text = esm_command(role, 'cat', '/sys/fs/cgroup/' + key)
        events = text.lines.to_h do |line|
          name, value = line.split
          [name, Integer(value)]
        end
        [key, events]
      end
      expect(values.fetch('memory.events').values_at('oom', 'oom_kill')).to eq([0, 0])
      expect(values.fetch('pids.events').fetch('max')).to eq(0)
      [role, values]
    end
    File.write(File.join(target_runtime.fetch('artifacts'), "elasticsearch-memory-resources-#{phase}.json"), JSON.pretty_generate(counters))
  end

  def esm_check(classification, options = {})
    before = esm_loot_paths
    previous_reports = esm_reports
    output = esm_owner(options, action: 'check')
    expression = case classification
                 when 'appears' then /The target appears to be vulnerable/
                 when 'safe' then /The target is not exploitable/
                 else /Cannot reliably check exploitability/i
                 end
    expect(output).to match(expression)
    expect(output).not_to match(/Check failed|Auxiliary (?:failed|aborted)/)
    expect(esm_loot_paths).to eq(before)
    reports = esm_reports
    expect(reports.fetch('vulns').length).to eq(classification == 'appears' ? 1 : previous_reports.fetch('vulns').length)
    expect(reports.fetch('loots')).to eq(previous_reports.fetch('loots'))
    output
  end

  def esm_disclosure(output, count)
    replies = esm_traces(output).select { |reply| reply.fetch(:status) == 400 }
    expect(replies.length).to eq(count)
    replies.map do |reply|
      reasons = esm_reasons(JSON.parse(reply.fetch(:body)))
      expect(reasons.length).to eq(2)
      reasons.map do |reason|
        # Read the source interval independently from the module parser. Use
        # the final location suffix so embedded older error messages stay data.
        prefix = '(byte[])"'
        start = reason.index(prefix)
        finish = reason.rindex('; line: ')
        expect(start).not_to be_nil
        expect(finish).to be > start
        data = reason[(start + prefix.length)...finish]
        expect(data.bytesize).to be > 2
        data
      end.join("\n")
    end.join
  end

  def esm_collect(options = {}, dump: false, count: 1)
    before = esm_loot_paths
    output = esm_owner(options)
    expect(output).not_to match(/Auxiliary (?:failed|aborted)/)
    expected = esm_disclosure(output, count)
    # The source contains HTTP framing beyond the two-byte malformed JSON.
    # Only records that actually contain prior data claim prior-data exposure.
    expect(expected).to match(%r{HTTP/1\.[01]})
    expect(output).to include("Leaked #{expected.bytesize} bytes")
    added = esm_loot_paths - before
    if dump
      expect(added.length).to eq(1)
      path = added.first
      actual = File.binread(path)
      expect(actual).to eq(expected.b)
      expect(File.expand_path(path)).to start_with(File.expand_path(ENV.fetch('MSF_CFGROOT_CONFIG')) + '/')
      expect(output.b).to include(path.b)
      @esm_native.fetch(:loots) << { workspace: @esm_workspace, path: path, bytes: actual.bytesize, sha256: Digest::SHA256.hexdigest(actual), base64: Base64.strict_encode64(actual) }
    else
      expect(added).to eq([])
    end
    reports = esm_reports
    expect(reports.fetch('vulns').length).to eq(1)
    expect(reports.fetch('vulns').first.fetch('name')).to eq('Elasticsearch Memory Disclosure')
    expect(reports.fetch('vulns').first.fetch('target_address')).to eq('127.0.0.1')
    expect(reports.fetch('vulns').first.fetch('refs')).to include('CVE-2021-22145')
    expect(reports.fetch('services').length).to eq(1)
    expect(reports.fetch('services').first.values_at('port', 'proto', 'state')).to eq([target_endpoint('app').fetch('port'), 'tcp', 'open'])
    expected_paths = @esm_native.fetch(:loots).select { |row| row.fetch(:workspace) == @esm_workspace }.map { |row| row.fetch(:path) }
    expect(reports.fetch('loots').map { |row| row.fetch('path') }).to match_array(expected_paths)
    reports.fetch('loots').each do |row|
      expect(row.values_at('ltype', 'content_type', 'info')).to eq(['elasticsearch.memory.disclosure', 'application/octet-stream', 'Elasticsearch server memory'])
    end
    replies_count = esm_traces(output).length
    @esm_native.fetch(:calls).last[:disclosure] = { http_replies: replies_count, bulk_replies: count, bytes: expected.bytesize, sha256: Digest::SHA256.hexdigest(expected.b), prior_index_marker_seen: expected.include?('module_target_memory') }
    expect(replies_count).to be >= count
    esm_save
    output
  end

  def esm_refuse(options = {}, failure: false, http_status: :native)
    before = esm_loot_paths
    output = esm_owner(options)
    expect(output).not_to match(/Auxiliary (?:failed|aborted)/) unless failure
    http_status = @esm_profile.fetch('mode') == 'unrelated' ? @esm_unrelated_bulk_status : 400 if http_status == :native
    replies = esm_traces(output)
    if http_status
      expect(replies.length).to eq(options.fetch('LEAK_COUNT', 1))
      expect(replies.map { |reply| reply.fetch(:status) }).to all(eq(http_status))
      if http_status == 401
        expect(output).to include('Elasticsearch bulk request denied (HTTP 401)')
      elsif @esm_profile.fetch('mode') == 'unrelated'
        expect(output).to include("Elasticsearch bulk request returned HTTP #{http_status}")
      elsif @esm_profile.fetch('mode') == 'fixed'
        replies.each { |reply| expect(esm_reasons(JSON.parse(reply.fetch(:body)))).to all(include('[Source: (ByteArrayInputStream)')) }
      elsif options.key?('TARGETURI')
        replies.each { |reply| expect(JSON.parse(reply.fetch(:body)).fetch('error')).to include('no handler found for uri') }
      end
    else
      expect(replies).to eq([])
      expect(output).to include('Could not connect to web service - no response')
    end
    expect(output).not_to include('Leaked ', 'Elasticsearch memory data stored')
    expect(esm_loot_paths).to eq(before)
    expect(esm_reports.values).to all(eq([]))
    output
  end
end
