# frozen_string_literal: true

require 'yaml'
require_relative '../rsync_creds/native'

# Independent catalog metadata, genuine SQL sessions and persisted schema evidence.
module MysqlSchemaTarget
  include RsyncCredentialTarget

  OWNER = 'auxiliary/scanner/mysql/mysql_schemadump'
  PASSWORD = 'Module-schema-password42!'

  def rc_owner
    OWNER
  end

  def rc_resource_roles
    %w[app reporting_db]
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'mysql-schema.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def ms_native(mode, username = 'root')
    output, = rc_command('native-' + mode + '-' + username, 'app', 'bash', '/opt/module-target/native.sh', mode, username)
    output
  end

  def ms_clients(expected = 0)
    rc_poll(8) { ms_native('clients').strip == expected.to_s }
  end

  def ms_expected(username)
    decode = ->(value) { [value].pack('H*').force_encoding(Encoding::UTF_8) }
    databases = ms_native('databases', username).lines.map { |line| { 'DBName' => decode.call(line.strip), 'Tables' => [] } }
    ms_native('tables', username).lines.each do |line|
      database, table = line.chomp.split("\t").map(&decode)
      databases.find { |entry| entry.fetch('DBName') == database }.fetch('Tables') << { 'TableName' => table, 'Columns' => [] }
    end
    ms_native('columns', username).lines.each do |line|
      database, table, column, type, = line.chomp.split("\t")
      entry = databases.find { |value| value.fetch('DBName') == decode.call(database) }.fetch('Tables').find { |value| value.fetch('TableName') == decode.call(table) }
      entry.fetch('Columns') << { 'ColumnName' => decode.call(column), 'ColumnType' => decode.call(type) }
    end
    databases
  end

  def ms_normalize(schema)
    schema.map { |entry| entry.merge('Tables' => entry.fetch('Tables').sort_by { |table| table.fetch('TableName') }) }.sort_by { |entry| entry.fetch('DBName') }
  end

  def ms_gate(phase)
    rc_resources(phase)
    output = ms_native('probe')
    processes = ms_native('processes')
    expect(output).to include('NATIVE_SCHEMA_ROOT', 'NATIVE_SCHEMA_BASIC', 'NATIVE_SCHEMA_CATALOG', 'NATIVE_SCHEMA_NONE', 'ERROR 1044')
    @expected.each { |username, expected| expect(ms_expected(username)).to eq(expected) }
    expect(ms_native('state')).to eq(@state)
    ms_clients
    @rc.fetch(:native) << { phase: phase, output_base64: Base64.strict_encode64(output.b), processes_base64: Base64.strict_encode64(processes.b) }
    rc_save
  end

  def ms_call(label, username: 'schema_basic', session_id: nil, display: true, reuse: false, options: {})
    record = { label: label, username: username, session: session_id, display: display }
    @rc.fetch(:calls) << record
    before = rc_json('Dir[File.join(Msf::Config.loot_directory,"*")].select{|p|File.file?(p)}')
    selected = { 'USERNAME' => username, 'PASSWORD' => PASSWORD, 'DISPLAY_RESULTS' => display, 'THREADS' => 1, 'ConnectTimeout' => 3 }.merge(options)
    selected.merge!('SESSION' => session_id, 'RPORT' => @unused_port) if session_id
    output = run_target_module(OWNER, 'app', selected, allow_errors: true, reuse_module: reuse, command_timeout: 90) do |text|
      record[:output_base64] = Base64.strict_encode64(text.b)
      record[:identity] = rc_json('{object_id:active_module.object_id,config:Msf::Config.config_directory}')
      rc_save
    end
    record[:paths] = rc_json('Dir[File.join(Msf::Config.loot_directory,"*")].select{|p|File.file?(p)}') - before
    rc_save
    ms_clients(session_id ? 1 : 0)
    expect(ms_native('state')).to eq(@state)
    [output, record.fetch(:paths)]
  end

  def ms_success(label, username:, session_id: nil, display: true, reuse: false)
    output, paths = ms_call(label, username: username, session_id: session_id, display: display, reuse: reuse)
    expect(output).to include('Schema stored in:')
    expect(paths.length).to eq(1)
    bytes = File.binread(paths.first)
    expect(bytes).not_to include('ROW_ONLY_SCHEMA_SENTINEL')
    start = bytes.index('---')
    expect(start).not_to be_nil
    schema = YAML.safe_load(bytes[start..])
    expect(ms_normalize(schema)).to eq(ms_normalize(@expected.fetch(username)))
    notes = rc_json('framework.db.notes(workspace:framework.db.workspace).select{|note|note.ntype=="mysql.db.schema"}.map{|note|{host:note.host.address,port:note.service&.port,data:note.data}}')
    @rc.fetch(:reports) << { label: label, notes: notes }
    expect(notes.map { |note| note.fetch('data').fetch('database') }.then { |data| ms_normalize(data) }).to eq(ms_normalize(@expected.fetch(username)))
    endpoint = target_endpoint('app')
    expect(notes.map { |note| note.fetch('host') }.uniq).to eq([endpoint.fetch('host')]) unless notes.empty?
    record = rc_json('framework.db.services(workspace:framework.db.workspace).map{|service|{host:service.host.address,port:service.port,name:service.name,proto:service.proto}}')
    @rc.fetch(:reports).last[:services] = record
    # report_note may create an unnamed endpoint before report_service names it.
    expect(record).to include('host' => endpoint.fetch('host'), 'port' => endpoint.fetch('port'), 'name' => 'mysql', 'proto' => 'tcp')
    expect(record.map { |service| service.except('name') }.uniq).to eq([{ 'host' => endpoint.fetch('host'), 'port' => endpoint.fetch('port'), 'proto' => 'tcp' }])
    expect(output).not_to include('DBName:') unless display
    @rc.fetch(:loots) << { label: label, path: paths.first, sha256: Digest::SHA256.file(paths.first).hexdigest, schema: schema }
    rc_save
    output
  end

  def ms_session(username)
    output = run_target_module('auxiliary/scanner/mysql/mysql_login', 'app', { 'USERNAME' => username, 'PASSWORD' => PASSWORD, 'BLANK_PASSWORDS' => false, 'USER_AS_PASS' => false, 'USER_FILE' => nil, 'PASS_FILE' => nil, 'USERPASS_FILE' => nil, 'STOP_ON_SUCCESS' => true, 'CreateSession' => true }, command_timeout: 90)
    expect(output).to include('MySQL session')
    sessions = rc_json('framework.sessions.map{|id,session|{id:id,type:session.type,info:session.info}}')
    expect(sessions.length).to eq(1)
    expect(sessions.first.fetch('type')).to eq('mysql')
    identifier = sessions.first.fetch('id')
    @rc.fetch(:sessions) << sessions.first
    rc_save
    ms_clients(1)
    identifier
  end

  def ms_session_query(identifier)
    rc_json("framework.sessions.fetch(#{identifier}).client.query('SELECT CONNECTION_ID(),CURRENT_USER(),DATABASE()').to_a")
  end

  def ms_close_session(identifier)
    expect(rc_json("begin;framework.sessions.fetch(#{identifier}).kill;{present:framework.sessions.key?(#{identifier})};end")).to eq('present' => false)
    ms_clients
  end
end
