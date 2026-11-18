# frozen_string_literal: true

require_relative '../mysql_schema/acceptance'

# Native files, SQL privileges, actual collector notes and borrowed connections.
module MysqlFileEnumTarget
  include MysqlSchemaTarget

  OWNER = 'auxiliary/scanner/mysql/mysql_file_enum'
  BASE = '/var/lib/mysql-files/module-target'

  def rc_owner
    OWNER
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'mysql-file-enum.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def mf_gate(phase)
    rc_resources(phase)
    output = ms_native('probe')
    expect(output).to include(ENV.fetch('MYSQL_FILE_RELEASE'), 'NATIVE_FILE_ROOT', 'NATIVE_FILE_OPERATOR', 'NATIVE_NO_FILE')
    expect(output).to include(ENV.fetch('MYSQL_FILE_MODE')) if ENV.key?('MYSQL_FILE_MODE')
    %w[1366 1264 1085 29 13 1290 1045].each { |code| expect(output).to include('ERROR ' + code + ' ') }
    expect(ms_native('state')).to eq(@state)
    ms_clients
    @rc.fetch(:native) << { phase: phase, output_base64: Base64.strict_encode64(output.b), processes_base64: Base64.strict_encode64(ms_native('processes').b) }
    rc_save
  end

  def mf_call(label, files:, username: 'file_operator', session_id: nil, reuse: false, options: {}, changed_existing: false)
    list = File.join(target_runtime.fetch('artifacts'), label + '-files.txt')
    File.write(list, files.join("\n") + "\n")
    record = { label: label, files: files, username: username, session: session_id, list_sha256: Digest::SHA256.file(list).hexdigest }
    @rc.fetch(:calls) << record
    selected = { 'USERNAME' => username, 'PASSWORD' => MysqlSchemaTarget::PASSWORD, 'FILE_LIST' => list, 'DATABASE_NAME' => 'module_files', 'TABLE_NAME' => 'module_enum_probe', 'THREADS' => 1, 'ConnectTimeout' => 3 }.merge(options)
    selected.merge!('SESSION' => session_id, 'RPORT' => @unused_port) if session_id
    output = run_target_module(OWNER, 'app', selected, allow_errors: true, reuse_module: reuse, command_timeout: 90) do |text|
      record[:output_base64] = Base64.strict_encode64(text.b)
      record[:identity] = rc_json('{object_id:active_module.object_id,config:Msf::Config.config_directory}')
      rc_save
    end
    record[:notes] = rc_json('framework.db.notes(workspace:framework.db.workspace).map{|note|{type:note.ntype,data:note.data,host:note.host.address,port:note.service&.port,proto:note.service&.proto}}')
    record[:services] = rc_json('framework.db.services(workspace:framework.db.workspace).map{|service|{host:service.host.address,port:service.port,name:service.name,proto:service.proto}}')
    record[:loot_paths] = rc_json('Dir[File.join(Msf::Config.loot_directory,"*")].select{|path|File.file?(path)}')
    rc_save
    expect(record.fetch(:loot_paths)).to eq([])
    ms_clients(session_id ? 1 : 0)
    expect(ms_native('state')).to eq(@state) unless changed_existing
    [output, record]
  end

  def mf_notes(record, files: [], directories: [])
    endpoint = target_endpoint('app')
    expected = files.map { |path| { 'type' => 'filesystem.file', 'data' => { 'file' => path } } } + directories.map { |path| { 'type' => 'filesystem.dir', 'data' => { 'directory' => path } } }
    actual = record.fetch(:notes)
    expect(actual.map { |note| note.slice('type', 'data') }.sort_by(&:to_s)).to eq(expected.sort_by(&:to_s))
    unless actual.empty?
      expect(actual.map { |note| note.slice('host', 'port', 'proto') }.uniq).to eq([{ 'host' => endpoint.fetch('host'), 'port' => endpoint.fetch('port'), 'proto' => 'tcp' }])
      expect(record.fetch(:services).map { |service| service.except('name') }.uniq).to eq([{ 'host' => endpoint.fetch('host'), 'port' => endpoint.fetch('port'), 'proto' => 'tcp' }])
    end
  end
end
