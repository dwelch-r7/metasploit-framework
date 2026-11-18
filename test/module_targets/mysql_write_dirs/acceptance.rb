# frozen_string_literal: true

require_relative '../mysql_schema/acceptance'

# Genuine SQL file writes, native bytes/ownership and actual filesystem notes.
module MysqlWriteDirectoriesTarget
  include MysqlSchemaTarget

  OWNER = 'auxiliary/scanner/mysql/mysql_writable_dirs'
  BASE = '/var/lib/mysql-files/module-write'
  OUTSIDE = '/tmp/module-write-outside'
  FILENAME = 'module-write-test.txt'

  def rc_owner
    OWNER
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'mysql-write-dirs.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def mw_gate(phase)
    rc_resources(phase)
    output = ms_native('probe')
    expect(output).to include(ENV.fetch('MYSQL_WRITE_RELEASE'), 'NATIVE_WRITE_ROOT', 'NATIVE_WRITE_BYTES mysql', 'NATIVE_WRITE_NO_FILE')
    expect(output).to include(ENV.fetch('MYSQL_WRITE_MODE')) if ENV.key?('MYSQL_WRITE_MODE')
    modes = output.scan(/^NATIVE_WRITE_BYTES mysql (\d+) 4$/).flatten.uniq
    expect(modes.length).to eq(1)
    @write_mode ||= modes.first
    expect(modes).to eq([@write_mode])
    (%w[1086 1 1290] + [ENV.fetch('MYSQL_WRITE_DENIAL_CODE', '1227')]).each { |code| expect(output).to include('ERROR ' + code + ' ') }
    expect(ms_native('state')).to eq(@state)
    ms_clients
    @rc.fetch(:native) << { phase: phase, output_base64: Base64.strict_encode64(output.b), processes_base64: Base64.strict_encode64(ms_native('processes').b) }
    rc_save
  end

  def mw_files
    ms_native('files').lines.map do |line|
      path, bytes, owner, mode = line.chomp.split("\t")
      { 'path' => [path].pack('H*').force_encoding(Encoding::UTF_8), 'hex' => bytes, 'owner' => owner, 'mode' => mode }
    end
  end

  def mw_call(label, directories:, filename: FILENAME, username: 'file_operator', session_id: nil, reuse: false, options: {})
    list = File.join(target_runtime.fetch('artifacts'), label + '-directories.txt')
    File.write(list, directories.join("\n") + "\n")
    record = { label: label, directories: directories, filename: filename, username: username, session: session_id, list_sha256: Digest::SHA256.file(list).hexdigest }
    @rc.fetch(:calls) << record
    selected = { 'USERNAME' => username, 'PASSWORD' => MysqlSchemaTarget::PASSWORD, 'DIR_LIST' => list, 'FILE_NAME' => filename, 'THREADS' => 1, 'ConnectTimeout' => 3 }.merge(options)
    selected.merge!('SESSION' => session_id, 'RPORT' => @unused_port) if session_id
    output = run_target_module(OWNER, 'app', selected, allow_errors: true, reuse_module: reuse, command_timeout: 90) do |text|
      record[:output_base64] = Base64.strict_encode64(text.b)
      record[:identity] = rc_json('{object_id:active_module.object_id,config:Msf::Config.config_directory}')
      rc_save
    end
    record[:files] = mw_files
    record[:notes] = rc_json('framework.db.notes(workspace:framework.db.workspace).map{|note|{type:note.ntype,data:note.data,host:note.host.address,port:note.service&.port,proto:note.service&.proto}}')
    record[:services] = rc_json('framework.db.services(workspace:framework.db.workspace).map{|service|{host:service.host.address,port:service.port,name:service.name,proto:service.proto}}')
    record[:loot_paths] = rc_json('Dir[File.join(Msf::Config.loot_directory,"*")].select{|path|File.file?(path)}')
    rc_save
    expect(record.fetch(:loot_paths)).to eq([])
    ms_clients(session_id ? 1 : 0)
    [output, record]
  end

  def mw_success(record, directories:, filename: FILENAME)
    expect(record.fetch(:files).map { |file| file.fetch('path') }.sort).to eq(directories.map { |directory| directory + '/' + filename }.sort)
    expect(record.fetch(:files).map { |file| file.slice('hex', 'owner') }.uniq).to eq([{ 'hex' => '74657374', 'owner' => 'mysql' }])
    expect(record.fetch(:files).map { |file| file.fetch('mode') }.uniq).to eq([@write_mode])
    endpoint = target_endpoint('app')
    expected = directories.map { |directory| { 'type' => 'filesystem.file', 'data' => { 'dir' => directory, 'permissions' => 'writeable' }, 'host' => endpoint.fetch('host'), 'port' => endpoint.fetch('port'), 'proto' => 'tcp' } }
    expect(record.fetch(:notes).sort_by(&:to_s)).to eq(expected.sort_by(&:to_s))
    expect(record.fetch(:services).map { |service| service.except('name') }.uniq).to eq([{ 'host' => endpoint.fetch('host'), 'port' => endpoint.fetch('port'), 'proto' => 'tcp' }])
  end

  def mw_reset
    ms_native('reset')
    expect(mw_files).to eq([])
    expect(ms_native('state')).to eq(@state)
  end
end
