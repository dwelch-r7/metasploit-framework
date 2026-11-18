require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/mysql_file_enum/acceptance'

RSpec.describe 'Native MySQL file enumeration and borrowed sessions', acceptance: true, order: :defined do
  include_context 'module target'
  include MysqlFileEnumTarget

  before(:all) do
    @rc = { commands: [], native: [], calls: [], sessions: [] }
    ms_native('seed')
    ms_native('probe')
    @state = ms_native('state')
    mf_gate('before')
    console_command('features set mysql_session_type true')
    endpoint = target_endpoint('reporting_db')
    expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    @rc[:provenance] = rc_json('{ruby:RUBY_VERSION,config:Msf::Config.config_directory,owner_sha256:Digest::SHA256.file("modules/auxiliary/scanner/mysql/mysql_file_enum.rb").hexdigest}')
    expect(@rc.fetch(:provenance).fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/auxiliary/scanner/mysql/mysql_file_enum.rb').hexdigest)
    expect(@rc.fetch(:provenance).fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
    expect(rc_json('begin;source=File.expand_path("modules/auxiliary/scanner/mysql/mysql_file_enum.rb");events=[];trace=TracePoint.new(:call){|event|next unless File.expand_path(event.path)==source && %i[run_host mysql_query_no_handle check_dir].include?(event.method_id);events<<{method:event.method_id,object:event.self.object_id,session:event.self.datastore["SESSION"]}};framework.instance_variable_set(:@mysql_file_events,events);framework.instance_variable_set(:@mysql_file_trace,trace);trace.enable;{installed:true};end')).to eq('installed' => true)
    socket = TCPServer.new('127.0.0.1', 0)
    @unused_port = socket.local_address.ip_port
    socket.close
  end

  before do |example|
    label = example.metadata.fetch(:scoped_id).tr('0123456789', 'abcdefghij').delete(':')
    console_command('workspace -a mysql_files_' + Process.pid.to_s + '_' + label)
    ms_native('flush')
  end

  after(:all) do
    if @state
      @rc[:owner_events] = rc_json('begin;trace=framework.instance_variable_get(:@mysql_file_trace);trace.disable if trace;framework.instance_variable_get(:@mysql_file_events);end')
      mf_gate('after')
    end
  ensure
    rc_save
  end

  it 'enumerates ordinary and empty files, a directory and absence twice standalone' do
    files = [MysqlFileEnumTarget::BASE + '/numbers.txt', MysqlFileEnumTarget::BASE + '/empty.txt']
    directory = MysqlFileEnumTarget::BASE + '/read-dir'
    list = files + [directory, MysqlFileEnumTarget::BASE + '/absent.txt']
    _output, first = mf_call('ordinary-first', files: list)
    mf_notes(first, files: files, directories: [directory])
    _output, repeated = mf_call('ordinary-repeat', files: list, reuse: true)
    mf_notes(repeated, files: files, directories: [directory])
    expect(repeated.fetch(:identity)).to eq(first.fetch(:identity))
  end

  it 'borrows a genuine MySQL session twice and keeps its client usable' do
    identifier = ms_session('file_operator')
    before = ms_session_query(identifier).first
    files = [MysqlFileEnumTarget::BASE + '/numbers.txt']
    _output, first = mf_call('session-first', files: files, session_id: identifier)
    mf_notes(first, files: files)
    expect(ms_session_query(identifier).first).to eq(before.first(2) + ['module_files'])
    _output, repeated = mf_call('session-repeat', files: files, session_id: identifier, reuse: true)
    mf_notes(repeated, files: files)
    expect(ms_session_query(identifier).first).to eq(before.first(2) + ['module_files'])
    expect(repeated.fetch(:identity)).to eq(first.fetch(:identity))
  ensure
    ms_close_session(identifier) if identifier
  end

  it 'retains file semantics for text and out-of-range numeric contents' do
    files = [MysqlFileEnumTarget::BASE + '/text.txt', MysqlFileEnumTarget::BASE + '/range.txt']
    output, record = mf_call('content-errors', files: files)
    files.each { |path| expect(output).to include(path + ' is a file and exists') }
    mf_notes(record, files: files)
  end

  it 'enumerates a real file whose name contains a single quote' do
    files = [MysqlFileEnumTarget::BASE + "/quote'file.txt"]
    _output, record = mf_call('quoted-path', files: files)
    mf_notes(record, files: files)
  end

  it 'does not label a protected file as absent or a directory' do
    path = MysqlFileEnumTarget::BASE + '/private.txt'
    output, record = mf_call('protected-file', files: [path])
    mf_notes(record)
    expect(output).not_to include(path + ' does not exist', path + ' is a directory')
  end

  it 'does not turn a SQL FILE privilege denial into a false absence claim' do
    path = MysqlFileEnumTarget::BASE + '/numbers.txt'
    output, record = mf_call('file-privilege-denied', files: [path], username: 'no_file')
    mf_notes(record)
    expect(output).not_to include(path + ' does not exist')
  end

  it 'retains an existing table and permits the documented row changes on repeats' do
    files = [MysqlFileEnumTarget::BASE + '/numbers.txt']
    _output, first = mf_call('existing-first', files: files, options: { 'TABLE_NAME' => 'existing_rows' }, changed_existing: true)
    mf_notes(first, files: files)
    expect(ms_native('existing').lines.map(&:to_i)).to eq([7, 8, 777])
    ms_native('reset_existing')
    _output, repeated = mf_call('existing-repeat', files: files, options: { 'TABLE_NAME' => 'existing_rows' }, changed_existing: true, reuse: true)
    mf_notes(repeated, files: files)
    expect(ms_native('existing').lines.map(&:to_i)).to eq([7, 8, 777])
    expect(repeated.fetch(:identity)).to eq(first.fetch(:identity))
  ensure
    ms_native('reset_existing')
    expect(ms_native('state')).to eq(@state)
  end

  it 'uses valid quoted database and table names accepted by the native client' do
    files = [MysqlFileEnumTarget::BASE + '/numbers.txt']
    _output, record = mf_call('quoted-identifiers', files: files, options: { 'DATABASE_NAME' => 'module files', 'TABLE_NAME' => 'module enum table' })
    mf_notes(record, files: files)
  end

  it 'uses a valid quoted table name in an ordinary database' do
    files = [MysqlFileEnumTarget::BASE + '/numbers.txt']
    _output, record = mf_call('quoted-table', files: files, options: { 'TABLE_NAME' => 'module enum table' })
    mf_notes(record, files: files)
  end

  it 'rejects a nonexistent database without leaving notes or a temporary table' do
    output, record = mf_call('missing-database', files: [MysqlFileEnumTarget::BASE + '/numbers.txt'], options: { 'DATABASE_NAME' => 'module_absent' })
    expect(output).to include('module_absent')
    expect(output).to match(/Unknown database|Access denied/i)
    mf_notes(record)
  end

  it 'refuses wrong credentials without notes or a temporary table' do
    output, record = mf_call('wrong-password', files: [MysqlFileEnumTarget::BASE + '/numbers.txt'], options: { 'PASSWORD' => 'Module-wrong-password42!' })
    expect(output).to match(/Access denied|Unable to login/i)
    mf_notes(record)
  end
end
