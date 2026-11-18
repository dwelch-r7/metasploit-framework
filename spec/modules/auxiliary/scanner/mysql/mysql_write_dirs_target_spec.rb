require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/mysql_write_dirs/acceptance'

RSpec.describe 'Native MySQL directory writes and borrowed sessions', acceptance: true, order: :defined do
  include_context 'module target'
  include MysqlWriteDirectoriesTarget

  before(:all) do
    @rc = { commands: [], native: [], calls: [], sessions: [] }
    ms_native('seed')
    ms_native('probe')
    @state = ms_native('state')
    mw_gate('before')
    console_command('features set mysql_session_type true')
    endpoint = target_endpoint('reporting_db')
    expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    @rc[:provenance] = rc_json('{ruby:RUBY_VERSION,config:Msf::Config.config_directory,owner_sha256:Digest::SHA256.file("modules/auxiliary/scanner/mysql/mysql_writable_dirs.rb").hexdigest}')
    expect(@rc.fetch(:provenance).fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/auxiliary/scanner/mysql/mysql_writable_dirs.rb').hexdigest)
    expect(@rc.fetch(:provenance).fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
    expect(rc_json('begin;source=File.expand_path("modules/auxiliary/scanner/mysql/mysql_writable_dirs.rb");events=[];trace=TracePoint.new(:call){|event|next unless File.expand_path(event.path)==source && %i[run_host mysql_query_no_handle check_dir].include?(event.method_id);events<<{method:event.method_id,object:event.self.object_id,session:event.self.datastore["SESSION"]}};framework.instance_variable_set(:@mysql_write_events,events);framework.instance_variable_set(:@mysql_write_trace,trace);trace.enable;{installed:true};end')).to eq('installed' => true)
    socket = TCPServer.new('127.0.0.1', 0)
    @unused_port = socket.local_address.ip_port
    socket.close
  end

  before do |example|
    label = example.metadata.fetch(:scoped_id).tr('0123456789', 'abcdefghij').delete(':')
    console_command('workspace -a mysql_write_' + Process.pid.to_s + '_' + label)
    ms_native('flush')
  end

  after do
    if @state
      mw_reset
      ms_clients
    end
  end

  after(:all) do
    if @state
      @rc[:owner_events] = rc_json('begin;trace=framework.instance_variable_get(:@mysql_write_trace);trace.disable if trace;framework.instance_variable_get(:@mysql_write_events);end')
      mw_gate('after')
    end
  ensure
    rc_save
  end

  it 'writes exact bytes, refuses collisions and writes again after an explicit reset standalone' do
    directories = [MysqlWriteDirectoriesTarget::BASE + '/ordinary', MysqlWriteDirectoriesTarget::BASE + '/space dir']
    denied = [MysqlWriteDirectoriesTarget::BASE + '/denied', MysqlWriteDirectoriesTarget::BASE + '/absent', MysqlWriteDirectoriesTarget::BASE + '/file-not-directory', MysqlWriteDirectoriesTarget::OUTSIDE]
    _output, first = mw_call('standalone-first', directories: directories + denied)
    mw_success(first, directories: directories)
    output, collision = mw_call('standalone-collision', directories: directories + denied, reuse: true)
    mw_success(collision, directories: directories)
    directories.each { |directory| expect(output).not_to include(directory + ' is writeable') }
    expect(collision.fetch(:files)).to eq(first.fetch(:files))
    mw_reset
    _output, repeated = mw_call('standalone-reset-repeat', directories: directories + denied, reuse: true)
    mw_success(repeated, directories: directories)
    expect(repeated.fetch(:identity)).to eq(first.fetch(:identity))
  end

  it 'uses a genuine MySQL session through success, collisions and reset without changing its identity or database' do
    identifier = ms_session('file_operator')
    connection = ms_session_query(identifier)
    directories = [MysqlWriteDirectoriesTarget::BASE + '/ordinary']
    _output, first = mw_call('session-first', directories: directories, session_id: identifier)
    mw_success(first, directories: directories)
    expect(ms_session_query(identifier)).to eq(connection)
    output, collision = mw_call('session-collision', directories: directories, session_id: identifier, reuse: true)
    mw_success(collision, directories: directories)
    expect(output).not_to include(directories.first + ' is writeable')
    mw_reset
    _output, repeated = mw_call('session-reset-repeat', directories: directories, session_id: identifier, reuse: true)
    mw_success(repeated, directories: directories)
    expect(ms_session_query(identifier)).to eq(connection)
    expect(repeated.fetch(:identity)).to eq(first.fetch(:identity))
  ensure
    ms_close_session(identifier) if identifier
  end

  it 'rejects SQL FILE privilege denial without files or notes' do
    _output, record = mw_call('file-privilege-denied', directories: [MysqlWriteDirectoriesTarget::BASE + '/ordinary'], username: 'no_file')
    expect(record.values_at(:files, :notes)).to eq([[], []])
  end

  it 'rejects wrong credentials without files or notes' do
    output, record = mw_call('wrong-password', directories: [MysqlWriteDirectoriesTarget::BASE + '/ordinary'], options: { 'PASSWORD' => 'Module-wrong-password42!' })
    expect(output).to match(/Access denied|Unable to login/i)
    expect(record.values_at(:files, :notes)).to eq([[], []])
  end

  it 'writes an exact filename containing a quote' do
    directories = [MysqlWriteDirectoriesTarget::BASE + '/ordinary']
    filename = "module-write'quote.txt"
    _output, record = mw_call('quoted-filename', directories: directories, filename: filename)
    mw_success(record, directories: directories, filename: filename)
  end

  it 'writes to an exact directory containing a quote' do
    directories = [MysqlWriteDirectoriesTarget::BASE + "/quote'dir"]
    _output, record = mw_call('quoted-directory', directories: directories)
    mw_success(record, directories: directories)
  end

  it 'preserves a literal backslash in the filename' do
    directories = [MysqlWriteDirectoriesTarget::BASE + '/ordinary']
    filename = 'module-write\back.txt'
    _output, record = mw_call('backslash-filename', directories: directories, filename: filename)
    mw_success(record, directories: directories, filename: filename)
  end

  it 'preserves a literal backslash in the directory' do
    directories = [MysqlWriteDirectoriesTarget::BASE + '/back\slash-dir']
    _output, record = mw_call('backslash-directory', directories: directories)
    mw_success(record, directories: directories)
  end

  it 'preserves both a backslash and a quote in one filename' do
    directories = [MysqlWriteDirectoriesTarget::BASE + '/ordinary']
    filename = "module-write\\back'quote.txt"
    _output, record = mw_call('backslash-quote-filename', directories: directories, filename: filename)
    mw_success(record, directories: directories, filename: filename)
  end
end
