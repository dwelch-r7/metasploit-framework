require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/mysql_schema/acceptance'

RSpec.describe 'Native MySQL schema metadata and borrowed sessions', acceptance: true, order: :defined do
  include_context 'module target'
  include MysqlSchemaTarget

  before(:all) do
    @rc = { commands: [], native: [], calls: [], sessions: [], reports: [], loots: [] }
    ms_native('seed')
    @state = ms_native('state')
    @expected = %w[schema_basic schema_catalog schema_none].to_h { |username| [username, ms_expected(username)] }
    expect(@expected.fetch('schema_basic').map { |database| database.fetch('DBName') }).to contain_exactly('module_basic', 'module_empty')
    expect(@expected.fetch('schema_catalog').map { |database| database.fetch('DBName') }).to contain_exactly('module_basic', 'module_empty', 'module odd-db', 'module`quoted')
    expect(@expected.fetch('schema_none')).to eq([])
    ms_gate('before')
    console_command('features set mysql_session_type true')
    endpoint = target_endpoint('reporting_db')
    expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    @rc[:provenance] = rc_json('{ruby:RUBY_VERSION,config:Msf::Config.config_directory,owner_sha256:Digest::SHA256.file("modules/auxiliary/scanner/mysql/mysql_schemadump.rb").hexdigest}')
    expect(@rc.fetch(:provenance).fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/auxiliary/scanner/mysql/mysql_schemadump.rb').hexdigest)
    expect(@rc.fetch(:provenance).fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
    expect(rc_json('begin;source=File.expand_path("modules/auxiliary/scanner/mysql/mysql_schemadump.rb");events=[];trace=TracePoint.new(:call){|event|next unless File.expand_path(event.path)==source && %i[run_host get_schema get_tbl_names get_columns].include?(event.method_id);events<<{method:event.method_id,object:event.self.object_id,session:event.self.datastore["SESSION"]}};framework.instance_variable_set(:@mysql_schema_events,events);framework.instance_variable_set(:@mysql_schema_trace,trace);trace.enable;{installed:true};end')).to eq('installed' => true)
    socket = TCPServer.new('127.0.0.1', 0)
    @unused_port = socket.local_address.ip_port
    socket.close
  end

  before do |example|
    label = example.metadata.fetch(:scoped_id).tr('0123456789', 'abcdefghij').delete(':')
    console_command('workspace -a mysql_schema_' + Process.pid.to_s + '_' + label)
    ms_native('flush')
  end

  after(:all) do
    if @state
      @rc[:owner_events] = rc_json('begin;trace=framework.instance_variable_get(:@mysql_schema_trace);trace.disable if trace;framework.instance_variable_get(:@mysql_schema_events);end')
      ms_gate('after')
    end
  ensure
    rc_save
  end

  %w[schema_basic schema_catalog].each do |username|
    it "exports native #{username} metadata and repeats without changing the console configuration" do
      ms_success(username + '-first', username: username)
      identity = @rc.fetch(:calls).last.fetch(:identity)
      ms_success(username + '-repeat', username: username, display: false, reuse: true)
      expect(@rc.fetch(:calls).last.fetch(:identity)).to eq(identity)
    end

    it "borrows a real #{username} MySQL session twice and preserves its connection" do
      identifier = ms_session(username)
      connection = ms_session_query(identifier)
      ms_success(username + '-session-first', username: username, session_id: identifier, display: false)
      expect(ms_session_query(identifier)).to eq(connection)
      ms_success(username + '-session-repeat', username: username, session_id: identifier, display: false, reuse: true)
      expect(ms_session_query(identifier)).to eq(connection)
    ensure
      ms_close_session(identifier) if identifier
    end
  end

  it 'stores an empty schema result without inventing databases for a USAGE-only user' do
    ms_success('no-visible-databases', username: 'schema_none', display: false)
  end

  it 'refuses incorrect credentials without writing schema loot or notes' do
    output, paths = ms_call('wrong-password', options: { 'PASSWORD' => 'Module-wrong-password42!' })
    expect(output).to match(/Access denied|Unable to login/i)
    expect(paths).to eq([])
    expect(rc_json('framework.db.notes(workspace:framework.db.workspace).count')).to eq(0)
  end
end
