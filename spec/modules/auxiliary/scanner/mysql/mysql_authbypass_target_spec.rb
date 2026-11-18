require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/mysql_authbypass/acceptance'

RSpec.describe 'Native MySQL authentication bypass and hash collection', acceptance: true, order: :defined do
  include_context 'module target'
  include MysqlAuthbypassTarget

  before(:all) do
    @rc = { commands: [], native: [], calls: [], loots: [], reports: [] }
    @mode = ENV.fetch('MYSQL_AUTHBYPASS_MODE', 'vulnerable')
    output, = rc_command('native-address', 'app', 'hostname', '-I')
    @native_peer = output.split.first
    expect(@native_peer).to match(/\A\d+(?:\.\d+){3}\z/)
    ma_native('seed')
    @state = ma_native('state')
    @expected = ma_native('expected').lines.map do |line|
      line.chomp.split("\t", -1).map { |value| [value].pack('H*') }
    end
    expect(@expected.map(&:first)).to include('comma,user', "quote'user", 'space user', 'empty_hash', 'module_reader', 'module_denied') unless @mode == 'policy'
    ma_gate('before')
    endpoint = target_endpoint('reporting_db')
    expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    @rc[:provenance] = rc_json('{ruby:RUBY_VERSION,config:Msf::Config.config_directory,owner_sha256:Digest::SHA256.file("modules/auxiliary/scanner/mysql/mysql_authbypass_hashdump.rb").hexdigest,mysql_gem:Gem.loaded_specs.fetch("ruby-mysql").version.to_s}')
    expect(@rc.fetch(:provenance).fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/auxiliary/scanner/mysql/mysql_authbypass_hashdump.rb').hexdigest)
    expect(@rc.fetch(:provenance).fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
    expect(rc_json('begin;source=File.expand_path("modules/auxiliary/scanner/mysql/mysql_authbypass_hashdump.rb");events=[];trace=TracePoint.new(:call){|event|next unless File.expand_path(event.path)==source && %i[run_host dump_hashes report_hashes].include?(event.method_id);events<<{method:event.method_id,object:event.self.object_id,username:event.self.datastore["USERNAME"]}};framework.instance_variable_set(:@mysql_bypass_events,events);framework.instance_variable_set(:@mysql_bypass_trace,trace);trace.enable;{installed:true};end')).to eq('installed' => true)
  end

  before do |example|
    label = example.metadata.fetch(:scoped_id).tr('0123456789', 'abcdefghij').delete(':')
    @workspace = "mysql_bypass_#{Process.pid}_#{label}"
    console_command('workspace -a ' + @workspace)
  end

  after(:all) do
    if @state
      @rc[:owner_events] = rc_json('begin;trace=framework.instance_variable_get(:@mysql_bypass_trace);trace.disable if trace;framework.instance_variable_get(:@mysql_bypass_events);end')
      ma_gate('after')
    end
  ensure
    rc_save
  end

  if %w[vulnerable open].include?(ENV.fetch('MYSQL_AUTHBYPASS_MODE', 'vulnerable'))
    it 'saves exact native rows including duplicate accounts, CSV punctuation and an empty hash' do
      ma_hashes('root-first')
    end

    it 'repeats hash collection with the same active console configuration' do
      identity = @rc.fetch(:calls).last.fetch(:identity)
      ma_hashes('root-repeat', reuse: true)
      expect(@rc.fetch(:calls).last.fetch(:identity)).to eq(identity)
    end

    it 'collects the same exact rows through a non-administrator with SELECT access' do
      ma_hashes('reader', username: 'module_reader')
    end

    if ENV.fetch('MYSQL_AUTHBYPASS_MODE', 'vulnerable') == 'open'
      it 'uses the immediate-login path for a nonexistent user when grants are disabled' do
        ma_hashes('nonexistent', username: 'does_not_exist')
        output = Base64.strict_decode64(@rc.fetch(:calls).last.fetch(:output_base64))
        expect(output).to include('The server accepted our first login')
      end
    else
      it 'does not save hashes when the authenticated account lacks SELECT permission' do
        output, paths = ma_acquire('denied', username: 'module_denied')
        expect(output).to include('There was an error reading the MySQL User Table')
        expect(paths).to eq([])
        expect(ma_services).to eq([])
      end
    end
  else
    it 'refuses the independently verified protected service without saving hashes' do
      output, paths = ma_call('refused')
      message = @mode == 'fixed' ? 'Unable to bypass authentication, this target may not be vulnerable' : 'Unable to login from this host due to policy'
      expect(output).to include(message)
      expect(paths).to eq([])
      expect(ma_services).to eq([])
    end

    it 'repeats refusal with the same active console configuration' do
      identity = @rc.fetch(:calls).last.fetch(:identity)
      output, paths = ma_call('refused-repeat', reuse: true)
      message = @mode == 'fixed' ? 'Unable to bypass authentication, this target may not be vulnerable' : 'Unable to login from this host due to policy'
      expect(output).to include(message)
      expect(paths).to eq([])
      expect(ma_services).to eq([])
      expect(@rc.fetch(:calls).last.fetch(:identity)).to eq(identity)
    end
  end

  it 'does not save hashes or services for an independently closed TCP port' do
    server = TCPServer.new('127.0.0.1', 0)
    port = server.local_address.ip_port
    server.close
    expect { TCPSocket.new('127.0.0.1', port) }.to raise_error(Errno::ECONNREFUSED)
    output, paths = ma_call('closed-port', options: { 'RPORT' => port })
    expect(output).to match(/Error:.*(?:refused|connect)/i)
    expect(paths).to eq([])
    expect(ma_services).to eq([])
  ensure
    server&.close unless server&.closed?
  end
end
