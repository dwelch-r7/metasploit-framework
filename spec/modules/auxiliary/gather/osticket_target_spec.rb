require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/osticket/acceptance'

RSpec.describe 'osTicket native file collection', acceptance: true, order: :defined do
  include_context 'module target'
  include OsticketTarget

  before(:all) do
    @rc = { commands: [], native: [], calls: [], loot: [], reports: [] }
    ot_native('before')
    @ticket_baseline = ot_control('state').fetch('tickets')
    @fixtures = ot_control('fixtures')
    expect(@fixtures.values.map { |value| value.fetch('uid') }.uniq).to eq([33])
    endpoint = target_endpoint('reporting_db')
    expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    @rc[:source] = rc_json('{owner_sha256:Digest::SHA256.file("modules/auxiliary/gather/osticket_arbitrary_file_read.rb").hexdigest,library_sha256:Digest::SHA256.file("lib/msf/core/auxiliary/osticket.rb").hexdigest,config:Msf::Config.config_directory}')
    expect(@rc.fetch(:source).fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/auxiliary/gather/osticket_arbitrary_file_read.rb').hexdigest)
    expect(@rc.fetch(:source).fetch('library_sha256')).to eq(Digest::SHA256.file('lib/msf/core/auxiliary/osticket.rb').hexdigest)
    expect(@rc.fetch(:source).fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
    expect(rc_json('begin;source=File.expand_path("modules/auxiliary/gather/osticket_arbitrary_file_read.rb");events=[];trace=TracePoint.new(:call){|event|next unless File.expand_path(event.path)==source && %i[check run].include?(event.method_id);events<<{method:event.method_id,object:event.self.object_id,portal:event.self.datastore["LOGIN_PORTAL"],auto_check:event.self.datastore["AutoCheck"]}};framework.instance_variable_set(:@osticket_events,events);framework.instance_variable_set(:@osticket_trace,trace);trace.enable;{installed:true};end')).to eq('installed' => true)
  end

  before do |example|
    label = example.metadata.fetch(:scoped_id).tr('0123456789', 'abcdefghij').delete(':')
    @workspace = "rc_#{Process.pid}_#{label}"
    expect(console_command('workspace -a ' + @workspace)).to include(@workspace)
    @ticket = ot_control('ticket')
  end

  after do
    ot_recover_tickets if @ticket_baseline
  end

  after(:all) do
    if @ticket_baseline
      @rc[:owner_events] = rc_json('begin;trace=framework.instance_variable_get(:@osticket_trace);trace.disable if trace;framework.instance_variable_get(:@osticket_events);end')
      ot_native('after')
    end
  ensure
    rc_save
  end

  it 'detects the independently verified product without claiming a vulnerability check' do
    output = ot_call('check', {}, action: 'check')
    expect(output).to include('Target appears to be an osTicket installation')
  end

  if ENV.fetch('OSTICKET_RELEASE', '1.18.2') == '1.18.2'
    %w[client scp].each do |portal|
      it "saves exact Base64 file bytes through #{portal} and repeats with AutoCheck disabled" do
        path = '/tmp/module-target-osticket-native-canary.txt'
        expected = Base64.strict_decode64(@fixtures.fetch(path).fetch('base64'))
        aggregate_failures do
          output, loot = ot_read(portal + '-first', path, portal: portal)
          expect(output).to include('Exploitation complete')
          expect(loot).to eq([expected])
          identity = @rc.fetch(:calls).last.fetch(:identity)
          output, loot = ot_read(portal + '-repeat', path, portal: portal, reuse: true)
          expect(output).to include('Exploitation complete')
          expect(loot).to eq([expected])
          expect(@rc.fetch(:calls).last.fetch(:identity)).to eq(identity)
        end
      end
    end

    it 'creates a real client ticket and saves the exact requested file' do
      path = '/tmp/module-target-osticket-native-canary.txt'
      output, loot = ot_read('client-create', path, create: true)
      expect(output).to include('Created ticket #', 'Exploitation complete')
      expect(loot).to eq([Base64.strict_decode64(@fixtures.fetch(path).fetch('base64'))])
    end

    it 'saves a short ASCII file without truncation' do
      path = '/tmp/module-target-osticket-ascii.txt'
      _output, loot = ot_read('short-file', path)
      expect(loot.map { |bytes| Base64.strict_encode64(bytes) }).to eq([@fixtures.fetch(path).fetch('base64')])
    end

    it 'saves the native configuration and persists discovered credentials and notes' do
      expected = Base64.strict_decode64(ot_control('state').fetch('config_base64'))
      aggregate_failures do
        output, loot = ot_read('configuration', 'include/ost-config.php')
        expect(output).to include('Exploitation complete')
        expect(loot.map { |bytes| Base64.strict_encode64(bytes) }).to eq([Base64.strict_encode64(expected)])
        expect(rc_credentials.map { |row| row.values_at('username', 'private_data') }).to eq([['module_target', 'module-target-db-password']])
        notes = rc_json('framework.db.notes(workspace: framework.db.workspace).map{|note|{type:note.ntype,host:note.host&.address,data:note.data}}')
        @rc[:notes] = notes
        salt = expected.match(/define\('SECRET_SALT','([^']+)'\)/)[1]
        expect(notes.map { |note| note.values_at('type', 'data') }).to contain_exactly(['osticket.admin_email', { 'email' => 'module-admin@example.test' }], ['osticket.secret_salt', { 'salt' => salt }])
      end
    end

  else
    %w[client scp].each do |portal|
      it "does not save file bytes through patched #{portal} PDF export" do
        output, loot = ot_read('fixed-' + portal, '/tmp/module-target-osticket-ascii.txt', portal: portal)
        expect(output).to include('No file could be extracted from the PDF')
        expect(loot.length).to eq(1)
        expect(loot.first).to start_with('%PDF-')
      end
    end
  end
end
