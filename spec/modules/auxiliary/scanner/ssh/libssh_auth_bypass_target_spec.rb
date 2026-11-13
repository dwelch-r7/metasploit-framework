require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/libssh/acceptance'

RSpec.describe 'Genuine libssh authentication bypass', acceptance: true, order: :defined do
  include_context 'module target'
  include_context 'wait_for_expect'
  include Acceptance::Libssh

  before(:all) do
    @native = ssh_native('before')
    @idle = ssh_state
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    expect(ssh_json('load "test/module_targets/libssh/session_control.rb"; DruidSessionControl.install(framework)')).to include('installed' => true)
  end

  before do |example|
    @case = example.metadata.fetch(:scoped_id).tr(':', '_')
    @workspace = 'libssh_' + @case
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(ssh_reports).to eq([])
    ssh_idle
  end

  after do |example|
    state = ssh_state
    ssh_journal('after-example-state.jsonl', case: @case, state: state, error: example.exception&.message)
    console_command('sessions -K') if example.exception
    RSpec.world.wants_to_quit = true if example.exception && !state.fetch('connections').empty?
    ssh_reports
  end

  after(:all) do
    if @native
      current = ssh_native('after')
      expect(current.fetch('binary_manifest')).to eq(@native.fetch('binary_manifest'))
      expect(current.fetch('packages_sha256')).to eq(@native.fetch('packages_sha256'))
      ssh_resources
    end
  end

  [2222, 2224].each do |port|
    [false, true].each do |pty|
      it("executes a real command twice on #{port} with PTY=#{pty}") { ssh_execute(port, allowed: true, pty: pty) }
    end
  end

  it('waits for a genuine delayed command twice') { ssh_execute(2222, allowed: true, delayed: true) }

  [2222, 2224].each do |port|
    [false, true].each do |pty|
      it("opens, uses and gracefully closes a real shell twice on #{port} with PTY=#{pty}") { ssh_session(port, pty: pty) }
    end
  end

  it('supports an alternative shell command twice') { ssh_session(2222, pty: false, alternative: true) }

  [2223, 2225].each do |port|
    [true, false].each do |check_banner|
      it "refuses fixed #{port} with CHECK_BANNER=#{check_banner} twice without reporting a vulnerability" do
        ssh_execute(port, allowed: false, check_banner: check_banner)
        expect(ssh_reports).to eq([])
      end
    end
    it("refuses a real fixed #{port} Shell request with banner checking disabled twice") { ssh_refuse_shell(port) }
  end

  it('uses real bypass proof for a versionless libssh banner twice') { ssh_execute(2226, allowed: true) }
  it('honors the default refusal of a custom banner twice') { ssh_execute(2227, allowed: false) }
  it('uses real bypass proof when banner checking is disabled twice') { ssh_execute(2227, allowed: true, check_banner: false) }
  it('does not claim command execution through the application guard twice') { ssh_execute(2228, allowed: false) }
  it('handles an unrelated SMTP service twice') { ssh_execute(2525, allowed: false) }
  it('handles a refused connection twice') { ssh_execute(1, allowed: false) }

  it 'keeps repeated vulnerability reports distinct for two services on one host' do
    ssh_execute(2222, allowed: true)
    ssh_execute(2224, allowed: true)
    rows = ssh_reports
    expect(rows.length).to eq(2)
    expected = [2222, 2224].map do |port|
      { 'address' => target_runtime.fetch('module_endpoints').fetch('target').fetch('host'), 'port' => port, 'proto' => 'tcp', 'service_name' => 'ssh' }
    end
    expect(rows.map { |row| row.slice('address', 'port', 'proto', 'service_name') }).to match_array(expected)
    expect(rows.map { |row| row.fetch('service_id') }).to all(be_a(Integer))
    expect(rows.map { |row| row.fetch('service_id') }.uniq.length).to eq(2)
  end
end
