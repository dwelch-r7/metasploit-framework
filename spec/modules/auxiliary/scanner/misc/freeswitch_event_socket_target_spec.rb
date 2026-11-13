require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/freeswitch/acceptance'

RSpec.describe 'Genuine FreeSWITCH event-socket authentication', acceptance: true, order: :defined do
  include_context 'module target'
  include Acceptance::FreeSwitch

  before(:all) do
    @mode = ENV.fetch('FREESWITCH_MODE')
    @password = ENV.fetch('FREESWITCH_PASSWORD')
    fs_native_phase('before')
    @state = fs_state
    expect(fs_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    @native_ready = true
  end

  before do |example|
    @workspace = "fs_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(fs_credentials).to eq([])
  end

  after do
    expect(fs_state).to eq(@state)
    %w[sessions jobs].each do |kind|
      expect(console_command("irb -e 'puts \"FS_IDLE=\" + framework.#{kind}.keys.to_json'")).to include('FS_IDLE=[]')
    end
  end

  after(:all) do
    fs_native_phase('after') if @native_ready
    %w[target reporting_db framework].each do |role|
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/memory.events')).to include("max 0\n", "oom 0\n", "oom_kill 0\n")
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end

  if ENV['FREESWITCH_MODE'] == 'allowed'
    it 'passively checks the genuine service twice without authentication' do
      fs_verify(action: 'check', attempts: [], check_reason: 'FreeSWITCH event socket is accepting authentication requests')
    end

    it 'stores the exact password-only credential twice with quiet success output' do
      fs_verify({ 'PASSWORD' => @password, 'VERBOSE' => false }, expected_password: @password, attempts: [@password])
    end

    it 'rejects the wrong password twice without saving a credential' do
      fs_verify({ 'PASSWORD' => 'module-target-wrong-password' }, attempts: ['module-target-wrong-password'])
    end

    it 'uses a bounded password file and stops after the first successful candidate twice' do
      file = File.join(target_runtime.fetch('artifacts'), 'candidate-passwords.txt')
      File.write(file, "module-target-wrong-password\n#{@password}\nmodule-target-after-success\n")
      fs_verify({ 'PASSWORD' => '', 'PASS_FILE' => file }, expected_password: @password, attempts: ['module-target-wrong-password', @password])
    end

    it 'prioritizes an explicit valid password over the candidate file twice' do
      file = File.join(target_runtime.fetch('artifacts'), 'unneeded-passwords.txt')
      File.write(file, "module-target-after-success\n")
      fs_verify({ 'PASSWORD' => @password, 'PASS_FILE' => file }, expected_password: @password, attempts: [@password])
    end

    it 'authenticates twice when AutoCheck is disabled' do
      fs_verify({ 'PASSWORD' => @password, 'AutoCheck' => false }, expected_password: @password, attempts: [@password])
    end

    it 'tries the public default password twice with the native-proven result' do
      fs_verify(expected_password: @password == 'ClueCon' ? 'ClueCon' : nil, attempts: ['ClueCon'])
    end

    it 'returns an honest unknown check for a native-proven refused port twice' do
      fs_verify({ 'RPORT' => 1 }, action: 'check', attempts: [], check_reason: 'Cannot reliably check exploitability.')
    end

    it 'handles refused-port AutoCheck twice without an exception or credential' do
      fs_verify({ 'RPORT' => 1, 'PASSWORD' => @password }, attempts: [])
    end
  elsif ENV['FREESWITCH_MODE'] == 'acl'
    it 'checks the actual ACL refusal twice without sending credentials' do
      fs_verify(action: 'check', attempts: [], check_reason: 'Access denied by network ACL')
    end

    it 'lets AutoCheck stop ACL-blocked runs twice without credentials' do
      fs_verify({ 'PASSWORD' => @password }, attempts: [], check_reason: 'Access denied by network ACL')
    end

    it 'does not report a valid password through the ACL when AutoCheck is disabled' do
      fs_verify({ 'PASSWORD' => @password, 'AutoCheck' => false })
    end

    it 'does not report a valid password through the ACL when ForceExploit is enabled' do
      fs_verify({ 'PASSWORD' => @password, 'ForceExploit' => true })
    end
  else
    it 'checks the real OpenSSH banner twice as an unidentified service' do
      fs_verify(action: 'check', attempts: [], check_reason: 'Unable to determine the service fingerprint')
    end

    it 'stops unrelated-service AutoCheck runs twice without sending credentials' do
      fs_verify({ 'PASSWORD' => @password }, attempts: [], check_reason: 'Unable to determine the service fingerprint')
    end

    it 'never reports the password as valid against OpenSSH with AutoCheck disabled' do
      fs_verify({ 'PASSWORD' => @password, 'AutoCheck' => false })
    end
  end
end
