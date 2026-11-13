require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/freeswitch_batch/acceptance'

RSpec.describe 'Genuine FreeSWITCH multi-host authentication', acceptance: true, order: :defined do
  include_context 'module target'
  include Acceptance::FreeSwitchBatch

  before(:all) do
    @batch_mode = ENV.fetch('FREESWITCH_BATCH_MODE')
    batch_native_phase('before')
    @state = batch_state
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
    expect(batch_state).to eq(@state)
    %w[sessions jobs].each do |kind|
      expect(console_command("irb -e 'puts \"FS_BATCH_IDLE=\" + framework.#{kind}.keys.to_json'")).to include('FS_BATCH_IDLE=[]')
    end
  end

  after(:all) do
    batch_native_phase('after') if @native_ready
    %w[target second reporting_db framework].each do |role|
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/memory.events')).to include("max 0\n", "oom 0\n", "oom_kill 0\n")
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end

  if ENV['FREESWITCH_BATCH_MODE'] == 'same'
    it 'authenticates both hosts in a public space-separated batch twice' do
      batch_verify(successes: { 'target' => 'ClueCon', 'second' => 'ClueCon' }, attempts: { 'target' => ['ClueCon'], 'second' => ['ClueCon'] })
    end

    it 'authenticates both hosts with AutoCheck disabled twice' do
      batch_verify(options: { 'AutoCheck' => false }, successes: { 'target' => 'ClueCon', 'second' => 'ClueCon' }, attempts: { 'target' => ['ClueCon'], 'second' => ['ClueCon'] })
    end

    it 'checks both genuine service fingerprints without sending credentials twice' do
      batch_verify(action: 'check', attempts: { 'target' => [], 'second' => [] })
    end

    it 'authenticates both hosts loaded from a host file twice' do
      batch_verify(host_file: true, successes: { 'target' => 'ClueCon', 'second' => 'ClueCon' }, attempts: { 'target' => ['ClueCon'], 'second' => ['ClueCon'] })
    end

    it 'keeps both concurrent workers credentials and state distinct twice' do
      batch_verify(options: { 'THREADS' => 2 }, successes: { 'target' => 'ClueCon', 'second' => 'ClueCon' }, attempts: { 'target' => ['ClueCon'], 'second' => ['ClueCon'] })
    end

    it 'continues to the healthy host after a native-proven refused endpoint twice' do
      batch_verify(%w[refused target], successes: { 'target' => 'ClueCon' }, attempts: { 'refused' => [], 'target' => ['ClueCon'] })
    end
  elsif ENV['FREESWITCH_BATCH_MODE'] == 'passwords'
    it 'persists only the host accepting the explicit password twice' do
      batch_verify(successes: { 'target' => 'ClueCon' }, attempts: { 'target' => ['ClueCon'], 'second' => ['ClueCon'] })
    end

    it 'keeps the result identical when the rejected-password host is first twice' do
      batch_verify(%w[second target], successes: { 'target' => 'ClueCon' }, attempts: { 'target' => ['ClueCon'], 'second' => ['ClueCon'] })
    end

    it 'preserves mixed-password results with AutoCheck disabled twice' do
      batch_verify(options: { 'AutoCheck' => false }, successes: { 'target' => 'ClueCon' }, attempts: { 'target' => ['ClueCon'], 'second' => ['ClueCon'] })
    end

    it 'finds each hosts distinct password from one bounded file twice' do
      path = File.join(target_runtime.fetch('artifacts'), 'batch-passwords.txt')
      File.write(path, "module-target-wrong-password\nClueCon\nmodule-target-Ω spaced\nmodule-target-after-success\n")
      batch_verify(options: { 'PASSWORD' => '', 'PASS_FILE' => path }, successes: { 'target' => 'ClueCon', 'second' => 'module-target-Ω spaced' }, attempts: { 'target' => ['module-target-wrong-password', 'ClueCon'], 'second' => ['module-target-wrong-password', 'ClueCon', 'module-target-Ω spaced'] })
    end

    it 'keeps distinct Unicode candidate results with two scanner workers twice' do
      path = File.join(target_runtime.fetch('artifacts'), 'batch-parallel-passwords.txt')
      File.write(path, "ClueCon\nmodule-target-Ω spaced\nmodule-target-after-success\n")
      batch_verify(options: { 'PASSWORD' => '', 'PASS_FILE' => path, 'THREADS' => 2 }, successes: { 'target' => 'ClueCon', 'second' => 'module-target-Ω spaced' }, attempts: { 'target' => ['ClueCon'], 'second' => ['ClueCon', 'module-target-Ω spaced'] })
    end
  else
    it 'continues past the ACL-rejected second host twice' do
      batch_verify(successes: { 'target' => 'ClueCon' }, attempts: { 'target' => ['ClueCon'], 'second' => [] })
    end

    it 'does not let an ACL-rejected first host cancel the healthy host twice' do
      batch_verify(%w[second target], successes: { 'target' => 'ClueCon' }, attempts: { 'target' => ['ClueCon'], 'second' => [] })
    end

    it 'still rejects ACL authentication when AutoCheck is disabled twice' do
      batch_verify(options: { 'AutoCheck' => false }, successes: { 'target' => 'ClueCon' })
    end

    it 'still rejects ACL authentication with ForceExploit enabled twice' do
      batch_verify(options: { 'ForceExploit' => true }, successes: { 'target' => 'ClueCon' })
    end

    it 'continues past a refused endpoint in a mixed ACL deployment twice' do
      batch_verify(%w[refused target second], successes: { 'target' => 'ClueCon' }, attempts: { 'refused' => [], 'target' => ['ClueCon'], 'second' => [] })
    end
  end
end
