# frozen_string_literal: true

require_relative '../langflow_execution/acceptance'

RSpec.shared_context 'langflow stored tool target' do
  include_context 'module target'
  include_context 'wait_for_expect'
  include Acceptance::LangflowExecution

  let(:owner_fullname) { 'exploit/multi/http/langflow_unauth_rce_cve_2026_10134' }

  def call_owner(options = {}, **kwargs)
    super({ 'FLOW_UUID' => '' }.merge(options), **kwargs)
  end

  def idle
    super
    expect(native("registry-#{@case}", action: 'registry')).to eq('flow_ids' => (@native.fetch('flow_ids') + Array(@staged_flow_id)).sort)
  end

  before(:all) do
    @native = native('before')
    poll(10) do
      @baseline = process_state
      expect(@baseline.fetch('connections')).to eq([])
      expect(@baseline.fetch('processes')).not_to include(include('state' => 'Z'))
    end
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    expect(console_command(%q{irb -e 'load "test/module_targets/langflow_execution/session_control.rb"; load "test/module_targets/druid_sessions/session_control.rb"; DruidSessionControl.install(framework); puts "LANGFLOW_CONTROL_READY"'})).to include('LANGFLOW_CONTROL_READY')
    @ready = true
  end

  before do |example|
    @case = example.metadata.fetch(:scoped_id).tr(':', '_')
    @workspace = "langflow_exec_#{@case}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    poll(10) { idle }
  end

  after do |example|
    poll(10) { idle }
  rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
    record('cleanup-errors.jsonl', error: e.class.name, message: e.message)
    RSpec.world.wants_to_quit = true
    raise if example.exception.nil?
  end

  after(:all) do
    if @ready
      begin
        expect(native('after')).to eq(@native)
      ensure
        expect(native('cleanup', action: 'cleanup')).to include('restored' => true)
      end
    end
    %w[target framework reporting_db].each do |role|
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/memory.events')).to include("oom 0\n", "oom_kill 0\n")
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end

  def existing_session_proof(payload, options = {})
    tag = "stage_#{@case}"
    settings = { 'LHOST' => listener_host, 'LPORT' => 4492 }.merge(options)
    encoded = rpc("framework.payloads.create(#{payload.inspect}).then { |candidate| candidate.datastore.merge!(#{settings.inspect}); Base64.strict_encode64(Msf::Simple::Payload.generate_simple(candidate, 'Format' => 'raw')) }")
    File.write(File.join(target_runtime.fetch('artifacts'), "preloaded-#{tag}.json"), JSON.generate(payload: payload, payload_base64: encoded))
    prepared = native(tag, action: 'stage')
    @staged_flow_id = prepared.fetch('flow_id')
    record('preloaded-flow-lifecycle.jsonl', phase: 'prepared', tag: tag, data: prepared)
    begin
      session_proof(payload, options.merge('FLOW_UUID' => @staged_flow_id, 'USERNAME' => '', 'PASSWORD' => ''))
    ensure
      removed = native(tag, action: 'unstage')
      expect(removed).to include('removed' => true, 'flow_id' => @staged_flow_id)
      record('preloaded-flow-lifecycle.jsonl', phase: 'removed', tag: tag, data: removed)
      @staged_flow_id = nil
    end
  end

  def trigger_existing(iteration, reuse: false)
    selected_path = "/tmp/module-target-langflow-own-#{@case}-known-#{iteration}"
    known_path = @native.fetch('known_marker_path')
    begin
      target_exec('target', 'test', '!', '-e', selected_path)
      target_exec('target', 'test', '!', '-e', known_path)
      output = call_owner({ 'FLOW_UUID' => @native.fetch('public_id'), 'USERNAME' => '', 'PASSWORD' => '', 'CMD' => "printf selected >> #{selected_path}" }, reuse: reuse)
      expect(output).not_to include('Exploit aborted', 'Exploit failed')
      captured = nil
      poll(10) do
        captured = target_exec('target', 'sh', '-c', 'if test -f "$1"; then cat "$1"; fi', 'stored-proof', known_path)
        expect(captured).to end_with("\n")
      end
      proof = JSON.parse(captured)
      expect(proof).to include('marker' => 'native-stored-tool', 'uid' => 1000)
      expect(target_exec('target', 'test', '!', '-e', selected_path)).to eq('')
      record('existing-flow-trigger-proofs.jsonl', flow_id: @native.fetch('public_id'), stored_code: proof, selected_marker_absent: true, selected_payload_delivery_proven: false)
    ensure
      target_exec('target', 'rm', '-f', '--', known_path, selected_path)
    end
  end
end
