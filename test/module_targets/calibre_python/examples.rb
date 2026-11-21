# frozen_string_literal: true

require_relative '../calibre/observe'

RSpec.shared_examples 'Calibre native-gated sessions' do
  include_context 'module target'

  before(:all) do
    @rc = { commands: [], native: [], http: [], calls: [], controls: [], states: [], attempts: [], calibrated: [] }
    @native = native_verify('before')
    expect(http('/').code).to eq('200')
    rc_resources('before')
    path = '/tmp/module-target-calibre-session-readiness'
    native_control('printf session-readiness > ' + path, path, 'session-readiness')
    @baseline = process_state
    expect(@baseline.fetch('connections')).to eq([])
    callback_control
    endpoint = target_endpoint('reporting_db')
    expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    @ready = rc_json("begin;load 'test/module_targets/druid_sessions/session_control.rb';load 'test/module_targets/calibre_python/session_control.rb';DruidSessionControl.install(framework);end")
    @rc[:runtime] = rc_json("{ruby:RUBY_VERSION,metasploit_payloads:Gem.loaded_specs['metasploit-payloads'].version.to_s,python_stage_sha256:Digest::SHA256.hexdigest(MetasploitPayloads.read('meterpreter','meterpreter.py'))}")
    @rc[:observer] = rc_json("begin;load 'test/module_targets/calibre/observe.rb';CalibreObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
  end

  before do |example|
    @workspace = 'calibre_' + example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command('workspace -a ' + @workspace)).not_to include('[-]')
    idle
  end

  it 'uses and closes the stock independent session' do
    native_session(session_families.keys.fetch(0))
  end

  it 'uses and closes the real owner session and repeats' do
    skip 'Native readiness failed; owner execution withheld' unless @rc[:calibrated].include?(session_families.keys.fetch(0))

    owner_session(session_families.keys.fetch(0))
  end

  after do |example|
    settled
  rescue RSpec::Expectations::ExpectationNotMetError, StandardError
    RSpec.world.wants_to_quit = true
    raise unless example.exception
  end

  after(:all) do
    expect(native_verify('after')).to eq(@native)
    expect(http('/').code).to eq('200')
    rc_resources('after')
  ensure
    rc_save
  end
end
