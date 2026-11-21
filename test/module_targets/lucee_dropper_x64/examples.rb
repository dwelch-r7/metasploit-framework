# frozen_string_literal: true

RSpec.shared_examples 'Lucee native-gated Linux dropper sessions' do
  include_context 'module target'

  before(:all) do
    @rc = { commands: [], native: [], http: [], calls: [], controls: [], states: [], attempts: [], calibrated: [] }
    @native = native_verify('before')
    rc_resources('before')
    rc_command('native-decoder-tools', 'target', 'sh', '-c', 'for tool in bash which base64 chmod rm; do command -v "$tool" || exit 1; done')
    path = '/tmp/module-target-lucee-dropper-readiness'
    native_control('printf dropper-readiness > ' + path, path, 'dropper-readiness')
    native_image_write
    @dropper_directory = "/tmp/module-target-lucee-dropper-#{Process.pid}-#{dropper_arch}"
    expect(file(@dropper_directory)).to eq('exists' => false)
    rc_command('create-dropper-directory', 'target', 'mkdir', '-m', '700', @dropper_directory)
    dropper_directory_empty
    @baseline = process_state
    callback_control
    endpoint = target_endpoint('reporting_db')
    expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    @ready = rc_json("begin;load 'test/module_targets/druid_sessions/session_control.rb';load 'test/module_targets/lucee_bash/session_control.rb';load 'test/module_targets/saltstack_deployer/session_control.rb';DruidSessionControl.install(framework);end")
    @rc[:runtime] = rc_json("{ruby:RUBY_VERSION,payload_gems:Gem.loaded_specs.select{|name,_|name.include?('payload')}.transform_values{|spec|spec.version.to_s}}")
    @rc[:observer] = rc_json("begin;load 'test/module_targets/lucee/observe.rb';LuceeObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:lifecycle_observer] = rc_json("begin;load 'test/module_targets/lucee_bash/observe.rb';LuceeLifecycleObservation.install(framework,#{target_runtime.fetch('artifacts').inspect},#{target_runtime.fetch('compose').inspect});end")
    @rc[:dropper_observer] = rc_json("begin;load 'test/module_targets/lucee_dropper_x64/observe.rb';LuceeDropperObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
  end

  before do |example|
    @workspace = 'lucee_' + example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command('workspace -a ' + @workspace)).not_to include('[-]')
    idle
    dropper_directory_empty
  end

  it 'uses and closes the stock independently launched native ELF session' do
    native_session(session_families.keys.fetch(0))
  end

  it 'uses the actual Linux dropper, verifies cleanup and repeats' do
    skip 'Native ELF readiness failed; owner execution withheld' unless @rc[:calibrated].include?(session_families.keys.fetch(0))

    owner_session(session_families.keys.fetch(0))
  end

  after do |example|
    settled
    dropper_directory_empty
  rescue RSpec::Expectations::ExpectationNotMetError, StandardError
    RSpec.world.wants_to_quit = true
    raise unless example.exception
  end

  after(:all) do
    expect(native_verify('after')).to eq(@native)
    rc_resources('after')
    dropper_directory_empty if @dropper_directory
  ensure
    primary = $ERROR_INFO
    begin
      if @dropper_directory
        rc_command('remove-dropper-directory', 'target', 'rmdir', '--', @dropper_directory)
        _, status = rc_command('dropper-directory-absent', 'target', 'test', '-e', @dropper_directory, required: false)
        expect(status).to eq(1)
      end
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      (@rc[:cleanup_errors] ||= []) << { type: e.class.name, message: e.message }
      raise unless primary
    ensure
      rc_save
    end
  end
end
