# frozen_string_literal: true

RSpec.shared_examples 'openDCIM native-gated Linux dropper' do
  include_context 'module target'

  before(:all) do
    @rc = { commands: [], native: [], calls: [], http: [], states: [], attempts: [], calibrated: [] }
  end

  before do |example|
    skip 'Native openDCIM readiness failed; module verdict withheld' unless example.metadata[:native] || @rc[:dropper_prepared]

    if @rc[:prepared]
      @baseline, @listener_host, @ready = @rc.fetch(:session_context).values_at(:baseline, :listener_host, :ready)
      @dropper_directory = @rc.fetch(:dropper_directory)
      @workspace = 'opendcim_' + example.metadata.fetch(:scoped_id).tr(':', '_')
      expect(console_command('workspace -a ' + @workspace)).not_to include('[-]')
      idle
      dropper_empty
    end
  end

  it 'calibrates actual SQL/exec and the UID 33 callback route', native: true do
    dropper_ready
  end

  it 'uses and closes the independently launched stock native ELF session' do
    native_session(session_families.keys.fetch(0))
  end

  it 'uses the real dropper twice and verifies normal stager cleanup' do
    skip 'Native architecture/session readiness failed; owner verdict withheld' unless @rc.fetch(:calibrated).include?(session_families.keys.fetch(0))

    owner_session(session_families.keys.fetch(0))
  end

  after do |example|
    if @rc[:prepared]
      settled
      od_registry
      dropper_empty if @dropper_directory
    end
  rescue StandardError, RSpec::Expectations::ExpectationNotMetError
    RSpec.world.wants_to_quit = true
    raise unless example.exception
  end

  after(:all) do
    if @rc[:readiness]
      rc_resources('after')
      @rc[:restored] = od_native('after')
      expect(@rc.fetch(:restored)).to include('restored' => true, 'preserved' => true, 'tables_unchanged' => true)
    end
    if @rc[:dropper_directory]
      rc_command('remove-dropper-directory', 'target', 'rmdir', '--', @rc.fetch(:dropper_directory))
      _, status = rc_command('dropper-directory-absent', 'target', 'test', '-e', @rc.fetch(:dropper_directory), required: false)
      expect(status).to eq(1)
    end
  ensure
    rc_save
  end
end
