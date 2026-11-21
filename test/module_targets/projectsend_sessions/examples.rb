# frozen_string_literal: true

require_relative 'acceptance'
require_relative 'console_recovery'

RSpec.shared_examples 'ProjectSend default Meterpreter sessions' do
  include_context 'module target'
  include ProjectsendSessions
  prepend ProjectsendConsoleRecovery

  before(:all) do
    @rc = { commands: [], calls: [], native: [], attempts: [], states: [], calibrated: [] }
  end

  before do |example|
    skip 'Console transport failed earlier; original failure retained' if pss_console_failure
    next if example.metadata[:native]

    skip 'Native application/callback readiness failed; module verdict withheld' unless @rc[:prepared]
    pss_restore_context
    skip 'Stock CLI/web session readiness failed; module verdict withheld' if example.metadata[:owner] && !@rc[:api_calibrated]
    idle
  end

  it 'installs the real application and proves the native UID1000 callback and reporting database', native: true do
    pss_ready
  end

  it 'uses and closes stock CLI and independently uploaded web Meterpreter sessions' do
    pss_cli_control
    pss_api_control
  end

  it 'uses and closes two original default sessions with AutoCheck on/off and one selection', owner: true do
    pss_owner
  end

  it 'preserves all options after each original default session', owner: true do
    pr_preservation
  end

  after(:all) do
    if @rc && @rc[:prepared] && !pss_console_failure
      pss_restore_context
      cleanup_session
    end
  ensure
    pss_assert_console_stopped
    pr_cleanup if @rc
  end
end
