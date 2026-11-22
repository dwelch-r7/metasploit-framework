# frozen_string_literal: true

require_relative '../linuxki_sessions/acceptance'

# Reuse the actual handler prototype, then isolate fresh owner selection.
module LinuxkiBootstrapControls
  include LinuxkiSessions

  def ls_session_options
    { 'SessionTlvLogging' => 'file:' + File.join(target_runtime.fetch('artifacts'), 'session-tlv.log') }
  end

  def ls_select_handler
    if @rc[:reuse_stock_handler] && @rc[:stock_handler_selected]
      expect(rc_json('active_module.object_id')).to eq(@rc.fetch(:stock_handler_selected))
      return
    end
    super
    @rc[:stock_handler_selected] = rc_json('active_module.object_id')
  end

  def lb_ready
    ls_ready
    @rc[:ordinary_runtime] = rc_json("begin;load 'test/module_targets/linuxki_php_sessions/runtime_identity.rb';LinuxkiPhpRuntimeIdentity.capture(#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:bootstrap_observer] = rc_json("begin;load 'test/module_targets/linuxki_unix_bootstrap_controls/observe.rb';LinuxkiBootstrapObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    expect(@rc.fetch(:ordinary_runtime)).to include('packaged_runtime_digest_valid' => true, 'local_override' => false)
    @rc[:ordinary_runtime_verified] = true
    rc_save
  end
end
