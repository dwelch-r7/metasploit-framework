# frozen_string_literal: true

require_relative '../ignition/acceptance'
require_relative '../laravel/sessions'

# Match the HTTP worker identity and the owner's Unix target index.
module IgnitionSessions
  include IgnitionTarget
  include LaravelSessions

  FAMILIES = { 'bash-shell' => [0, 'cmd/unix/reverse_bash', 'shell'] }.freeze

  def session_families
    FAMILIES
  end

  def session_exec_options
    ['--user', 'www-data']
  end

  def session_default_options
    { 'bash-shell' => %w[TARGET PAYLOAD] }
  end

  def session_control_name
    'IgnitionSessionControl'
  end

  def session_health_path
    '/'
  end

  def use_session(family, attempt, owner)
    result = super
    return result unless owner == laravel_owner

    selected = rc_json('active_module.target_index')
    (@rc[:resolved_targets] ||= []) << selected
    expect(selected).to eq(0)
    # The synchronous system() gadget resumes after shell shutdown and its real
    # LazyOption then throws. Retain that IOC for the next owner to handle.
    state = rc_poll(5) do
      value = native('log', {}, 'owner-session-log')
      value if value.fetch('exists') && value.fetch('size').positive?
    end
    (@rc[:session_logs] ||= []) << { iteration: attempt.fetch(:iteration), state: state }
    expect(state).to include('uid' => laravel_uid)
    bytes = Base64.strict_decode64(state.fetch('base64'))
    expect(bytes.lines.first).to include('local.ERROR: Expected instance of PhpOption\\Option {"exception":')
    expect(bytes.scan('local.ERROR:').length).to eq(1)
    expect(bytes).to include('/var/www/vendor/phpoption/phpoption/src/PhpOption/LazyOption.php:164')
  ensure
    rc_save
  end
end
