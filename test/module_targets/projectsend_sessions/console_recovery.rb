# frozen_string_literal: true

require 'base64'
require 'json'

# Circuit-break only these opt-in profiles after losing the console transport.
# Module execution, payloads and successful command/reset behavior stay original.
module ProjectsendConsoleRecovery
  # Stop only once and reset saved output without using the failed transport.
  module FailedConsole
    def close
      return if @projectsend_closed

      @projectsend_closed = true
      if wait_thread&.alive?
        super
      else
        stdin.close if stdin && !stdin.closed?
        stdout_and_stderr.close if stdout_and_stderr && !stdout_and_stderr.closed?
      end
    end

    def reset
      # The shared after-example hook already saved all_data. A failed console
      # cannot accept sessions/jobs commands; clear its log locally instead.
      @all_data.reopen('')
    end
  end

  def pss_console_failure
    target_runtime['projectsend_console_failure']
  end

  def console_command(...)
    raise Acceptance::ChildProcessRecvError, 'ProjectSend console transport failed in an earlier example' if pss_console_failure

    super
  rescue Acceptance::ChildProcessRecvError, Acceptance::ChildProcessTimeoutError, Errno::EPIPE, IOError, RuntimeError => e
    # The shared command helper raises RuntimeError if the child exits. Keep
    # unrelated Ruby errors on a live transport outside this recovery path.
    raise if e.is_a?(RuntimeError) && console.alive?

    pss_abort_console(e) unless pss_console_failure
    raise
  end

  def cleanup_session
    return if pss_console_failure

    super
  end

  def pss_assert_console_stopped
    return unless pss_console_failure && console.wait_thread.alive?

    raise Acceptance::ChildProcessTimeoutError, 'ProjectSend console is still running; native fixture recovery would race its requests'
  end

  def pss_abort_console(error)
    child = console
    record = {
      'error_class' => error.class.name,
      'message' => error.message,
      'pid' => child.wait_thread.pid,
      'output_base64' => Base64.strict_encode64(child.all_data.b),
      'terminated' => false
    }
    target_runtime['projectsend_console_failure'] = record
    child.extend(FailedConsole)
    begin
      driver.close
      if child.wait_thread.join(10)
        record['terminated'] = true
        record['exitstatus'] = child.wait_thread.value.exitstatus
        record['termsig'] = child.wait_thread.value.termsig
      else
        record['cleanup_error'] = 'Console did not terminate within ten seconds'
      end
    rescue IOError, SystemCallError, ThreadError => e
      record['cleanup_error'] = { 'class' => e.class.name, 'message' => e.message }
    ensure
      @rc[:console_failure] = record if instance_variable_defined?(:@rc) && @rc
      begin
        File.write(File.join(target_runtime.fetch('artifacts'), 'console-failure.json'), JSON.pretty_generate(record))
        rc_save if respond_to?(:rc_save)
      rescue SystemCallError, IOError => e
        warn "Could not save ProjectSend console recovery evidence: #{e.message}"
      end
    end
  end
end
