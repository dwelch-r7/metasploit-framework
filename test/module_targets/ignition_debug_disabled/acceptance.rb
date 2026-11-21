# frozen_string_literal: true

require_relative '../ignition/acceptance'

# Calibrate the exact archive in the real PHP CLI before HTTP denial.
module IgnitionDebugDisabledTarget
  include IgnitionTarget

  def native_cli_phar(archive)
    program = "require '/var/www/vendor/autoload.php';file_get_contents($argv[1]);"
    command = target_runtime.fetch('compose') + ['exec', '-T', '--user', 'www-data', 'target', 'php', '-r', program, 'phar://' + archive + '/proof.txt']
    output, error, status = Open3.capture3(*command)
    @rc[:commands] << { label: 'native-cli-phar', argv: command, exit: status.exitstatus, stdout_base64: Base64.strict_encode64(output.b), stderr: error }
    rc_save
    # LazyOption executes system(), then rejects its non-Option return value.
    # The caller separately requires exact physical proof of that execution.
    expect(status.exitstatus).to eq(255)
    expect(output + error).to include('Expected instance of PhpOption\\Option')
  end
end
