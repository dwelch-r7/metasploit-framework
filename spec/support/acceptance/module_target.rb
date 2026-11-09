# frozen_string_literal: true

require 'json'
require 'open3'
require 'base64'

RSpec.shared_context 'module target' do
  include Acceptance::DatastoreFormatting

  let_it_be(:target_runtime) do
    JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
  end
  let_it_be(:driver) { Acceptance::ConsoleDriver.new(console_command: target_runtime['console_command']) }
  let_it_be(:console) { driver.open_console }

  after(:all) do
    driver.close
    ObjectSpace.undefine_finalizer(driver)
  end

  after do |example|
    path = File.join(target_runtime.fetch('artifacts'), "example-#{example.id.gsub(/[^a-zA-Z0-9_-]/, '_')}.log")
    File.write(path, console.all_data)
    console.reset
  end

  def target_endpoint(service)
    target_runtime.fetch('endpoints').fetch(service)
  end

  def listener_host
    target_runtime.fetch('listener_host')
  end

  def target_exec(service, *arguments, expected_exit: 0)
    output, status = Open3.capture2e(*target_runtime.fetch('compose'), 'exec', '-T', service, *arguments)
    text = output.dup.force_encoding(Encoding::UTF_8)
    encoding = text.valid_encoding? ? 'utf-8' : 'base64'
    recorded_output = encoding == 'utf-8' ? text : Base64.strict_encode64(output)
    File.open(File.join(target_runtime.fetch('artifacts'), 'native-commands.jsonl'), 'a') do |log|
      log.puts(JSON.generate(service: service, argv: arguments, exitstatus: status.exitstatus, output_encoding: encoding, output: recorded_output))
    end
    raise "Fixture command failed: #{service} #{arguments.inspect} (#{encoding} output): #{recorded_output}" unless status.exitstatus == expected_exit

    output
  end

  def console_command(command, timeout: 40)
    console.sendline(command)
    output = console.recvuntil(Acceptance::Console.prompt, timeout: timeout)
    raise "Console exited during #{command.inspect}" unless output

    output.gsub(/\e\[[0-9;]*m/, '')
  end

  def run_target_module(fullname, service, options = {}, action: 'run', allow_errors: false, endpoint_options: nil, command_timeout: 40)
    endpoint = target_runtime.fetch('module_endpoints', target_runtime.fetch('endpoints')).fetch(service)
    console_command('back')
    selected = console_command("use #{fullname}")
    expect(selected).not_to match(/Failed to load|Unknown command|No results/)
    # Select the payload before passing payload-specific run options such as CMD.
    # Otherwise the console validates those options against the default payload.
    %w[TARGET PAYLOAD].each do |name|
      next unless options.key?(name)

      configured = console_command("set #{name} #{options.fetch(name)}")
      expect(configured).not_to match(/Failed|Invalid|not found/)
    end
    # Some modules select servers through NS/RHOST rather than RHOSTS/RPORT.
    # Supply only registered endpoint options so console validation stays real.
    endpoint_values = endpoint_options || { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port') }
    datastore = endpoint_values.merge('VERBOSE' => true).merge(options)
    output = console_command("#{action} #{format_datastore_options(datastore)}", timeout: command_timeout)
    expect(output).not_to match(/Exception|undefined method|Unknown command|Msf::OptionValidateError/)
    expect(output).not_to include('[-]') unless allow_errors
    expect(output).to include('Auxiliary module execution completed') if action == 'run' && fullname.start_with?('auxiliary/')
    output
  end
end
