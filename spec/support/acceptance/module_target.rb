# frozen_string_literal: true

require 'json'
require 'open3'

RSpec.shared_context 'module target' do
  include Acceptance::DatastoreFormatting

  let_it_be(:target_runtime) do
    JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
  end
  let_it_be(:driver) { Acceptance::ConsoleDriver.new }
  let_it_be(:console) do
    instance = driver.open_console
    instance.sendline(%q{irb -e 'puts "MODULE_TARGET_CONFIG=" + Msf::Config.config_directory'})
    output = instance.recvuntil(Acceptance::Console.prompt)
    expected = "MODULE_TARGET_CONFIG=#{ENV.fetch('MSF_CFGROOT_CONFIG')}"
    raise "Console configuration isolation failed: #{output}" unless output&.include?(expected)

    instance
  end

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

  def target_exec(service, *arguments, expected_exit: 0)
    output, status = Open3.capture2e(*target_runtime.fetch('compose'), 'exec', '-T', service, *arguments)
    raise "Fixture command failed: #{service} #{arguments.inspect}: #{output}" unless status.exitstatus == expected_exit

    output
  end

  def console_command(command, timeout: 40)
    console.sendline(command)
    output = console.recvuntil(Acceptance::Console.prompt, timeout: timeout)
    raise "Console exited during #{command.inspect}" unless output

    output.gsub(/\e\[[0-9;]*m/, '')
  end

  def run_target_module(fullname, service, options = {}, action: 'run', allow_errors: false)
    endpoint = target_endpoint(service)
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
    datastore = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'VERBOSE' => true }.merge(options)
    output = console_command("#{action} #{format_datastore_options(datastore)}")
    expect(output).not_to match(/Exception|undefined method|Unknown command|Msf::OptionValidateError/)
    expect(output).not_to include('[-]') unless allow_errors
    expect(output).to include('Auxiliary module execution completed') if action == 'run' && fullname.start_with?('auxiliary/')
    output
  end
end
