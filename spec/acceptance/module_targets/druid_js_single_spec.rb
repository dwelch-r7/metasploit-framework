require 'acceptance_spec_helper'
require 'shellwords'
require 'rex/parser/arguments'
require 'rex/proto/http/packet'
require 'rex/proto/http/packet/header'
require 'rex/proto/http/request'
require 'timeout'
require_relative '../../../test/module_targets/druid_js_single/acceptance_helpers'

role = ENV.fetch('DRUID_SINGLE_ROLE', 'affected')
raise ArgumentError, "Unknown single Druid role: #{role}" unless %w[affected fixed].include?(role)

RSpec.describe 'Native single-version Druid JS targets' do
  include_context 'module target'
  include_context 'wait_for_expect'
  include DruidSingleAcceptance

  before(:all) do
    output, error, status = Open3.capture3('python3', '-B', 'test/module_targets/druid_js_single/native_probe.py')
    File.write(artifact('native-single-status.json'), JSON.pretty_generate(exitstatus: status.exitstatus, stderr: error))
    expect(status.success?).to be(true), error
    @native = JSON.parse(output)
    expect(@native.fetch('role')).to eq(role)
    expect(@native.fetch('version')).to eq(role == 'affected' ? '0.20.0' : '0.20.1')
    expect(@native.fetch('counts')).to eq('commands' => role == 'affected' ? 32 : 26, 'requests' => 17)
    target_runtime.fetch('module_endpoints').merge!(JSON.parse(File.read(artifact('native-endpoints.json'))).fetch('module_endpoints'))
    installed = console_command("irb -e 'load \"test/module_targets/druid/input_audit.rb\"; puts \"DRUID_CATALOG=\" + DruidTargetInputs.install(framework, \"#{listener_host}\").to_json'")
    catalog = JSON.parse(installed[/DRUID_CATALOG=(\{.*\})/, 1])
    @command_target = catalog.fetch(owner).fetch('command_target')
    expect(catalog.fetch(owner).fetch('generic_in_compatible_list')).to be(true)
    expect(catalog.fetch(owner).fetch('callback_host')).to eq(listener_host)
    observer = console_command("irb -e 'load \"test/module_targets/druid_js_single/socket_observer.rb\"; puts \"DRUID_OBSERVER=\" + DruidSingleSocketObserver.install(framework).to_json'")
    expect(JSON.parse(observer[/DRUID_OBSERVER=(\{.*\})/, 1])).to include('installed' => true)
    endpoint = target_runtime.fetch('module_endpoints').fetch('app')
    calibrated = console_command("irb -e 'puts \"DRUID_CALIBRATION=\" + DruidSingleSocketObserver.calibrate(\"#{endpoint.fetch('host')}\", #{endpoint.fetch('port')}).to_json'")
    actual = JSON.parse(calibrated[/DRUID_CALIBRATION=(\{.*\})/, 1])
    expect(actual).to eq('status' => 200, 'rows' => @native.fetch('expected_names'), 'errors' => [])
    @intended_commands = []
    verify_socket_rows('calibration')
  end

  before do |example|
    @case_id = example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command('sessions -l')).to include('No active sessions')
    expect(console_command('jobs -l')).to include('No active jobs')
    prove_ports_removed
    @before_files = target_files
    @intended_commands = []
    started = console_command("irb -e 'puts \"DRUID_OBSERVER_STATE=\" + DruidSingleSocketObserver.begin_case(\"#{@case_id}\").to_json'")
    expect(JSON.parse(started[/DRUID_OBSERVER_STATE=(\{.*\})/, 1]).fetch('errors')).to eq([])
  end

  after do |example|
    if [Acceptance::ChildProcessRecvError, Acceptance::ChildProcessTimeoutError, Timeout::Error, EOFError, Errno::EPIPE].any? { |type| example.exception.is_a?(type) }
      @console_broken = true
      RSpec.world.wants_to_quit = true
    end
    begin
      verify_socket_rows(@case_id) unless @console_broken
    ensure
      if @before_files
        console_command('jobs -K') unless @console_broken
        console_command('sessions -K') unless @console_broken
        restore_files
        prove_ports_removed unless @console_broken
        @before_files = nil
      end
    end
  end

  {
    'direct affected endpoint' => ['app', {}, true],
    'genuine proxy prefix' => ['gateway', { 'TARGETURI' => '/prefix/' }, true],
    'valid HTTP Basic frontend' => ['gateway', { 'TARGETURI' => '/auth/', 'HttpUsername' => 'admin', 'HttpPassword' => 'module-target-druid-password' }, true],
    'fixed release' => ['app', {}, false],
    'missing HTTP credentials' => ['gateway', { 'TARGETURI' => '/auth/' }, false],
    'wrong HTTP password' => ['gateway', { 'TARGETURI' => '/auth/', 'HttpUsername' => 'admin', 'HttpPassword' => 'wrong' }, false],
    'authenticated denied frontend role' => ['gateway', { 'TARGETURI' => '/denied/', 'HttpUsername' => 'viewer', 'HttpPassword' => 'module-target-viewer-password' }, false],
    'missing application path' => ['app', { 'TARGETURI' => '/module-target-no-druid/' }, false],
    'unrelated genuine Apache HTTP' => ['unrelated', {}, false]
  }.select { |label, _value| role == 'fixed' ? label == 'fixed release' : label != 'fixed release' }.each do |label, (service, options, positive)|
    it "checks #{label} twice without a false positive", capture_expected: positive do
      2.times do
        output = invoke(service, options, action: 'check', allow_errors: true)
        if positive
          expect(output).to include('The target is vulnerable')
        else
          expect(output).not_to include('The target is vulnerable', 'The target appears to be vulnerable')
        end
        expect(target_files).to eq(@before_files)
        prove_ports_removed
      end
    end
  end

  if role == 'affected'
    {
      'plain command' => ['app', 'plain-command', {}],
      'quoted characters' => ['app', %(Double " and single ' : spaces), {}],
      'literal backslashes' => ['app', 'backslash\\t\\path', {}],
      'delimiter text' => ['app', 'before`@~after', {}],
      'authenticated prefixed command' => ['gateway', 'authenticated-command', { 'TARGETURI' => '/auth/', 'HttpUsername' => 'admin', 'HttpPassword' => 'module-target-druid-password' }]
    }.each do |label, (service, bytes, options)|
      it "executes #{label} twice with exact bytes and independent cleanup", capture_expected: true do
        2.times do |iteration|
          path = "/tmp/module-target-druid-command-#{@case_id}-#{iteration}"
          expect(target_exec('app', 'test', '!', '-e', path)).to eq('')
          command = label == 'plain command' ? "printf${IFS}%s${IFS}#{bytes}>#{path}" : "printf '%s' #{Shellwords.escape(bytes)} > #{path}"
          expect(command).not_to include("\n")
          native_command_proof(command, path, bytes)
          output = invoke(service, generic_options(command).merge(options), allow_errors: true)
          prove_executing_input(command)
          begin
            wait_for_expect(20, 0.1) { expect(target_exec('app', 'sh', '-c', 'if test -f "$1"; then cat "$1"; fi', 'sh', path)).to eq(bytes) }
            expect(target_exec('app', 'stat', '-c', '%u:%g', path).strip).to eq('1000:1000')
            expect(output).not_to include('[-]')
          ensure
            capture_created_files
          end
          restore_files
        end
      end
    end

    it 'executes a quiet command twice even when its stdout is empty', capture_expected: true do
      2.times do |iteration|
        path = "/tmp/module-target-druid-empty-#{@case_id}-#{iteration}"
        command = ": > #{path}"
        native_command_proof(command, path, '')
        output = invoke('app', generic_options(command), allow_errors: true)
        prove_executing_input(command)
        wait_for_expect(20, 0.1) { expect(target_exec('app', 'sh', '-c', 'if test -f "$1"; then printf present; else printf absent; fi', 'sh', path)).to eq('present') }
        expect(target_exec('app', 'stat', '-c', '%u:%g:%s', path).strip).to eq('1000:1000:0')
        expect(output).not_to include('[-]')
        capture_created_files
        restore_files
      end
    end
  end
end

# Stop after console transport loss so later case labels cannot be misclassified.
module DruidSingleConsoleGuard
  def format_datastore_options(datastore)
    return super unless datastore.key?('CMD')

    command = datastore.fetch('CMD')
    rendered = "CMD=#{Shellwords.escape(command)}"
    expect(Rex::Parser::Arguments.from_s(rendered)).to eq(["CMD=#{command}"])
    "#{super(datastore.except('CMD'))} #{rendered}"
  end

  def console_command(command, timeout: 40)
    raise Acceptance::ChildProcessTimeoutError, 'Console transport failed; Druid diagnostic stopped' if @console_broken

    super
  rescue Acceptance::ChildProcessTimeoutError, Acceptance::ChildProcessRecvError, EOFError, Errno::EPIPE
    @console_broken = true
    RSpec.world.wants_to_quit = true
    raise
  end
end

RSpec.world.example_groups.find { |group| group.description == 'Native single-version Druid JS targets' }.prepend(DruidSingleConsoleGuard)
