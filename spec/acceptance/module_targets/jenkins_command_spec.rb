require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Native Jenkins command scanner targets' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/jenkins_command/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-jenkins-command.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-jenkins-command-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native = JSON.parse(stdout).fetch('profiles').fetch('open')
  end

  it 'prints the actual target account on consecutive anonymous commands' do
    2.times do
      output = scan('open', '/usr/bin/id -un')
      expect(output).to match(/\[\+\].* #{Regexp.escape(@native.fetch('account'))}\r?$/)
    end
  end

  it 'creates a fresh target file twice with native owner proof and explicit operator cleanup' do
    path = '/tmp/module-target-jenkins-command-proof'
    begin
      2.times do
        target_exec('open', 'test', '!', '-e', path)
        scan('open', "/usr/bin/touch #{path}")
        expect(target_exec('open', 'stat', '-c', '%U', path).strip).to eq(@native.fetch('account'))
        target_exec('open', 'rm', path)
      end
    ensure
      target_exec('open', 'rm', '-f', path)
    end
  end

  it 'preserves literal quotes, backslashes, ampersands and output-marker text' do
    expected = @native.fetch('literal')
    expect(scan('open', "/usr/bin/printf %s #{expected}")).to include(expected)
  end

  it 'preserves a literal HTML entity and marker-like text in the command output' do
    expected = @native.fetch('entities')
    expect(scan('open', "/usr/bin/printf %s #{expected}")).to include(expected)
  end

  it 'preserves native Unicode and literal dollar text through the actual console and Groovy path' do
    expected = @native.fetch('unicode')
    output = scan('open', "/usr/bin/printf %s #{expected}").dup.force_encoding(Encoding::UTF_8)
    expect(output.valid_encoding?).to be(true)
    expect(output).to include(expected)
  end

  it 'reports an actual missing executable without presenting it as command output' do
    output = scan('open', '/module-target-no-command', allow_errors: true)
    expect(output).to include('No such file or directory')
    expect(output).not_to include('[+]')
  end

  it 'does not execute the command on a controller that requires authentication' do
    path = '/tmp/module-target-jenkins-denied-command'
    target_exec('secured', 'test', '!', '-e', path)
    output = scan('secured', "/usr/bin/touch #{path}", allow_errors: true)
    expect(output).to match(/requires authentication|Access .* denied/i)
    expect(output).not_to include('[+]')
    expect(target_exec('secured', 'test', '!', '-e', path)).to eq('')
  end

  it 'does not execute or identify unrelated actual HTTP as Jenkins' do
    output = scan('unrelated', '/usr/bin/id -un', allow_errors: true)
    expect(output).to include('not running Jenkins-CI')
    expect(output).not_to include('[+]')
  end

  def scan(service, command, allow_errors: false)
    run_target_module('auxiliary/scanner/http/jenkins_command', service, { 'SSL' => false, 'TARGETURI' => '/jenkins/', 'COMMAND' => command, 'THREADS' => 1 }, allow_errors: allow_errors)
  end
end
