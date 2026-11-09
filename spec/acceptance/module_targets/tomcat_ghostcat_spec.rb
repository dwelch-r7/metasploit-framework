require 'acceptance_spec_helper'
require 'base64'

RSpec.describe 'Native Tomcat Ghostcat file-read targets' do
  include_context 'module target'

  before(:all) do
    argv = ['python3', 'test/module_targets/tomcat_ghostcat/native_probe.py']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-ghostcat.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-ghostcat-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native = JSON.parse(stdout).fetch('profiles')
  end

  it 'checks a genuinely readable private file on the affected release' do
    expect(read_file('vulnerable', 'short', action: 'check')).to include('Successfully read file /WEB-INF/short.txt')
  end

  %w[fixed unrelated].each do |service|
    it "does not identify #{service} as a successful private-file read" do
      output = read_file(service, 'short', action: 'check')
      expect(output).not_to include('Successfully read file', 'target appears to be vulnerable')
      expect(output).to match(/target is not exploitable|cannot reliably check|check failed|Unknown/i)
    end
  end

  it 'does not identify the actual missing included resource as readable' do
    output = read_file('vulnerable', 'module-target-missing', action: 'check')
    expect(output).not_to include('Successfully read file')
    expect(output).to include('Target did not return a valid Ghostcat response')
  end

  it 'stores exact private short-file bytes on two consecutive reads' do
    2.times { expect(loot(read_file('vulnerable', 'short'))).to eq(native_file('short')) }
  end

  it 'reads the actual WEB-INF descriptor used by the default FILENAME' do
    output = run_target_module('auxiliary/admin/http/tomcat_ghostcat', 'vulnerable', { 'FILENAME' => '/WEB-INF/web.xml' })
    expect(loot(output)).to eq(native_file('webxml'))
  end

  %w[large empty unicode binary].each do |name|
    it "stores exact native #{name} file bytes" do
      expect(loot(read_file('vulnerable', name))).to eq(native_file(name))
    end
  end

  { 'fixed' => 'short', 'vulnerable' => 'module-target-missing', 'unrelated' => 'short' }.each do |service, name|
    it "does not store error-page or invented file loot for #{service}/#{name}" do
      output = read_file(service, name)
      expect(output).to match(/Unable to read file|Received unknown AJP prefix/)
      expect(output).not_to include('File contents save to:')
    end
  end

  def read_file(service, name, action: 'run')
    run_target_module('auxiliary/admin/http/tomcat_ghostcat', service, { 'FILENAME' => "/WEB-INF/#{name}.txt" }, action: action, allow_errors: true)
  end

  def native_file(name)
    Base64.strict_decode64(@native.fetch('vulnerable').fetch('files').fetch(name))
  end

  def loot(output)
    paths = output.scan(/File contents save to: ([^\r\n]+)/).flatten.map(&:strip)
    expect(paths.size).to eq(1), output
    expect(File.expand_path(paths.first)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
    File.binread(paths.first)
  end
end
