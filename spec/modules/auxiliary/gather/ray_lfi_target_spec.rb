require 'acceptance_spec_helper'
require 'base64'
require_relative '../../../../tools/dev/run_module_target_tests'

version = ENV.fetch('MODULE_TARGET_RAY_VERSION', '2.6.3')
raise ArgumentError, 'Unsupported Ray LFI profile' unless %w[2.6.3 2.8.1].include?(version)

fixed = version == '2.8.1'

RSpec.describe 'Genuine Ray static file owner', acceptance: true do
  include_context 'module target'

  owner = 'auxiliary/gather/ray_lfi_cve_2023_6020'

  before(:all) do
    native_phase('before')
    @fixture = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), 'owner-fixtures.json')))
    @content = Base64.strict_decode64(@fixture.fetch('content_base64'))
  end

  after(:all) do
    native_phase('after') if @fixture
  end

  it "checks the genuine #{version} service as #{fixed ? 'safe' : 'vulnerable'}" do
    output = run_target_module(owner, 'ray', {}, action: 'check', allow_errors: fixed)
    if fixed
      expect(output).to include('The target is not exploitable.', "Ray version #{version} is not vulnerable")
    else
      expect(output).to include('The target is vulnerable.', "Ray #{version} - successfully read /etc/passwd")
    end
  end

  it "#{fixed ? 'refuses' : 'prints'} UTF8 content from a quoted path twice" do
    2.times { verify_file(owner, 'utf8', fixed: fixed) }
  end

  it "#{fixed ? 'refuses' : 'accepts'} a genuine zero-length file twice" do
    2.times { verify_file(owner, 'empty', fixed: fixed) }
  end

  it "#{fixed ? 'refuses' : 'preserves'} reserved characters, a literal percent escape and UTF8 twice" do
    2.times { verify_file(owner, 'reserved', fixed: fixed) }
  end

  it 'reports a genuinely absent file without printing fixture content' do
    output = run_target_module(owner, 'ray', { 'FILEPATH' => @fixture.fetch('paths').fetch('missing'), 'AutoCheck' => !fixed }, allow_errors: true)
    expect(output).to include('Failed to execute LFI')
    expect(output.b).not_to include(@content.b.strip)
  end

  it 'returns unknown on unrelated Apache content' do
    output = run_target_module(owner, 'unrelated', {}, action: 'check')
    expect(output).to include('Cannot reliably check exploitability.', 'No response or unexpected status from Ray API')
  end

  it 'honors automatic refusal on unrelated Apache content' do
    output = run_target_module(owner, 'unrelated', { 'FILEPATH' => @fixture.fetch('paths').fetch('utf8') }, allow_errors: true)
    expect(output).to include('Cannot reliably check exploitability.')
    expect(output.b).not_to include(@content.b.strip)
  end

  it(fixed ? 'honors automatic refusal on the genuine confined service' : 'reads without relying on check initialization') do
    if fixed
      output = run_target_module(owner, 'ray', { 'FILEPATH' => @fixture.fetch('paths').fetch('utf8') }, allow_errors: true)
      expect(output).to include('The target is not exploitable.')
      expect(output.b).not_to include(@content.b.strip)
    else
      output = run_target_module(owner, 'ray', { 'FILEPATH' => @fixture.fetch('paths').fetch('utf8'), 'AutoCheck' => false })
      expect(output.gsub("\r\n", "\n").b).to include(@content.b)
    end
  end

  def verify_file(owner, name, fixed:)
    path = @fixture.fetch('paths').fetch(name)
    options = { 'FILEPATH' => path }
    options['AutoCheck'] = false if fixed
    output = run_target_module(owner, 'ray', options, allow_errors: fixed)
    if fixed
      expect(output).to include('Failed to execute LFI')
      expect(output.b).not_to include(@content.b.strip)
    elsif name == 'empty'
      expect(output).to include(path)
      expect(output).not_to include('Failed to execute LFI')
    else
      expect(output.gsub("\r\n", "\n").b).to include(@content.b)
    end
  end

  def native_phase(phase)
    output = +''
    argv = ['python3', '-B', 'test/module_targets/ray/native_runtime.py', ENV.fetch('MODULE_TARGET_RUNTIME'), phase]
    path = File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log")
    expect(ModuleTargetTests.new.send(:command, argv, path: path, timeout: 300, capture: output, quiet: true)).to be(true), output
    native = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}/native-result.json")))
    expect(native.fetch('status')).to eq('native_passed')
  end
end
