require 'acceptance_spec_helper'
require 'base64'
require_relative '../../../../tools/dev/run_module_target_tests'

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

  it 'checks the genuine affected service through an actual file read' do
    output = run_target_module(owner, 'ray', {}, action: 'check')
    expect(output).to include('The target is vulnerable.', 'Ray 2.6.3 - successfully read /etc/passwd')
  end

  it 'prints exact UTF8 file content from a quoted path twice' do
    2.times do
      output = run_target_module(owner, 'ray', { 'FILEPATH' => @fixture.fetch('paths').fetch('utf8') })
      expect(output.gsub("\r\n", "\n")).to include(@content.force_encoding(Encoding::UTF_8))
    end
  end

  it 'accepts a genuine zero-length file twice' do
    2.times do
      path = @fixture.fetch('paths').fetch('empty')
      output = run_target_module(owner, 'ray', { 'FILEPATH' => path })
      expect(output).to include(path)
      expect(output).not_to include('Failed to execute LFI')
    end
  end

  it 'preserves reserved characters, a literal percent escape and UTF8 in a filename twice' do
    2.times do
      output = run_target_module(owner, 'ray', { 'FILEPATH' => @fixture.fetch('paths').fetch('reserved') })
      expect(output.gsub("\r\n", "\n")).to include(@content.force_encoding(Encoding::UTF_8))
    end
  end

  it 'reports a genuinely absent file without printing fixture content' do
    output = run_target_module(owner, 'ray', { 'FILEPATH' => @fixture.fetch('paths').fetch('missing') }, allow_errors: true)
    expect(output).to include('Failed to execute LFI')
    expect(output).not_to include(@content.force_encoding(Encoding::UTF_8).strip)
  end

  it 'returns unknown on unrelated Apache content' do
    output = run_target_module(owner, 'unrelated', {}, action: 'check')
    expect(output).to include('Cannot reliably check exploitability.', 'No response or unexpected status from Ray API')
  end

  it 'honors automatic refusal on unrelated Apache content' do
    output = run_target_module(owner, 'unrelated', { 'FILEPATH' => @fixture.fetch('paths').fetch('utf8') }, allow_errors: true)
    expect(output).to include('Cannot reliably check exploitability.')
    expect(output).not_to include(@content.force_encoding(Encoding::UTF_8).strip)
  end

  it 'reads without relying on check initialization' do
    output = run_target_module(owner, 'ray', { 'FILEPATH' => @fixture.fetch('paths').fetch('utf8'), 'AutoCheck' => false })
    expect(output.gsub("\r\n", "\n")).to include(@content.force_encoding(Encoding::UTF_8))
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
