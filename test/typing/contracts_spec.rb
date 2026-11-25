require 'spec_helper'
require 'fileutils'
require 'open3'
require 'pathname'
require 'rbconfig'
require 'tmpdir'

RSpec.describe 'Framework typing contracts' do
  let(:repo) { Pathname(__dir__).join('../..').expand_path }
  let(:packet_path) { 'lib/rex/proto/dcerpc/packet.rb' }
  let(:uuid_path) { 'lib/rex/proto/dcerpc/uuid.rb' }
  let(:uuid_signature) { 'typing/rex/proto/dcerpc/uuid.rbs' }

  around do |example|
    # Mutate only task-owned copies. Use the real Steepfile, signatures, gate
    # and implementations so exclusions or weakened contracts break these tests.
    Dir.mktmpdir('framework-type-contract-') do |directory|
      @project = Pathname(directory)
      FileUtils.cp(repo.join('Steepfile'), @project)
      FileUtils.cp_r(repo.join('typing'), @project)
      %w[
        lib/rex/ntpath.rb lib/rex/version.rb lib/rex/parser/ini.rb
        lib/rex/proto/dcerpc/uuid.rb lib/rex/proto/dcerpc/packet.rb
        lib/rex/proto/ms_tds/ms_tds_login7_password.rb lib/msf/core/exploit/retry.rb
      ].each do |path|
        FileUtils.mkdir_p(@project.join(path).dirname)
        FileUtils.cp(repo.join(path), @project.join(path))
      end
      example.run
    end
  end

  def replace(path, before, after)
    original = @project.join(path).read
    raise "Mutation no longer matches #{path}: #{before}" unless original.include?(before)

    @project.join(path).write(original.sub(before, after))
  end

  def caller_source(source)
    @project.join('contract.rb').write(source)
    replace('Steepfile', '  configure_code_diagnostics Steep::Diagnostic::Ruby.strict', "  check 'contract.rb'\n  configure_code_diagnostics Steep::Diagnostic::Ruby.strict")
  end

  def gate
    stdout, stderr, status = Open3.capture3(
      RbConfig.ruby, '-r', repo.join('tools/dev/check_types.rb').to_s,
      '-e', 'exit(FrameworkTypeCheck.run(root: ARGV.fetch(0)) ? 0 : 1)', @project.to_s
    )
    [status.exitstatus, stdout + stderr]
  end

  def rejects(diagnostic)
    status, output = gate
    expect([status, output.include?(diagnostic)]).to eq([1, true]), output
  end

  it 'accepts the connected production path and valid callers' do
    @project.join('typing/host.rbs').write("class RetryHost\n  include Msf::Exploit::Retry\n  def vprint_status: (String) -> void\nend\n")
    caller_source(repo.join('test/typing/fixtures/valid_calls.rb').read)
    status, output = gate
    expect(status).to eq(0), output
  end

  it 'rejects an incorrect UUID argument in the real packet builder' do
    replace(packet_path, 'UUID.uuid_pack(uuid)', 'UUID.uuid_pack(42)')
    rejects('Ruby::ArgumentTypeMismatch')
  end

  it 'rejects an incorrect return from the UUID implementation' do
    replace(uuid_path, "    '2.0'\n", "    42\n")
    rejects('Ruby::MethodBodyTypeMismatch')
  end

  it 'protects wire fields even when both the UUID implementation and signature change' do
    original = @project.join(uuid_path).read.lines.find { |line| line.include?(".pack('Vvvn') +") }
    raise 'UUID encoder mutation no longer matches' unless original

    replace(uuid_path, original, "    42\n")
    replace(uuid_signature, 'def self.uuid_pack: (String uuid_str) -> String', 'def self.uuid_pack: (String uuid_str) -> Integer')
    rejects('Ruby::IncompatibleAssignment')
  end

  it 'rejects removal of a required API signature' do
    replace(uuid_signature, "        def self.uuid_pack: (String uuid_str) -> String\n", '')
    rejects('Ruby::NoMethod')
  end

  it 'rejects a declared protocol method with no implementation' do
    replace(uuid_path, 'def self.xfer_syntax_vers', 'def self.removed_xfer_syntax_vers')
    rejects('Ruby::MethodDefinitionMissing')
  end

  it 'rejects removal of the packet builder from the enforced scope' do
    replace('Steepfile', "  check 'lib/rex/proto/dcerpc/packet.rb'\n", '')
    rejects('Required connected files are not checked')
  end

  it 'rejects explicit untyped declarations even when the API is unused' do
    @project.join('typing/erased.rbs').write("class Erased\n def value: () -> untyped\nend\n")
    rejects('Untyped declaration')
  end

  it 'rejects inferred untyped calls from standard-library escape hatches' do
    replace('lib/rex/ntpath.rb', '      Pathname.new(path)', "      eval(\"'x'\").upcase\n      Pathname.new(path)")
    rejects('Unchecked calls or unsuccessful analysis')
  end

  it 'rejects an untyped assertion that would bypass argument checking' do
    replace(packet_path, 'UUID.uuid_pack(uuid)', "UUID.uuid_pack(42 #: untyped\n    )")
    rejects('Untyped annotation')
  end

  it 'fails on Ruby syntax diagnostics rather than treating them as informational' do
    @project.join(packet_path).write('def (')
    rejects('Ruby::SyntaxError')
  end

  it 'fails closed if the checker logs an internal failure but returns success' do
    require repo.join('tools/dev/check_types.rb').to_s
    status = instance_double(Process::Status, success?: true)
    allow(Open3).to receive(:capture3).and_return(['', "FATAL: [Steep 2.1.0] internal failure\n", status])
    result = nil
    expect { result = FrameworkTypeCheck.run(root: @project) }.to output(/FATAL: \[Steep/).to_stderr
    expect(result).to be(false)
  end

  shared_examples 'an invalid API caller' do |source, diagnostic|
    it "rejects #{source}" do
      caller_source(source)
      rejects(diagnostic)
    end
  end

  include_examples 'an invalid API caller', 'Rex::Ntpath.as_ntpath(1)', 'Ruby::ArgumentTypeMismatch'
  include_examples 'an invalid API caller', 'Rex::Version.new(false)', 'Ruby::ArgumentTypeMismatch'
  include_examples 'an invalid API caller', 'Rex::Parser::Ini.from_s(nil)', 'Ruby::ArgumentTypeMismatch'
  include_examples 'an invalid API caller', "Rex::Parser::Ini.new.path = 'config.ini'", 'Ruby::NoMethod'
  include_examples 'an invalid API caller', 'Rex::Proto::DCERPC::UUID.uuid_unpack(nil)', 'Ruby::ArgumentTypeMismatch'
  include_examples 'an invalid API caller', "Rex::Proto::DCERPC::UUID.uuid_by_name('unknown').upcase", 'Ruby::NoMethod'
  include_examples 'an invalid API caller', 'Rex::Proto::MsTds::MsTdsLogin7Password.encode(42)', 'Ruby::ArgumentTypeMismatch'

  it 'requires the output method on a retry mixin host' do
    @project.join('typing/host.rbs').write("class SilentHost\n include Msf::Exploit::Retry\nend\n")
    caller_source('SilentHost.new')
    rejects('RBS::ModuleSelfTypeError')
  end

  it 'checks retry arguments and propagates generic block results' do
    @project.join('typing/host.rbs').write("class RetryHost\n include Msf::Exploit::Retry\n def vprint_status: (String) -> void\nend\n")
    caller_source("RetryHost.new.retry_until_truthy(timeout: '1') { true }\nRetryHost.new.retry_until_truthy(timeout: 1) { 42 }&.upcase\n")
    status, output = gate
    expect([status, output.include?('Ruby::ArgumentTypeMismatch'), output.include?('Ruby::NoMethod')]).to eq([1, true, true]), output
  end
end
