require 'spec_helper'
require 'open3'
require 'rbconfig'
require 'shellwords'
require_relative '../../../test/module_targets/rsync_creds/native'

RSpec.describe RsyncCredentialTarget, 'console JSON framing' do
  let(:harness) do
    Class.new do
      include RSpec::Matchers
      include RsyncCredentialTarget

      def console_command(_command)
        raise NotImplementedError
      end
    end.new
  end
  let(:value) { { 'pid' => 812, 'ready' => true } }
  let(:code) { value.inspect }
  let(:prefix) { '' }
  let(:suffix) { '' }
  let(:status) do
    JSON.parse(File.read(File.expand_path('../../file_fixtures/module_targets/console_interleave.json', __dir__))).fetch('status')
  end

  before do
    allow(harness).to receive(:console_command) do |command|
      arguments = Shellwords.split(command)
      # Execute the actual producer with the bundled Ruby, including before the
      # fix, so a different framing format cannot manufacture a regression.
      output, error, result = Open3.capture3(RbConfig.ruby, '-rjson', '-rbase64', '-e', arguments.fetch(2))
      raise error unless result.success?

      prefix + output.sub(/\r?\n\z/, '') + suffix + "\n"
    end
  end

  it 'preserves clean structured results' do
    expect(harness.rc_json(code)).to eq(value)
  end

  context 'with the captured session status before the result newline' do
    let(:suffix) { status }

    it 'decodes the result without consuming the asynchronous status' do
      expect(harness.rc_json(code)).to eq(value)
    end
  end

  context 'with asynchronous text on both sides of the result' do
    let(:prefix) { status }
    let(:suffix) { status }

    it 'finds the result without requiring a clean line boundary' do
      expect(harness.rc_json(code)).to eq(value)
    end
  end

  context 'with quotes, control characters and marker text in data' do
    let(:value) { { 'text' => "雪😀 \"quoted\" \\ \n RSYNC_JSON=literal" } }

    it 'preserves the data exactly' do
      expect(harness.rc_json(code)).to eq(value)
    end
  end

  context 'with a false result' do
    let(:value) { false }

    it 'preserves its type and value' do
      expect(harness.rc_json(code)).to be(false)
    end
  end

  it 'evaluates the expression exactly once' do
    code = 'begin;Thread.current[:module_json_calls]=(Thread.current[:module_json_calls] || 0)+1;Thread.current[:module_json_calls];end'
    expect(harness.rc_json(code)).to eq(1)
  end
end
