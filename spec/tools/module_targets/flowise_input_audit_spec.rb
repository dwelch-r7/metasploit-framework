require 'spec_helper'
require 'tmpdir'
require_relative '../../../test/module_targets/flowise/input_audit'

RSpec.describe FlowiseInputs do
  let(:response) { Struct.new(:code, :body).new(500, "Peer response\xFF".b) }
  let(:owner_class) do
    Class.new do
      attr_reader :calls

      def initialize(response)
        @response = response
        @calls = []
      end

      def fullname
        'exploit/test/flowise'
      end

      def targets
        []
      end

      def compatible_payloads
        []
      end

      def send_request_cgi(*arguments, **keywords)
        @calls << [arguments, keywords]
        raise IOError, 'Actual transport failure' if @response == :error

        @response
      end

      def execute_command(*arguments, **keywords)
        @calls << [arguments, keywords]
        @response
      end

      def create_tar_package
        @calls << :archive
        @response
      end

      def send_response(*arguments, **keywords)
        @calls << [arguments, keywords]
        @response
      end

      prepend FlowiseInputs::Requests
      prepend FlowiseInputs::Commands
      prepend FlowiseInputs::Archive

      protected

      def rhost
        '192.0.2.10'
      end

      def rport
        3000
      end
    end
  end
  let(:owner) { owner_class.new(response) }
  let(:options) { { 'method' => 'POST', 'uri' => '/api/v1/node-load-method/customMCP', 'data' => "Actual input\xFE".b } }

  around do |example|
    Dir.mktmpdir('flowise-observer-') do |directory|
      @directory = directory
      example.run
    end
  end

  before do
    stub_const('Msf::Config', Class.new do
      def self.config_directory; end
    end)
    allow(Msf::Config).to receive(:config_directory).and_return(File.join(@directory, 'msf-config'))
    File.write(described_class.path, '')
  end

  def records
    File.readlines(described_class.path).map { |line| JSON.parse(line) }
  end

  it 'delegates request arguments once and preserves object identity and return' do
    expect(owner.send_request_cgi(options, 8, false)).to equal(response)
    expect(owner.calls).to eq([[[options, 8, false], {}]])
    expect(owner.calls.fetch(0).fetch(0).fetch(0)).to equal(options)
  end

  it 'observes real selected endpoint readers even when they are protected' do
    owner.send_request_cgi(options)
    expect(records.fetch(0)).to include('host' => '192.0.2.10', 'port' => 3000)
  end

  it 'records actual binary request and peer body without reserializing either' do
    owner.send_request_cgi(options)
    expect(records.fetch(0)).to include('data_base64' => Base64.strict_encode64(options.fetch('data')), 'body_base64' => Base64.strict_encode64(response.body), 'status' => 500)
  end

  it 'preserves a missing response as nil' do
    expect(owner_class.new(nil).send_request_cgi(options)).to be_nil
    expect(records.fetch(0)).to include('status' => nil, 'body_base64' => nil)
  end

  it 'propagates the actual transport exception without retrying' do
    failing = owner_class.new(:error)
    expect { failing.send_request_cgi(options) }.to raise_error(IOError, 'Actual transport failure')
    expect(failing.calls).to eq([[[options], {}]])
    expect(records).to eq([])
  end

  it 'preserves command argument identity and a false owner return' do
    command = +'Actual command'
    subject_owner = owner_class.new(false)
    expect(subject_owner.execute_command(command, option: :actual)).to be(false)
    expect(subject_owner.calls.fetch(0).fetch(0).fetch(0)).to equal(command)
    expect(records.fetch(0)).to include('kind' => 'COMMAND-ARG', 'command_base64' => Base64.strict_encode64(command))
  end

  it 'records the single actual archive return without generating another payload' do
    archive = "Actual tar\xFF".b
    producer = owner_class.new(archive)
    expect(producer.create_tar_package).to equal(archive)
    expect(producer.calls).to eq([:archive])
    expect(records.fetch(0)).to include('kind' => 'RETURNED-TAR', 'returned_base64' => Base64.strict_encode64(archive))
  end

  it 'preserves a nil archive result without inventing tar bytes' do
    expect(owner_class.new(nil).create_tar_package).to be_nil
    expect(records.fetch(0)).to include('kind' => 'RETURNED-TAR', 'returned_base64' => nil)
  end

  it 'installs only explicitly selected owner classes and reports their actual catalog' do
    selected = described_class::CUSTOM
    registry = double('Actual module factory')
    framework = double('Framework', modules: registry)
    allow(owner).to receive(:fullname).and_return(selected)
    allow(owner).to receive(:targets).and_return([Struct.new(:name).new('Unix/Linux Command')])
    allow(owner).to receive(:compatible_payloads).and_return([['cmd/unix/generic', Object]])
    expect(registry).to receive(:create).with(selected).once.and_return(owner)
    expect(described_class.install(framework, [selected])).to eq(selected => { target_name: 'Unix/Linux Command', generic_compatible: true, fetch_compatible: false, python_compatible: false })
  end

  it 'delegates the actual response body once with its original return value' do
    peer = Struct.new(:peerhost).new('192.0.2.20')
    body = "Actual package\xFF".b
    expect(owner.send_response(peer, body, { 'Content-Type' => 'application/x-tar' })).to equal(response)
    expect(owner.calls.fetch(0).fetch(0).fetch(1)).to equal(body)
    expect(records.fetch(0)).to include('kind' => 'RESPONSE-ARGS', 'peer' => '192.0.2.20', 'body_base64' => Base64.strict_encode64(body))
  end
end
