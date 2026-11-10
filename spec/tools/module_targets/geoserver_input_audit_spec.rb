require 'spec_helper'
require 'tmpdir'
require_relative '../../../test/module_targets/geoserver/input_audit'

RSpec.describe GeoServerInputs do
  let(:response) { Struct.new(:code, :body).new(400, "Actual response\xFF".b) }
  let(:owner_class) do
    Class.new do
      attr_reader :calls

      def initialize(response)
        @response = response
        @calls = []
      end

      def fullname
        'exploit/test/geoserver'
      end

      def rhost
        '192.0.2.10'
      end

      def rport
        8080
      end

      def send_request_cgi(*arguments, **keywords)
        @calls << [arguments, keywords]
        raise IOError, 'Actual transport failure' if @response == :error

        @response
      end

      prepend GeoServerInputs::Requests
    end
  end
  let(:owner) { owner_class.new(response) }
  let(:options) { { 'method' => 'POST', 'uri' => '/geoserver/wfs', 'data' => "Actual request\xFE".b } }

  around do |example|
    Dir.mktmpdir('geoserver-input-audit-') do |directory|
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

  def rows
    File.readlines(described_class.path).map { |line| JSON.parse(line) }
  end

  it 'delegates once with the same argument object and preserves the returned object' do
    expect(owner.send_request_cgi(options, 8, false)).to equal(response)
    expect(owner.calls).to eq([[[options, 8, false], {}]])
    expect(owner.calls.fetch(0).fetch(0).fetch(0)).to equal(options)
  end

  it 'records actual binary request and response bytes with the selected endpoint' do
    owner.send_request_cgi(options)
    expect(rows).to eq([
      {
        'owner' => owner.fullname, 'kind' => 'REQUEST-ARGS/RESPONSE-BODY',
        'host' => '192.0.2.10', 'port' => 8080, 'method' => 'POST', 'uri' => '/geoserver/wfs', 'vars_get' => nil,
        'data_base64' => Base64.strict_encode64(options.fetch('data')), 'status' => 400, 'body_base64' => Base64.strict_encode64(response.body)
      }
    ])
  end

  it 'retains a nil response without changing it into a protocol response' do
    actual = owner_class.new(nil).send_request_cgi(options)
    expect(actual).to be_nil
    expect(rows.fetch(0)).to include('status' => nil, 'body_base64' => nil)
  end

  it 'propagates a transport error unchanged after one delegation' do
    failing = owner_class.new(:error)
    expect { failing.send_request_cgi(options) }.to raise_error(IOError, 'Actual transport failure')
    expect(failing.calls.length).to eq(1)
    expect(rows).to eq([])
  end

  it 'records the actual producer return without calling the producer again' do
    producer = Class.new do
      attr_reader :calls

      def initialize
        @calls = []
      end

      def fullname
        'exploit/test/geoserver'
      end

      def create_payload(command, feature_type)
        @calls << [command, feature_type]
        @create_payload ||= "Actual randomized XML\xFF".b
      end

      prepend GeoServerInputs::RceProducer
    end.new
    actual = producer.create_payload('echo harmless', 'topp:states')
    expect(actual).to equal(producer.instance_variable_get(:@create_payload))
    expect(producer.calls).to eq([['echo harmless', 'topp:states']])
    expect(rows.fetch(0)).to include('kind' => 'RETURNED-XML', 'arguments' => ['echo harmless', 'topp:states'], 'returned_base64' => Base64.strict_encode64(actual))
  end

  it 'preserves the actual randomized XXE URI and XML return objects' do
    producer = Class.new do
      def fullname
        'auxiliary/test/geoserver'
      end

      def build_wms_uri
        @build_wms_uri ||= '/geoserver/wms?version=1.1.1&format=image/png'
      end

      def build_xxe_payload(path)
        @build_xxe_payload ||= "Actual XML for #{path}"
      end

      prepend GeoServerInputs::XxeProducer
    end.new
    uri = producer.build_wms_uri
    xml = producer.build_xxe_payload('/tmp/native-file')
    expect(uri).to equal(producer.instance_variable_get(:@build_wms_uri))
    expect(xml).to equal(producer.instance_variable_get(:@build_xxe_payload))
    expect(rows.map { |row| row.fetch('returned_base64') }).to eq([uri, xml].map { |value| Base64.strict_encode64(value) })
  end
end
