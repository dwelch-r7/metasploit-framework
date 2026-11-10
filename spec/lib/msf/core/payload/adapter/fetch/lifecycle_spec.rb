require 'spec_helper'
require 'net/http'
require 'socket'

RSpec.describe 'Fetch HTTP service ownership' do
  # The public adapter/server methods are real. These bindings supply options,
  # benign bytes and a parent handler without starting an executable payload.
  let(:parent_class) do
    Class.new do
      def setup_handler; end
      def cleanup_handler; end
      def cleanup; end
      def framework; end
      def print_status(*); end
      def print_error(*); end
      def print_warning(*); end
      def vprint_status(*); end

      def fail_with(reason, message = nil)
        raise "#{reason}: #{message}"
      end

      def _determine_server_comm(*)
        Rex::Socket::Comm::Local
      end
    end
  end

  let(:resource_bytes) { File.binread(File.expand_path('../../../../../../file_fixtures/fetch/http_lifecycle/resource.txt', __dir__)) }
  let(:port) do
    socket = TCPServer.new('127.0.0.1', 0)
    socket.addr[1]
  ensure
    socket&.close
  end

  let(:adapter_module) { Msf::Payload::Adapter::Fetch::HTTP }
  let(:adapter_class) { owner_class(adapter_module) }
  let(:normal_class) { owner_class(Msf::Exploit::Remote::HttpServer) }

  before do
    @owners = []
    @servers = []
  end

  after do
    @owners.each { |owner| owner.normal? ? owner.cleanup : owner.cleanup_handler }
    # Failed before-fix expectations must not leak a test-owned listener into
    # the next example. Only this example's acquired references are released.
    @servers.uniq.each do |server|
      server.deref while server.instance_variable_get(:@_references) > 1
    end
  end

  shared_examples 'a reference-counted fetch adapter' do
    it 'releases its last service reference and closes the actual HTTP endpoint' do
      owner = new_owner('single')
      server = start(owner)
      expect(request('/single').body).to eq(resource_bytes)
      owner.cleanup_handler
      expect(server.instance_variable_get(:@_references)).to eq(0)
      expect(aliases(server)).to eq([])
      expect { request('/single') }.to raise_error(Errno::ECONNREFUSED)
    end

    it 'clears its route ownership and permits a fresh repeated setup' do
      owner = new_owner('repeat')
      first = start(owner)
      owner.cleanup_handler
      expect(owner.instance_variable_get(:@myresources)).to eq([])
      second = start(owner)
      expect(second).not_to equal(first)
      expect(second.instance_variable_get(:@_references)).to eq(2)
      expect(request('/repeat').body).to eq(resource_bytes)
      owner.cleanup_handler
      expect(aliases(second)).to eq([])
    end

    it 'preserves a concurrent owner across repeated cleanup' do
      first = new_owner('first')
      second = new_owner('second')
      server = start(first)
      expect(start(second)).to equal(server)
      first.cleanup_handler
      expect(request('/first').code).to eq('404')
      expect(request('/second').body).to eq(resource_bytes)
      expect(server.instance_variable_get(:@_references)).to eq(2)
      first.cleanup_handler
      expect(server.instance_variable_get(:@_references)).to eq(2)
      expect(request('/second').body).to eq(resource_bytes)
      second.cleanup_handler
      expect(aliases(server)).to eq([])
    end

    it 'preserves the new owner after a reused owner collides and cleans up' do
      retired = new_owner('shared')
      start(retired)
      retired.cleanup_handler
      current = new_owner('shared', data: resource_bytes + 'Second owner')
      server = start(current)
      expect(request('/shared').body).to eq(current.bytes)
      expect { start(retired) }.to raise_error(RuntimeError, /Resource collision detected/)
      retired.cleanup_handler
      expect(request('/shared').body).to eq(current.bytes)
      expect(server.instance_variable_get(:@_references)).to eq(2)
      retired.cleanup_handler
      expect(request('/shared').body).to eq(current.bytes)
      current.cleanup_handler
      expect(aliases(server)).to eq([])
    end
  end

  context 'with HTTP' do
    include_examples 'a reference-counted fetch adapter'
  end

  context 'with HTTPS' do
    let(:adapter_module) { Msf::Payload::Adapter::Fetch::Https }

    include_examples 'a reference-counted fetch adapter'
  end

  %w[normal fetch].each do |first|
    it "preserves mixed normal/Fetch ownership when #{first} cleans up first" do
      normal = new_owner('normal', normal: true)
      fetch = new_owner('fetch')
      server = start(normal)
      expect(start(fetch)).to equal(server)
      if first == 'normal'
        normal.cleanup
        expect(request('/normal').code).to eq('404')
        expect(request('/fetch').body).to eq(resource_bytes)
      else
        fetch.cleanup_handler
        expect(request('/fetch').code).to eq('404')
        expect(request('/normal').body).to eq(resource_bytes)
      end
      expect(server.instance_variable_get(:@_references)).to eq(2)
      normal.cleanup
      fetch.cleanup_handler
      expect(aliases(server)).to eq([])
      expect { request('/normal') }.to raise_error(Errno::ECONNREFUSED)
    end
  end

  def owner_class(protocol)
    Class.new(parent_class) do
      include protocol

      attr_reader :datastore, :bytes

      # The bindings intentionally bypass option-registration constructors.
      def initialize(path, port, bytes, normal: false) # rubocop:disable Lint/MissingSuper
        @normal = normal
        @bytes = bytes
        @path = path
        @my_resources = []
        @myresources = []
        @srv_resources = [{ uri: path, data: bytes, opts: { dynamic_arch: false } }]
        @datastore = {
          'SRVHOST' => '127.0.0.1', 'SRVPORT' => port, 'SRVSSL' => false,
          'FETCH_SRVHOST' => '127.0.0.1', 'FETCH_SRVPORT' => port,
          'FetchHttpServerName' => 'LifecycleSpec', 'FetchHandlerDisable' => false,
          'HTTP::server_name' => 'LifecycleSpec', 'HTTP::compression' => 'none'
        }
      end

      def normal?
        @normal
      end

      def held_service
        normal? ? service : @fetch_service
      end

      def start_normal
        start_service(
          'ServerHost' => '127.0.0.1', 'ServerPort' => datastore.fetch('SRVPORT'),
          'ssl' => false, 'Comm' => Rex::Socket::Comm::Local, 'Path' => "/#{@path}",
          'Uri' => {
            'Proc' => proc do |client, _request|
              response = Rex::Proto::Http::Response.new(200)
              response.body = bytes
              client.send_response(response)
            end
          }
        )
      end
    end
  end

  def new_owner(path, normal: false, data: resource_bytes)
    (normal ? normal_class : adapter_class).new(path, port, data, normal: normal).tap { |owner| @owners << owner }
  end

  def start(owner)
    owner.normal? ? owner.start_normal : owner.setup_handler
    owner.held_service.tap { |server| @servers << server }
  end

  def request(path)
    Net::HTTP.start(
      '127.0.0.1', port, nil, use_ssl: adapter_module == Msf::Payload::Adapter::Fetch::Https,
                              verify_mode: OpenSSL::SSL::VERIFY_NONE, open_timeout: 1, read_timeout: 1
    ) { |http| http.get(path, 'Connection' => 'close') }
  end

  def aliases(server)
    Rex::ServiceManager.instance.select { |_name, value| value.equal?(server) }.keys
  end
end
