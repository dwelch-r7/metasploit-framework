require 'rspec'
require 'tmpdir'
require_relative '../../../test/module_targets/druid_js_single/socket_observer'

module DruidObserverSpecFixtures
  # An in-memory delegate with observable return and failure contracts.
  class Socket
    attr_reader :calls
    attr_accessor :result, :error, :mutate

    def initialize
      @calls = []
    end

    def getpeername_as_array
      [2, '192.0.2.10', 8081]
    end

    def put(buffer, *arguments, **keywords, &block)
      @calls << [buffer, arguments, keywords, block]
      raise error if error

      buffer << 'changed' if mutate
      result.nil? ? buffer.bytesize : result
    end
  end

  # An ordinary subscriber that never performs transport work.
  class Delegate
    attr_reader :requests, :responses
    attr_accessor :error

    def initialize
      @requests = []
      @responses = []
    end

    def on_request(request)
      @requests << request
      raise error if error

      :original_request_return
    end

    def on_response(response)
      @responses << response
      :original_response_return
    end
  end

  # Fails immediately if observation attempts another serialization.
  class Request
    attr_reader :opts, :serializations

    def initialize
      @opts = { 'method' => 'POST', 'uri' => '/druid/indexer/v1/sampler', 'data' => '{"real":"body"}' }
      @serializations = 0
    end

    def to_s
      @serializations += 1
      raise 'Observer must not serialize'
    end
  end

  # Returns its supplied socket without opening any network connection.
  class Client
    attr_accessor :subscriber, :socket, :error
    attr_reader :calls

    def initialize(socket, subscriber)
      @socket = socket
      @subscriber = subscriber
      @calls = []
    end

    def connect(timeout = -1)
      @calls << timeout
      raise error if error

      socket
    end
  end

  # Rex::Proto::Http::Client exposes these readers as protected, not public.
  class ProtectedClient < Client
    attr_reader :proxies

    def initialize(socket, subscriber)
      super
      @hostname = '192.0.2.10'
      @port = 8081
      @ssl = false
      @proxies = nil
    end

    protected

    attr_reader :hostname, :port, :ssl
  end

  # Models the module connection hook without loading Framework or a database.
  class Owner
    attr_reader :calls
    attr_accessor :error

    def initialize(client)
      @client = client
      @calls = []
    end

    def fullname
      DruidSingleSocketObserver::OWNER
    end

    def target_index
      1
    end

    def datastore
      { 'PAYLOAD' => 'cmd/unix/generic' }
    end

    def connect(options = {})
      @calls << options
      raise error if error

      @client
    end
  end
end

RSpec.describe 'Druid single-release socket observer' do
  let(:events) { [] }
  let(:metadata) { { client: 1, owner: 'native-calibration', case_id: 'case', host: '192.0.2.10', port: 8081, ssl: false } }
  let(:recorder) { DruidSingleSocketObserver::Recorder.new(metadata) { |row| events << row } }
  let(:socket) { DruidObserverSpecFixtures::Socket.new }
  let(:delegate) { DruidObserverSpecFixtures::Delegate.new }
  let(:client) { DruidObserverSpecFixtures::Client.new(socket, delegate) }
  let(:request) { DruidObserverSpecFixtures::Request.new }
  let(:bytes) { "POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}" }

  before { DruidSingleSocketObserver.attach(client, recorder) }

  it 'preserves the client object' do
    expect(DruidSingleSocketObserver.attach(client, recorder)).to equal(client)
  end

  it 'delegates connect once with the original timeout and returned socket' do
    expect(client.connect(8)).to equal(socket)
    expect(client.calls).to eq([8])
  end

  it 'preserves the original connection exception object' do
    original = IOError.new('Connection failed')
    client.error = original

    expect { client.connect }.to(raise_error { |error| expect(error).to equal(original) })
  end

  it 'preserves a nil connection return' do
    client.socket = nil

    expect(client.connect).to be_nil
  end

  it 'delegates the original subscriber request once and preserves its return' do
    expect(client.subscriber.on_request(request)).to eq(:original_request_return)
    expect(delegate.requests).to eq([request])
  end

  it 'does not serialize a request to observe it' do
    client.subscriber.on_request(request)

    expect(request.serializations).to eq(0)
  end

  it 'labels the request snapshot as pre-send' do
    client.subscriber.on_request(request)

    expect(events.fetch(0).slice(:kind, :body_base64)).to eq(kind: 'PRE-SEND', body_base64: Base64.strict_encode64(request.opts.fetch('data')))
  end

  it 'preserves the original subscriber exception' do
    original = IOError.new('Original subscriber failed')
    delegate.error = original

    expect { client.subscriber.on_request(request) }.to(raise_error { |error| expect(error).to equal(original) })
  end

  it 'delegates the response once and preserves its return' do
    response = Struct.new(:code, :body).new(200, '{}')

    expect(client.subscriber.on_response(response)).to eq(:original_response_return)
    expect(delegate.responses).to eq([response])
  end

  it 'records a nil response without inventing success' do
    client.subscriber.on_response(nil)

    expect(events.fetch(0).slice(:kind, :status, :body_base64)).to eq(kind: 'RESPONSE', status: nil, body_base64: nil)
  end

  it 'delegates put once with identical object, arguments, keywords and block' do
    block = proc { :unchanged }
    client.connect
    returned = socket.put(bytes, { 'Timeout' => 7 }, audit: :unchanged, &block)

    expect(socket.calls).to eq([[bytes, [{ 'Timeout' => 7 }], { audit: :unchanged }, block]])
    expect(socket.calls.fetch(0).fetch(0)).to equal(bytes)
    expect(returned).to eq(bytes.bytesize)
  end

  it 'records actual socket argument bytes and actual peer with full count' do
    client.subscriber.on_request(request)
    client.connect
    socket.put(bytes)

    expect(events.last.slice(:kind, :data_base64, :returned_count, :complete, :peer, :attempt)).to eq(kind: 'SOCKET-WRITE', data_base64: Base64.strict_encode64(bytes), returned_count: bytes.bytesize, complete: true, peer: [2, '192.0.2.10', 8081], attempt: 1)
  end

  it 'captures the argument before a delegate mutates it' do
    client.connect
    original = bytes.dup
    socket.mutate = true
    socket.put(bytes)

    expect(Base64.strict_decode64(events.last.fetch(:data_base64))).to eq(original)
  end

  it 'retains a short count and does not label it complete' do
    client.connect
    socket.result = 3

    expect(socket.put(bytes)).to eq(3)
    expect(events.last.slice(:returned_count, :complete)).to eq(returned_count: 3, complete: false)
  end

  it 'preserves the original put exception while recording failure' do
    client.connect
    original = IOError.new('Actual transport failed')
    socket.error = original

    expect { socket.put(bytes) }.to(raise_error { |error| expect(error).to equal(original) })
    expect(events.last.slice(:complete, :error)).to eq(complete: false, error: { type: 'IOError', message: original.message })
  end

  it 'does not let an audit sink mask a successful transport return' do
    broken = DruidSingleSocketObserver::Recorder.new(metadata) { raise IOError, 'Audit unavailable' }
    broken.observe(socket)

    expect(socket.put(bytes)).to eq(bytes.bytesize)
    expect(broken.errors).to include(error: 'IOError', message: 'Audit unavailable')
  end

  it 'does not let an audit sink mask the original transport exception' do
    broken = DruidSingleSocketObserver::Recorder.new(metadata) { raise IOError, 'Audit unavailable' }
    broken.observe(socket)
    original = IOError.new('Original transport exception')
    socket.error = original

    expect { socket.put(bytes) }.to(raise_error { |error| expect(error).to equal(original) })
  end

  it 'does not attach multiple observer layers to the same client' do
    DruidSingleSocketObserver.attach(client, recorder)
    client.subscriber.on_request(request)
    client.connect
    socket.put(bytes)

    expect(events.count { |row| row[:kind] == 'SOCKET-WRITE' }).to eq(1)
    expect(delegate.requests).to eq([request])
  end

  it 'does not instrument another client or its socket class' do
    other_socket = DruidObserverSpecFixtures::Socket.new
    other = DruidObserverSpecFixtures::Client.new(other_socket, delegate)
    other.connect.put(bytes)

    expect(events).to eq([])
    expect(other.subscriber).to equal(delegate)
  end

  it 'leaves a nonselected owner client untouched' do
    other = DruidObserverSpecFixtures::Client.new(socket, delegate)
    owner = Struct.new(:fullname).new('exploit/example')

    expect(DruidSingleSocketObserver.attach_owner(other, owner)).to equal(other)
    expect(other.subscriber).to equal(delegate)
  end

  it 'increments attempt IDs without confusing authentication retries' do
    client.subscriber.on_request(request)
    client.connect.put(bytes)
    client.subscriber.on_response(Struct.new(:code, :body).new(401, ''))
    client.subscriber.on_request(request)
    client.connect.put(bytes)

    expect(events.select { |row| row[:kind] == 'SOCKET-WRITE' }.map { |row| row[:attempt] }).to eq([1, 2])
  end
  it 'records a transform without calling it' do
    calls = 0
    request.opts['ntlm_transform_request'] = proc { calls += 1 }
    client.subscriber.on_request(request)

    expect(events.fetch(0).fetch(:transformed)).to be(true)
    expect(calls).to eq(0)
  end

  it 'does not freeze the caller metadata hash' do
    recorder
    metadata[:extra] = 'caller-owned'
    client.subscriber.on_request(request)

    expect(events.fetch(0)).not_to have_key(:extra)
  end
end

RSpec.describe 'Druid selected-owner socket observation' do
  let(:socket) { DruidObserverSpecFixtures::Socket.new }
  let(:delegate) { DruidObserverSpecFixtures::Delegate.new }
  let(:client) { DruidObserverSpecFixtures::ProtectedClient.new(socket, delegate) }
  let(:owner) { DruidObserverSpecFixtures::Owner.new(client) }
  let(:request) { DruidObserverSpecFixtures::Request.new }
  let(:bytes) { "POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}" }
  let(:output_path) { DruidSingleSocketObserver.instance_variable_get(:@path) }

  around do |example|
    names = %i[@path @recorders @case_id]
    previous = names.to_h { |name| [name, [DruidSingleSocketObserver.instance_variable_defined?(name), DruidSingleSocketObserver.instance_variable_get(name)]] }
    Dir.mktmpdir('druid-observer-spec') do |directory|
      DruidSingleSocketObserver.instance_variable_set(:@path, File.join(directory, 'observations.jsonl'))
      DruidSingleSocketObserver.instance_variable_set(:@recorders, [])
      DruidSingleSocketObserver.instance_variable_set(:@case_id, 'selected-owner')
      example.run
    end
  ensure
    previous&.each do |name, (defined, value)|
      if defined
        DruidSingleSocketObserver.instance_variable_set(name, value)
      elsif DruidSingleSocketObserver.instance_variable_defined?(name)
        DruidSingleSocketObserver.remove_instance_variable(name)
      end
    end
  end

  it 'attaches the selected client without changing its protected reader visibility' do
    expect { client.hostname }.to raise_error(NoMethodError, /protected method/)
    expect(DruidSingleSocketObserver.attach_owner(client, owner)).to equal(client)
    expect { client.hostname }.to raise_error(NoMethodError, /protected method/)
    expect(DruidSingleSocketObserver.state).to eq(clients: 1, errors: [])
  end

  it 'delegates the selected module connection and actual write once with unchanged bytes and metadata' do
    owner.singleton_class.prepend(DruidSingleSocketObserver::ModuleConnections)
    options = { 'vhost' => 'fixture.example' }
    expect(owner.connect(options)).to equal(client)
    expect(owner.calls).to eq([options])
    expect(client.subscriber.on_request(request)).to eq(:original_request_return)
    expect(client.connect(8).put(bytes)).to eq(bytes.bytesize)
    client.subscriber.on_response(Struct.new(:code, :body).new(200, '{}'))

    rows = File.readlines(output_path).map { |line| JSON.parse(line) }
    expect(rows.map { |row| row.fetch('kind') }).to eq(%w[PRE-SEND SOCKET-WRITE RESPONSE])
    expect(rows.fetch(1)).to include(
      'host' => '192.0.2.10', 'port' => 8081, 'ssl' => false, 'proxies' => nil,
      'owner' => DruidSingleSocketObserver::OWNER, 'target' => 1, 'payload' => 'cmd/unix/generic',
      'case_id' => 'selected-owner', 'complete' => true, 'returned_count' => bytes.bytesize,
      'data_base64' => Base64.strict_encode64(bytes), 'peer' => [2, '192.0.2.10', 8081]
    )
    expect(socket.calls.length).to eq(1)
    expect(delegate.requests).to eq([request])
    expect(client.calls).to eq([8])
  end

  it 'preserves the selected module connection failure without attaching or masking it' do
    owner.singleton_class.prepend(DruidSingleSocketObserver::ModuleConnections)
    original = IOError.new('Connection setup failed')
    owner.error = original

    expect { owner.connect('vhost' => 'fixture.example') }.to(raise_error { |error| expect(error).to equal(original) })
    expect(owner.calls).to eq([{ 'vhost' => 'fixture.example' }])
    expect(client.subscriber).to equal(delegate)
    expect(DruidSingleSocketObserver.state).to eq(clients: 0, errors: [])
  end
end
