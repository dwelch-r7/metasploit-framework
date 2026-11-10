# frozen_string_literal: true

require 'base64'
require 'json'

# Passive test-local observation. PRE-SEND is not a packet capture; SOCKET-WRITE
# is the actual put argument and returned count, paired with a genuine reply.
module DruidSingleSocketObserver
  OWNER = 'exploit/linux/http/apache_druid_js_rce'

  # Keeps request attempts and records audit failures without masking I/O.
  class Recorder
    attr_reader :errors

    def initialize(metadata, &sink)
      @metadata = metadata.dup.freeze
      @sink = sink
      @attempt = 0
      @errors = []
    end

    def emit(fields)
      @sink.call(@metadata.merge(fields).merge(attempt: @attempt))
    rescue StandardError => e
      @errors << { error: e.class.name, message: e.message }
      nil
    end

    def request(request)
      @attempt += 1
      opts = request.opts
      emit(kind: 'PRE-SEND', method: opts['method'], uri: opts['uri'], body_base64: Base64.strict_encode64(opts.fetch('data', '').b), transformed: !!(opts['ntlm_transform_request'] || opts['krb_transform_request']))
    rescue StandardError => e
      @errors << { error: e.class.name, message: e.message }
    end

    def response(response)
      emit(kind: 'RESPONSE', status: response&.code, body_base64: response && Base64.strict_encode64(response.body.b))
    rescue StandardError => e
      @errors << { error: e.class.name, message: e.message }
    end

    def snapshot(buffer, socket)
      { bytes: buffer.is_a?(String) ? buffer.dup.b : nil, peer: socket.getpeername_as_array }
    rescue StandardError => e
      @errors << { error: e.class.name, message: e.message }
      { bytes: nil, peer: nil }
    end

    def written(snapshot, count: nil, error: nil)
      bytes = snapshot.fetch(:bytes)
      emit(kind: 'SOCKET-WRITE', peer: snapshot.fetch(:peer), bytes: bytes&.bytesize,
           data_base64: bytes && Base64.strict_encode64(bytes), returned_count: count,
           complete: !error && bytes.is_a?(String) && count == bytes.bytesize,
           error: error && { type: error.class.name, message: error.message })
    end

    def observe(socket)
      return socket unless socket

      socket.instance_variable_set(:@druid_single_socket_recorder, self)
      socket.singleton_class.prepend(SocketWrites) unless socket.singleton_class.ancestors.include?(SocketWrites)
      socket
    rescue StandardError => e
      @errors << { error: e.class.name, message: e.message }
      socket
    end
  end

  # Delegates the existing subscriber without another serialization.
  class Subscriber
    def initialize(delegate, recorder)
      @delegate = delegate
      @recorder = recorder
    end

    def on_request(request)
      @recorder.request(request)
      @delegate.on_request(request)
    end

    def on_response(response)
      @recorder.response(response)
      @delegate.on_response(response)
    end
  end

  # Observes only the real socket argument and original returned count.
  module SocketWrites
    def put(buffer, *arguments, **keywords, &block)
      recorder = @druid_single_socket_recorder
      snapshot = recorder.snapshot(buffer, self)
      begin
        count = super
      rescue StandardError => e
        recorder.written(snapshot, error: e)
        raise
      end
      recorder.written(snapshot, count: count)
      count
    end
  end

  # Attaches to the actual returned socket for this one client instance.
  module ClientConnections
    def connect(*arguments, **keywords, &block)
      socket = super
      @druid_single_socket_recorder.observe(socket)
      socket
    end
  end

  # Selects clients created by the tested module, not unrelated traffic.
  module ModuleConnections
    def connect(opts = {})
      client = super
      DruidSingleSocketObserver.attach_owner(client, self)
      client
    end
  end

  def self.attach(client, recorder)
    return client if client.instance_variable_defined?(:@druid_single_socket_recorder)

    client.instance_variable_set(:@druid_single_socket_recorder, recorder)
    client.subscriber = Subscriber.new(client.subscriber, recorder)
    client.singleton_class.prepend(ClientConnections)
    client
  end

  def self.attach_owner(client, owner)
    return client unless owner.fullname == OWNER

    metadata = {
      client: @recorders.length + 1, case_id: @case_id, owner: owner.fullname, object_id: owner.object_id,
      host: client.hostname, port: client.port, ssl: client.ssl, proxies: client.proxies, target: owner.target_index,
      payload: owner.datastore['PAYLOAD']
    }
    recorder = Recorder.new(metadata) { |row| File.open(@path, 'a') { |output| output.puts(JSON.generate(row)) } }
    @recorders << recorder
    attach(client, recorder)
  end

  def self.install(framework)
    @artifacts = File.dirname(Msf::Config.config_directory)
    @path = File.join(@artifacts, 'socket-observations.jsonl')
    File.write(@path, '')
    @recorders = []
    @case_id = 'calibration'
    instance = framework.modules.create(OWNER)
    instance.class.prepend(ModuleConnections) unless instance.class.ancestors.include?(ModuleConnections)
    { installed: true, owner: OWNER }
  end

  def self.begin_case(identifier)
    @case_id = identifier
    state
  end

  def self.state
    { clients: @recorders.length, errors: @recorders.flat_map(&:errors) }
  end

  # Uses the same observer on a real native row sample before any module method.
  def self.calibrate(host, port)
    input = JSON.parse(File.read(File.join(@artifacts, 'native-single-proof.json')))
    body = Base64.strict_decode64(input.fetch('sample_request_base64'))
    client = Rex::Proto::Http::Client.new(host, port)
    recorder = Recorder.new(client: 'calibration', case_id: 'calibration', owner: 'native-calibration', host: host, port: port, ssl: false, proxies: nil) do |row|
      File.open(@path, 'a') { |output| output.puts(JSON.generate(row)) }
    end
    @recorders << recorder
    attach(client, recorder)
    request = client.request_cgi('method' => 'POST', 'uri' => '/druid/indexer/v1/sampler', 'ctype' => 'application/json', 'data' => body)
    response = client.send_recv(request, 8)
    document = response&.get_json_document
    { status: response&.code, rows: document&.fetch('data')&.map { |row| row.fetch('parsed').fetch('name') }, errors: recorder.errors }
  ensure
    client&.close
  end
end
