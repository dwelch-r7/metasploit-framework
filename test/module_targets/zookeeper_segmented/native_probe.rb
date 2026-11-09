# frozen_string_literal: true

require 'json'
require 'net/http'
require 'socket'
require 'timeout'
require 'open3'

runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
commands = []
requests = []
streams = []
evidence = { commands: commands, requests: requests, streams: streams }

native = lambda do |*arguments|
  argv = runtime.fetch('compose') + arguments
  stdout, stderr, status = Open3.capture3(*argv)
  commands << { argv: argv, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
  raise "Native command failed: #{commands.last.inspect}" unless status.success?

  stdout
end
address = native.call('port', 'sliced', '8474').strip
control_port = Integer(address.split(':').last)
api = lambda do |method, path, body = nil|
  http = Net::HTTP.new('127.0.0.1', control_port, nil)
  http.open_timeout = 3
  http.read_timeout = 5
  message = Net::HTTPGenericRequest.new(method, !body.nil?, true, path)
  if body
    message['Content-Type'] = 'application/json'
    message.body = JSON.generate(body)
  end
  response = http.request(message)
  requests << { method: method, path: path, request: body, status: response.code.to_i, headers: response.to_hash, body: response.body }
  raise "Native proxy API failed: #{requests.last.inspect}" unless %w[200 201].include?(response.code)

  JSON.parse(response.body)
end
read_stream = lambda do |service, command|
  endpoint = runtime.fetch('endpoints').fetch(service)
  chunks = []
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  Timeout.timeout(8) do
    Socket.tcp(endpoint.fetch('host'), endpoint.fetch('port'), connect_timeout: 3) do |socket|
      socket.write(command)
      loop do
        chunks << socket.readpartial(16_384)
      rescue EOFError
        break
      end
    end
  end
  data = chunks.join.force_encoding(Encoding::UTF_8)
  raise 'Native stream is not valid UTF-8' unless data.valid_encoding?

  streams << { service: service, command: command, chunk_sizes: chunks.map(&:bytesize), bytes: data.bytesize, elapsed: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, data: data }
  data
end
fields = lambda do |text|
  text.lines.filter_map { |line| line.strip.split('=', 2) if line.include?('=') }.to_h
end

begin
  evidence[:version] = api.call('GET', '/version')
  raise 'Native Toxiproxy version differs' unless evidence.fetch(:version).fetch('version') == '2.9.0'

  proxy = { name: 'zookeeper', listen: '0.0.0.0:2181', upstream: 'backend:2181', enabled: true }
  api.call('POST', '/proxies', proxy)
  attributes = { 'average_size' => 640, 'size_variation' => 0, 'delay' => 150_000 }
  toxic = api.call('POST', '/proxies/zookeeper/toxics', { name: 'deterministic_slices', type: 'slicer', stream: 'downstream', toxicity: 1.0, attributes: attributes })
  raise 'Native slicer differs' unless toxic.fetch('attributes') == attributes && toxic.fetch('stream') == 'downstream'

  evidence[:configuration] = api.call('GET', '/proxies/zookeeper')
  %w[ruok envi stat].each do |command|
    direct = read_stream.call('backend', command)
    sliced = read_stream.call('sliced', command)
    if command == 'envi'
      direct_fields = fields.call(direct)
      sliced_fields = fields.call(sliced)
      raise 'Native environment changed in transport' unless direct_fields.except('os.memory.free', 'os.memory.total') == sliced_fields.except('os.memory.free', 'os.memory.total') && direct_fields.keys.sort == sliced_fields.keys.sort
      raise 'Native environment was not actually sliced' unless streams.last.fetch(:chunk_sizes).length > 1 && streams.last.fetch(:chunk_sizes).first < sliced.bytesize

      evidence[:environment] = sliced_fields
      evidence[:full_environment] = sliced
    elsif command == 'stat'
      %w[Zookeeper\ version Mode Node\ count].each do |name|
        expression = /^#{Regexp.escape(name)}: (.+)$/
        raise "Native statistics changed in transport: #{name}" unless direct[expression, 1] && direct[expression, 1] == sliced[expression, 1]
      end
      evidence[:statistics] = sliced
    else
      raise 'Native ruok differs' unless direct == 'imok' && sliced == direct
    end
  end
ensure
  puts JSON.pretty_generate(evidence)
end
