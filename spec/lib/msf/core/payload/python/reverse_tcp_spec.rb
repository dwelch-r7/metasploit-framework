require 'msfenv'
require 'msf/base'
require 'json'
require 'open3'
require 'socket'
require 'rex/text'

RSpec.describe Msf::Payload::Python::ReverseTcp do
  let(:python) { ENV.fetch('PYTHON', 'python3') }
  let(:executor) { File.expand_path('../../../../../file_fixtures/python_reverse_tcp/execute.py', __dir__) }
  let(:generator) { Object.new.extend(described_class) }
  let(:normal_stage) { "s.sendall(b'stage-proof')\n" }

  # The generator, compressed exec stub, stage framing, sockets and optional
  # fork are real. The embedding interpreter stays alive while its peer checks
  # EOF, so interpreter exit or garbage collection cannot supply the cleanup.
  def execute_stage(stage, retry_wait: nil, forked: false)
    server = TCPServer.new('127.0.0.1', 0)
    stub = generator.generate_reverse_tcp(host: '127.0.0.1', port: server.addr[1], retry_count: 1, retry_wait: retry_wait)
    encoded = Rex::Text.encode_base64(Rex::Text.zlib_deflate(stage))
    result = nil
    process_options = Gem.win_platform? ? {} : { pgroup: true }
    Open3.popen3(python, executor, **process_options) do |input, output, error, process|
      begin
        input.puts({ stager: stub }.to_json)
        input.flush
        raise 'Generated stager did not connect within five seconds' unless IO.select([server], nil, nil, 5)

        peer = server.accept
        peer.write([encoded.bytesize].pack('N') + encoded)
        raise 'Generated stager did not return within five seconds' unless IO.select([output], nil, nil, 5)

        result = JSON.parse(output.gets)
        result['proof'] = read_stage_bytes(peer, 'stage-proof'.bytesize)
        if forked
          peer.write('x')
          result['child_reply'] = read_stage_bytes(peer, 'child-alive'.bytesize)
        end
        result['peer_eof'] = IO.select([peer], nil, nil, 0.5) && peer.read_nonblock(1, exception: false).nil?
        result['interpreter_alive'] = process.alive?
      ensure
        input.close
        peer&.close
        unless process.join(8)
          Process.kill('KILL', Gem.win_platform? ? process.pid : -process.pid)
          process.join
          raise 'Generated stager contract exceeded its process bound'
        end
      end
      stderr = error.read
      raise "Generated stager interpreter failed: #{stderr}" unless process.value.success?
    end
    result
  ensure
    server&.close
  end

  def read_stage_bytes(peer, length)
    value = String.new
    while value.bytesize < length
      raise 'The stage did not send its proof within five seconds' unless IO.select([peer], nil, nil, 5)

      value << peer.readpartial(length - value.bytesize)
    end
    value
  end

  it 'closes its real connection after a stage returns while its interpreter remains alive' do
    expect(execute_stage(normal_stage)).to eq(
      'socket_closed' => true, 'failure' => nil, 'proof' => 'stage-proof',
      'peer_eof' => true, 'interpreter_alive' => true
    )
  end

  it 'also closes the connection established by the retry-enabled branch' do
    expect(execute_stage(normal_stage, retry_wait: 0)).to include('socket_closed' => true, 'peer_eof' => true)
  end

  it 'closes the connection and propagates a stage exception' do
    result = execute_stage(normal_stage + "raise RuntimeError('stage-error')\n")

    expect(result).to include(
      'socket_closed' => true, 'peer_eof' => true, 'interpreter_alive' => true,
      'failure' => { 'type' => 'RuntimeError', 'message' => 'stage-error' }
    )
  end

  it 'releases the fork parent descriptor while preserving the child connection until its own close' do
    skip 'The stage requires fork support' if Gem.win_platform?

    stage = <<~PYTHON
      import builtins, os
      child = os.fork()
      if child == 0:
          try:
              s.settimeout(3)
              s.sendall(b'stage-proof')
              if s.recv(1) != b'x':
                  os._exit(1)
              s.sendall(b'child-alive')
          finally:
              s.close()
          os._exit(0)
      builtins._module_target_child = child
    PYTHON

    expect(execute_stage(stage, forked: true)).to eq(
      'socket_closed' => true, 'failure' => nil, 'proof' => 'stage-proof',
      'child_reply' => 'child-alive', 'peer_eof' => true, 'interpreter_alive' => true
    )
  end
end
