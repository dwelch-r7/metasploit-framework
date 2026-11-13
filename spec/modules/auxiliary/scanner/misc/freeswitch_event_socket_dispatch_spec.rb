require 'rspec'
require 'msfenv'
require 'msf/base'
require 'tempfile'

RSpec.describe 'FreeSWITCH per-host AutoCheck dispatch' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    source = File.expand_path('../../../../../modules/auxiliary/scanner/misc/freeswitch_event_socket_login.rb', __dir__)
    scope = Module.new
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap do |klass|
      klass.include(Msf)
      klass.refname = 'scanner/misc/freeswitch_event_socket_login'
      klass.framework = framework
      klass.prepend(Module.new do
        def invalidate_login(options)
          framework.invalidations << options.dup
          super
        end
      end)
    end
  end
  let(:framework) do
    value = Struct.new(:db, :datastore, :threads, :invalidations).new(Struct.new(:active, :workspace).new(false, Struct.new(:name).new('module_target')), Msf::DataStore.new, nil, Queue.new)
    @test_manager = Msf::ThreadManager.new(value)
    value.threads = @test_manager
    value
  end
  let(:transport_class) do
    Class.new do
      attr_accessor :barrier
      attr_reader :checks, :attempts, :connections, :passwords

      def initialize
        @checks = []
        @attempts = []
        @connections = []
        @sockets = []
        @mutex = Mutex.new
        @condition = ConditionVariable.new
        @waiting = 0
        @barrier = false
        @passwords = { '192.0.2.10' => 'ClueCon', '192.0.2.11' => 'ClueCon' }
      end

      def create(options)
        host = options.fetch('PeerHost')
        port = options.fetch('PeerPort')
        raise SocketError, 'getaddrinfo: Name or service not known' unless ['192.0.2.10', '192.0.2.11', '192.0.2.12', '192.0.2.13'].include?(host)
        raise Rex::ConnectionRefused.new(host, port) if host == '192.0.2.12'

        socket = Class.new do
          def initialize(transport, host, port)
            @transport = transport
            @host = host
            @port = port
            @reader, @writer = IO.pipe
            @writer.write('ready')
            @reads = 0
            @closed = false
          end

          def get
            @transport.check(@host)
            greeting
          end

          def get_once
            @reads += 1
            return greeting if @reads == 1

            "Content-Type: command/reply\nReply-Text: #{@accepted ? '+OK accepted' : '-ERR invalid'}\n\n"
          end

          def greeting
            return "Content-Type: text/rude-rejection\nContent-Length: 24\n\nAccess Denied, go away.\n" if @host == '192.0.2.13'

            "Content-Type: auth/request\n\n"
          end

          def put(data)
            raise Errno::EPIPE if @host == '192.0.2.13'

            password = data.delete_prefix('auth ').delete_suffix("\n\n")
            @accepted = @transport.authenticate(@host, @port, password)
            data.bytesize
          end

          def to_io
            @reader
          end

          def shutdown
            nil
          end

          def close
            return if @closed

            @reader.close
            @writer.close
            @closed = true
          end

          def closed?
            @closed
          end
        end.new(self, host, port)
        @mutex.synchronize do
          @connections << [host, port]
          @sockets << socket
        end
        socket
      end

      def check(host)
        @mutex.synchronize do
          @checks << host
          if @barrier
            @waiting += 1
            @condition.broadcast
            @condition.wait(@mutex, 2) if @waiting < 2
            raise 'Expected two concurrent scanner workers' if @waiting < 2
          end
        end
      end

      def authenticate(host, port, password)
        accepted = @passwords.fetch(host).b == password.b
        @mutex.synchronize { @attempts << [host, port, password, accepted] }
        accepted
      end

      def close
        @sockets.each(&:close)
      end
    end
  end
  let(:transport) do
    @test_transport = transport_class.new
  end

  around do |example|
    reporting = Thread.report_on_exception
    example.run
  ensure
    @test_transport&.close
    @test_manager&.each do |thread|
      thread.kill if thread.alive?
      thread.join
    end
    if @test_manager&.monitor
      @test_manager.monitor.kill
      @test_manager.monitor.join
    end
    Thread.report_on_exception = reporting
  end

  before do
    mod.datastore['RHOSTS'] = '192.0.2.10 192.0.2.11'
    mod.datastore['PASS_FILE'] = ''
    mod.datastore['PASSWORD'] = 'ClueCon'
    mod.datastore['BRUTEFORCE_SPEED'] = 5
    mod.datastore['ShowProgress'] = false
    allow(Rex::Socket::Tcp).to receive(:create) { |options| transport.create(options) }
  end

  # Owner initialization, Scanner/RhostsWalker/replicant dispatch, real Ruby
  # threads/ThreadManager, AutoCheck policy and the login scanner remain real.
  # Only Rex TCP creation/I/O is replaced with capture-derived framed replies;
  # an IO pipe supplies select readiness without external network connections.
  # The Framework/DB facade is a non-persisting boundary double. Native tests
  # separately verify full transport and SQL behavior for independent services.

  it 'retains constructor defaults and both AutoCheck controls' do
    expect(%w[RPORT THREADS AutoCheck ForceExploit VERBOSE].map { |key| mod.datastore[key] }).to eq([8021, 1, true, false, false])
  end

  it 'checks and scans both hosts in a public RHOSTS list' do
    mod.run

    expect(transport.attempts.map(&:first).sort).to eq(['192.0.2.10', '192.0.2.11'])
    expect(transport.checks.sort).to eq(['192.0.2.10', '192.0.2.11'])
  end

  it 'uses the real host-file walker before checking each service' do
    Tempfile.create('freeswitch-rhosts') do |file|
      file.write("192.0.2.10\n192.0.2.11\n")
      file.flush
      mod.datastore['RHOSTS'] = "file:#{file.path}"
      mod.run
    end

    expect(transport.attempts.map(&:first).sort).to eq(['192.0.2.10', '192.0.2.11'])
  end

  it 'dispatches real concurrent per-host workers when THREADS is two' do
    mod.datastore['THREADS'] = 2
    transport.barrier = true
    mod.run

    expect(transport.attempts.map(&:first).sort).to eq(['192.0.2.10', '192.0.2.11'])
  end

  it 'lets a healthy peer run after a refused-port Unknown host' do
    mod.datastore['RHOSTS'] = '192.0.2.12 192.0.2.10'
    mod.run

    expect(transport.attempts.map(&:first)).to eq(['192.0.2.10'])
  end

  it 'lets a healthy peer run after an ACL Safe host without authenticating to the ACL host' do
    mod.datastore['RHOSTS'] = '192.0.2.13 192.0.2.10'
    mod.run

    expect(transport.attempts.map(&:first)).to eq(['192.0.2.10'])
  end

  it 'keeps a rejected password on one host independent from a successful peer' do
    transport.passwords['192.0.2.11'] = 'DifferentPassword'
    mod.run

    expect(transport.attempts.map { |row| row.values_at(0, 3) }.sort).to eq([['192.0.2.10', true], ['192.0.2.11', false]])
  end

  it 'passes explicit nullable password-only identity to the invalidation API' do
    mod.datastore['AutoCheck'] = false
    transport.passwords['192.0.2.11'] = 'DifferentPassword'
    mod.run
    options = framework.invalidations.pop(true)

    expect(options.slice(:username, :private_data, :realm_key, :realm_value)).to eq(
      username: nil, private_data: 'ClueCon', realm_key: nil, realm_value: nil
    )
  end

  it 'preserves AutoCheck=false for the complete real scanner dispatch' do
    mod.datastore['AutoCheck'] = false
    mod.run

    expect(transport.attempts.map(&:first).sort).to eq(['192.0.2.10', '192.0.2.11'])
    expect(transport.checks).to eq([])
  end

  it 'retains ForceExploit for a refused ACL gate without cancelling its healthy peer' do
    mod.datastore['RHOSTS'] = '192.0.2.13 192.0.2.10'
    mod.datastore['ForceExploit'] = true
    mod.run

    expect(transport.checks.sort).to eq(['192.0.2.10', '192.0.2.13'])
    expect(transport.attempts.map(&:first)).to eq(['192.0.2.10'])
  end

  it 'preserves public host, port and thread options after a batch' do
    mod.datastore['RPORT'] = 18_021
    mod.datastore['THREADS'] = 2
    mod.run

    expect(%w[RHOSTS RPORT THREADS].map { |key| mod.datastore[key] }).to eq(['192.0.2.10 192.0.2.11', 18_021, 2])
    expect(transport.connections.map(&:last).uniq).to eq([18_021])
  end
end
