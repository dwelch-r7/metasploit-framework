require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'FreeSWITCH event-socket check contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    source = File.expand_path('../../../../../modules/auxiliary/scanner/misc/freeswitch_event_socket_login.rb', __dir__)
    scope = Module.new
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:auth_request) { "Content-Type: auth/request\n\n" }
  let(:acl_rejection) { "Content-Type: text/rude-rejection\nContent-Length: 24\n\nAccess Denied, go away.\n" }
  let(:ssh_banner) { "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.18\r\n" }
  let(:banner) { auth_request }
  let(:socket) { double('event socket', get: banner, shutdown: nil, close: nil) }

  before do
    mod.datastore['RHOST'] = '192.0.2.17'
    allow(mod).to receive(:connect) do
      mod.send(:sock=, socket)
      mod.add_socket(socket)
    end
    allow(mod).to receive(:elog)
  end

  # Banner bytes come from the genuine FreeSWITCH 1.10.10 and OpenSSH 8.9p1
  # serial lab. Connection/read operations and logging are doubles. Owner
  # initialization, classification and the TCP disconnect helper are real.
  # Exception and nil/empty cases below are synthetic boundary regressions.

  it 'keeps the conventional event-socket default port' do
    expect(mod.datastore['RPORT']).to eq(8021)
  end

  it 'preserves an operator-selected port while checking' do
    mod.datastore['RPORT'] = 18_021
    mod.check_host('192.0.2.17')

    expect(mod.datastore['RPORT']).to eq(18_021)
  end

  it 'recognizes the native authentication request with its existing reason' do
    expect(mod.check_host('192.0.2.17')).to have_attributes(
      code: 'appears', reason: 'FreeSWITCH event socket is accepting authentication requests'
    )
  end

  context 'with the native ACL rejection' do
    let(:banner) { acl_rejection }

    it 'recognizes both the split native header and complete ACL frame' do
      allow(socket).to receive(:get).and_return("Content-Type: text/rude-rejection\nContent-Length: 24\n\n", acl_rejection)
      results = [mod.check_host('192.0.2.17'), mod.check_host('192.0.2.17')]

      expect(results).to all(have_attributes(code: 'safe', reason: 'Access denied by network ACL'))
    end
  end

  context 'with the native unrelated OpenSSH banner' do
    let(:banner) { ssh_banner }

    it 'returns the existing reason-bearing unknown result' do
      expect(mod.check_host('192.0.2.17')).to have_attributes(code: 'unknown', reason: 'Unable to determine the service fingerprint')
    end
  end

  context 'with a nil banner' do
    let(:banner) { nil }

    it 'returns a reason-bearing unknown result' do
      expect(mod.check_host('192.0.2.17')).to have_attributes(code: 'unknown', reason: match(/\S/))
    end
  end

  context 'with an empty banner' do
    let(:banner) { '' }

    it 'returns a reason-bearing unknown result' do
      expect(mod.check_host('192.0.2.17')).to have_attributes(code: 'unknown', reason: match(/\S/))
    end
  end

  context 'when connection establishment fails' do
    it 'returns an unknown result for the reproduced refused-port error' do
      error = Rex::ConnectionRefused.new('192.0.2.17', 1)
      allow(mod).to receive(:connect).and_raise(error)

      expect(mod.check_host('192.0.2.17')).to have_attributes(code: 'unknown', reason: include('banner', error.message))
    end

    it 'returns an unknown result for a connection timeout' do
      error = Rex::ConnectionTimeout.new('192.0.2.17', 8021)
      allow(mod).to receive(:connect).and_raise(error)

      expect(mod.check_host('192.0.2.17')).to have_attributes(code: 'unknown', reason: include('banner', error.message))
    end

    it 'runs the existing disconnect helper after a refused connection' do
      allow(mod).to receive(:connect).and_raise(Rex::ConnectionRefused.new('192.0.2.17', 1))
      expect(mod).to receive(:disconnect).once.and_call_original

      mod.check_host('192.0.2.17')
    end
  end

  context 'when reading the banner fails' do
    [
      ['a Ruby timeout', ::Timeout::Error, 'Banner read timed out'],
      ['a Rex timeout', Rex::TimeoutError, 'Rex banner read timed out'],
      ['a connection reset', Errno::ECONNRESET, 'Banner connection reset'],
      ['EOF', ::EOFError, 'Peer closed before its banner'],
      ['a closed Rex stream', Rex::StreamClosedError, 'Event socket stream closed'],
      ['a closed Ruby stream', ::IOError, 'Stream is closed']
    ].each do |description, error_class, message|
      it "returns an unknown result for #{description}" do
        error = error_class.new(message)
        allow(socket).to receive(:get).and_raise(error)

        result = nil
        # Rex::TimeoutError inherits Interrupt; the matcher reports it as an
        # expectation failure rather than interrupting the suite.
        expect { result = mod.check_host('192.0.2.17') }.not_to raise_error
        expect(result).to have_attributes(code: 'unknown', reason: include('banner', error.message))
      end
    end

    it 'closes and unregisters the socket after a read error' do
      allow(socket).to receive(:get).and_raise(EOFError, 'Peer closed before its banner')
      expect(socket).to receive(:close).once
      mod.check_host('192.0.2.17')

      expect([mod.send(:sock), mod.send(:sockets)]).to eq([nil, []])
    end
  end

  it 'preserves a user interrupt while closing the socket' do
    allow(socket).to receive(:get).and_raise(Interrupt, 'User interrupted the check')
    expect(socket).to receive(:close).once

    expect { mod.check_host('192.0.2.17') }.to raise_error(Interrupt, 'User interrupted the check')
  end

  it 'does not hide an unexpected programming error while closing the socket' do
    allow(socket).to receive(:get).and_raise(ArgumentError, 'Unexpected banner parser failure')
    expect(socket).to receive(:close).once

    expect { mod.check_host('192.0.2.17') }.to raise_error(ArgumentError, 'Unexpected banner parser failure')
  end

  it 'closes and unregisters the socket after a successful check' do
    expect(socket).to receive(:close).once
    mod.check_host('192.0.2.17')

    expect([mod.send(:sock), mod.send(:sockets)]).to eq([nil, []])
  end

  it 'can check again after a failed banner read without retaining socket state' do
    allow(socket).to receive(:get).and_raise(EOFError, 'Peer closed before its banner')
    first = mod.check_host('192.0.2.17')
    allow(socket).to receive(:get).and_return(auth_request)
    second = mod.check_host('192.0.2.17')

    expect([first.code, second.code, mod.send(:sock), mod.send(:sockets)]).to eq(['unknown', 'appears', nil, []])
  end
end
