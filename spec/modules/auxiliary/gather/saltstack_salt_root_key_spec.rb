require 'rspec'
require 'msfenv'
require 'msf/base'
require 'msgpack'
require 'stringio'

RSpec.describe 'Salt root key response framing' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('SALT_ROOT_KEY_UNIT_MODULE', File.expand_path('../../../../modules/auxiliary/gather/saltstack_salt_root_key.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:root_key) { 'unit-root-key' }
  let(:auth_info) { ['user', 'UserAuthenticationError', { 'root' => root_key }] }
  let(:body) { auth_info.to_msgpack }
  let(:wire) { "\x01\x00".b + frame(body) }
  let(:stream) { StringIO.new(wire) }
  let(:segment_size) { nil }
  let(:socket) { double('Rex TCP stream') }
  let(:sent) { [] }
  let(:credentials) { [] }
  let(:errors) { [] }

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    allow(mod).to receive_messages(zmq_connect: nil, zmq_negotiate: nil, zmq_disconnect: nil, print_status: nil, print_good: nil, vprint_good: nil, fullname: 'auxiliary/gather/saltstack_salt_root_key', myworkspace_id: 1)
    allow(mod).to receive(:print_error) { |text| errors << text }
    allow(mod).to receive(:create_credential_and_login) { |data| credentials << data }
    allow(mod).to receive(:sock).and_return(socket)
    allow(socket).to receive(:put) { |data| sent << data }
    allow(socket).to receive(:get_once) do |length = -1, _timeout = nil|
      length = stream.size if length == -1
      length = [length, segment_size].min if segment_size
      stream.read(length)
    end
  end

  # Synthetic MessagePack fixtures preserve the native response structure
  # verified by native_client.py in run 20261112T053535-27a580. The genuine
  # default response is 116 bytes; publisher_acl users bin/daemon/nobody/root
  # yield 371 bytes and require a long frame. Keys below are unit-only data.
  # Socket, handshake, output and credential persistence are explicit doubles;
  # module initialization, serialization, framing, unpacking and run stay real.
  it 'extracts the key from an existing short response' do
    expect(mod.extract_root_key(mod.yeet_prep_auth_info)).to eq(root_key)
  end

  it 'preserves the vulnerable CheckCode and root key reason for a short response' do
    result = mod.run

    expect([result, result.reason]).to eq([Msf::Exploit::CheckCode::Vulnerable, root_key])
  end

  it 'preserves the credential reporting arguments' do
    mod.run

    expect(credentials).to eq([
      {
        workspace_id: 1, module_fullname: 'auxiliary/gather/saltstack_salt_root_key',
        origin_type: :service, address: '192.0.2.1', port: 4506, protocol: 'tcp',
        service_name: 'salt/zeromq', username: 'root', private_data: root_key,
        private_type: :password
      }
    ])
  end

  it 'retains the existing clear request serialization' do
    mod.yeet_prep_auth_info

    expect(MessagePack.unpack(sent.fetch(0).byteslice(11..))).to eq('enc' => 'clear', 'load' => { 'cmd' => '_prep_auth_info' })
  end

  context 'publisher_acl expands the response beyond a short frame' do
    let(:root_key) { 'unit-root-' + ('r' * 64) }
    let(:auth_info) do
      [
        'user', 'UserAuthenticationError',
        {
          'bin' => 'unit-bin-' + ('b' * 64),
          'daemon' => 'unit-daemon-' + ('d' * 64),
          'nobody' => 'unit-nobody-' + ('n' * 64),
          'root' => root_key
        }
      ]
    end

    it 'extracts the root key after decoding a 64-bit frame length' do
      expect(mod.extract_root_key(mod.yeet_prep_auth_info)).to eq(root_key)
    end

    it 'returns Vulnerable with the root key as its reason' do
      result = mod.run

      expect([result, result.reason]).to eq([Msf::Exploit::CheckCode::Vulnerable, root_key])
    end

    it 'persists the decoded root credential' do
      mod.run

      expect(credentials).to contain_exactly(include(username: 'root', private_data: root_key))
    end

    context 'one-byte TCP fragments' do
      let(:segment_size) { 1 }

      it 'extracts a complete root key after fragmented delimiter, length and body' do
        expect(mod.extract_root_key(mod.yeet_prep_auth_info)).to eq(root_key)
      end
    end
  end

  context 'a fragmented short response' do
    let(:segment_size) { 1 }

    it 'does not validate or deserialize a partial frame' do
      expect(mod.extract_root_key(mod.yeet_prep_auth_info)).to eq(root_key)
    end
  end

  context 'another response coalesced on the same TCP stream' do
    let(:wire) { "\x01\x00".b + frame(body) + "\x01\x00".b + frame(body) }

    it 'decodes one reply at a time' do
      expect([mod.extract_root_key(mod.yeet_prep_auth_info), mod.extract_root_key(mod.yeet_prep_auth_info)]).to eq([root_key, root_key])
    end
  end

  context 'the patched master response' do
    let(:auth_info) { {} }

    it 'preserves the existing unexpected-auth-info failure and reports no credential' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /Did not receive serialized auth info/)
      expect(credentials).to be_empty
    end
  end

  context 'the peer closes the connection' do
    before { allow(socket).to receive(:get_once).and_raise(EOFError) }

    it 'retains a reason-bearing Unknown check and disconnects' do
      result = mod.run

      expect([result, result.reason]).to eq([Msf::Exploit::CheckCode::Unknown, 'Connection error occurred'])
      expect(mod).to have_received(:zmq_disconnect)
    end
  end

  def frame(payload)
    if payload.bytesize > 255
      "\x02".b + [payload.bytesize].pack('Q>') + payload
    else
      [0, payload.bytesize].pack('CC') + payload
    end
  end
end
