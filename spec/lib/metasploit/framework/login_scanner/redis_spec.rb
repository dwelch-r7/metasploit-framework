require 'spec_helper'
require 'metasploit/framework/login_scanner/redis'

RSpec.describe Metasploit::Framework::LoginScanner::Redis do
  let(:socket) { double('Socket') }
  let(:captures) do
    path = File.expand_path('../../../../file_fixtures/redis/protocol_6_0_11.json', __dir__)
    JSON.parse(File.read(path))
  end

  def update_socket_res(*res)
    allow(socket).to receive(:put)
    allow(socket).to receive(:get_once).and_return(*res)
    allow(subject).to receive(:sock).and_return(socket)
  end

  let(:credential) do
    cred = double('Credential')
    allow(cred).to receive(:public).and_return('USER')
    allow(cred).to receive(:private).and_return('PASSWORD')
    allow(cred).to receive(:realm).and_return('REALM')
    cred
  end

  subject do
    described_class.new
  end

  describe '#redis_proto' do
    let(:command_parts) do
      ['data']
    end

    it 'returns a String' do
      expect(subject.redis_proto(command_parts)).to be_kind_of(String)
    end

    it 'matches the stock redis-cli default-user UTF-8 AUTH request' do
      capture = captures.fetch('requests').fetch(2)
      arguments = ['AUTH', capture.fetch('username'), capture.fetch('password')]

      expect(subject.redis_proto(arguments)).to eq(Base64.strict_decode64(capture.fetch('packets_base64').first))
    end

    it 'retains the nil argument-list sentinel' do
      expect(subject.redis_proto(nil)).to be_nil
    end

    it 'retains the empty argument-list sentinel' do
      expect(subject.redis_proto([])).to be_nil
    end
  end

  describe '#attempt_login' do
    before do
      allow(subject).to receive(:connect)
      allow(subject).to receive(:disconnect)
      allow(subject).to receive(:select)
    end

    context 'with Redis version < 6' do
      context 'when server returns incorrect arguments' do
        let(:res) do
          [
            "-ERR wrong number of arguments for 'auth' command",
            '+OK'
          ]
        end

        before { update_socket_res(*res) }

        it 'successfully retries and gets the correct response' do
          expect(subject.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end

      context 'when server returns no password is set' do
        let(:res) { '-ERR Client sent AUTH, but no password is set' }

        before do
          update_socket_res(res)
        end

        it 'returns NO_AUTH_REQUIRED' do
          expect(subject.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::NO_AUTH_REQUIRED)
        end
      end

      context 'when server returns invalid password' do
        let(:res) { '-ERR invalid password' }

        before do
          update_socket_res(res)
        end

        it 'returns INCORRECT' do
          expect(subject.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        end
      end

      context 'when server returns OK' do
        let(:res) { '+OK' }

        before do
          update_socket_res(res)
        end

        it 'returns SUCCESSFUL' do
          expect(subject.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end
    end

    context 'with Redis version > 6' do
      context 'when a modern Redis reply ends with a period' do
        let(:res) { Base64.strict_decode64(captures.fetch('authentication_responses').fetch('wrong_password_modern')) }

        before { update_socket_res(res) }

        it 'preserves INCORRECT classification and the complete proof' do
          result = subject.attempt_login(credential)

          expect([result.status, result.proof]).to eq([Metasploit::Model::Login::Status::INCORRECT, res])
        end
      end

      context 'when Redis 6.0.11 returns its shorter invalid-password response' do
        let(:res) { Base64.strict_decode64(captures.fetch('authentication_responses').fetch('wrong_password')) }

        before { update_socket_res(res) }

        it 'returns INCORRECT with the exact observed proof bytes' do
          result = subject.attempt_login(credential)

          expect([result.status, result.proof]).to eq([Metasploit::Model::Login::Status::INCORRECT, res])
        end

        it 'can subsequently authenticate valid credentials on the same scanner' do
          update_socket_res(res, Base64.strict_decode64(captures.fetch('authentication_responses').fetch('okay')))
          first = subject.attempt_login(credential)
          second = subject.attempt_login(credential)

          expect([first.status, second.status]).to eq([Metasploit::Model::Login::Status::INCORRECT, Metasploit::Model::Login::Status::SUCCESSFUL])
        end
      end

      context 'when an unrelated response embeds a Redis-like error message' do
        let(:res) { '-ERR unrelated product: WRONGPASS invalid username-password pair or user is disabled' }

        before { update_socket_res(res) }

        it 'retains unknown status rather than treating an embedded substring as an AUTH result' do
          expect(subject.attempt_login(credential).status).to be_nil
        end
      end

      context 'when server returns no password is set' do
        let(:res) { '-ERR AUTH <password> called without any password configured for the default user. Are you sure your configuration is correct?' }

        before do
          update_socket_res(res)
        end

        it 'returns NO_AUTH_REQUIRED' do
          expect(subject.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::NO_AUTH_REQUIRED)
        end
      end

      context 'when server returns invalid password' do
        let(:res) { '-WRONGPASS invalid username-password pair or user is disabled' }

        before do
          update_socket_res(res)
        end

        it 'returns INCORRECT' do
          expect(subject.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        end
      end

      context 'when server returns OK' do
        let(:res) { '+OK' }

        before do
          update_socket_res(res)
        end

        it 'returns SUCCESSFUL' do
          expect(subject.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        end
      end
    end
  end

  describe '#set_sane_defaults' do
    context 'when initialized' do
      before(:each) do
        subject.send(:set_sane_defaults)
      end

      it 'sets the connection_timeout to 30' do
        expect(subject.connection_timeout).to be(30)
      end

      it 'sets the default port to 6379' do
        expect(subject.port).to be(6379)
      end

      it 'sets the max_send_size to 0' do
        expect(subject.max_send_size).to be(0)
      end

      it 'sets the send_delay to 0' do
        expect(subject.send_delay).to be(0)
      end
    end
  end

end
