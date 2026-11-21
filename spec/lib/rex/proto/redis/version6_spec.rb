require 'spec_helper'
require 'rex/proto/redis/version6'

RSpec.describe Rex::Proto::Redis::Version6::Constants do
  let(:captures) do
    path = File.expand_path('../../../../file_fixtures/redis/protocol_6_0_11.json', __dir__)
    JSON.parse(File.read(path))
  end
  describe 'WRONG_PASSWORD' do
    subject(:pattern) { described_class::WRONG_PASSWORD }

    it 'captures the observed Redis 6.0.11 message without protocol framing' do
      response = Base64.strict_decode64(captures.fetch('authentication_responses').fetch('wrong_password'))

      expect(pattern.match(response)&.[](:auth_response)).to eq('WRONGPASS invalid username-password pair')
    end

    it 'retains the existing longer Redis 6 message and named capture' do
      response = "-WRONGPASS invalid username-password pair or user is disabled\r\n"

      expect(pattern.match(response)&.[](:auth_response)).to eq('WRONGPASS invalid username-password pair or user is disabled')
    end

    it 'accepts modern punctuation while retaining the original named capture' do
      response = Base64.strict_decode64(captures.fetch('authentication_responses').fetch('wrong_password_modern'))

      expect(pattern.match(response)&.[](:auth_response)).to eq('WRONGPASS invalid username-password pair or user is disabled')
    end

    it 'retains the established unframed response contract' do
      expect(pattern.match('WRONGPASS invalid username-password pair or user is disabled')).not_to be_nil
    end

    it 'does not accept additional unrelated error text' do
      expect(pattern.match("-WRONGPASS invalid username-password pair or user is disabled by another product\r\n")).to be_nil
    end

    it 'does not accept a prefix from another protocol or product' do
      expect(pattern.match("Other service: WRONGPASS invalid username-password pair or user is disabled\r\n")).to be_nil
    end

    it 'does not accept an incomplete message' do
      expect(pattern.match("-WRONGPASS invalid username-password\r\n")).to be_nil
    end

    it 'does not accept unrelated Redis errors' do
      expect(pattern.match("-WRONGTYPE Operation against a key holding the wrong kind of value\r\n")).to be_nil
    end
  end
end
