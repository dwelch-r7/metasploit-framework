# frozen_string_literal: true

require 'net/http'
require 'json'
require 'digest'
require 'base64'

# Keep an actual HTTP response distinct from a refused last-owner connection.
uri = URI(ARGV.fetch(0))
begin
  response = Net::HTTP.start(uri.host, uri.port, nil, open_timeout: 3, read_timeout: 3) { |http| http.get(uri.request_uri) }
  puts JSON.generate(
    state: 'response', code: response.code.to_i, bytes: response.body.bytesize,
    sha256: Digest::SHA256.hexdigest(response.body),
    prefix_base64: Base64.strict_encode64(response.body.byteslice(0, 16))
  )
rescue Errno::ECONNREFUSED => e
  puts JSON.generate(state: 'refused', error: e.class.name, message: e.message)
end
