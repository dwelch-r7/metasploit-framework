# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'net/http'
require 'uri'

destination = ARGV.fetch(0)
FileUtils.mkdir_p(destination)
JSON.parse(File.read(File.join(__dir__, 'vendor.json'))).fetch('artifacts').each do |artifact|
  uri = URI(artifact.fetch('url'))
  raise ArgumentError, 'Unexpected vendor artifact origin' unless uri.scheme == 'https' && uri.host == 'repo.maven.apache.org'

  response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 20, read_timeout: 60) { |http| http.get(uri.request_uri) }
  raise IOError, "Vendor download failed: #{response.code}" unless response.is_a?(Net::HTTPSuccess)

  bytes = response.body
  raise IOError, 'Vendor SHA-256 mismatch' unless Digest::SHA256.hexdigest(bytes) == artifact.fetch('sha256')
  raise IOError, 'Vendor artifact size mismatch' unless bytes.bytesize == artifact.fetch('bytes')

  File.binwrite(File.join(destination, artifact.fetch('file')), bytes)
end
