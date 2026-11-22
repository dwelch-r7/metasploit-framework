# frozen_string_literal: true

require 'digest'
require 'openssl'

# Verify the ordinary package file before attributing native PHP outcomes.
module LinuxkiPhpRuntimeIdentity
  def self.capture(directory)
    specification = Gem.loaded_specs.fetch('metasploit-payloads')
    root = specification.full_gem_path
    manifest = File.binread(File.join(root, 'manifest'))
    uuid = File.binread(File.join(root, 'manifest.uuid')).strip
    raise 'Payload package manifest digest mismatch' unless OpenSSL::Digest.new('SHA3-256', manifest).hexdigest == uuid

    files = %w[meterpreter.php ext_server_stdapi.php].to_h do |name|
      path = MetasploitPayloads.path('meterpreter', name)
      expected = File.join(MetasploitPayloads.data_directory, 'meterpreter', name)
      raise "A local PHP runtime override is active: #{name}" unless File.realpath(path) == File.realpath(expected)

      row = manifest.lines.map { |line| line.strip.split(':') }.find { |entry| entry.first == './data/meterpreter/' + name }
      raise "No PHP runtime manifest entry: #{name}" unless row

      raw = File.binread(path)
      raise "Payload package PHP runtime digest mismatch: #{name}" unless OpenSSL::Digest.new(row[1], raw).hexdigest == row[2]

      decoded = MetasploitPayloads.read('meterpreter', name)
      File.binwrite(File.join(directory, 'ordinary-' + name), decoded)
      [name, { path: path, raw_sha256: Digest::SHA256.hexdigest(raw), decoded_sha256: Digest::SHA256.hexdigest(decoded) }]
    end
    {
      version: specification.version.to_s, files: files,
      read_source: MetasploitPayloads.method(:read).source_location,
      package_manifest_digest_valid: true, packaged_runtime_digest_valid: true, local_override: false
    }
  end
end
