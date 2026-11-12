# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'net/http'
require 'open3'
require 'rubygems/package'
require 'time'
require 'zip'
require 'zlib'

component = File.expand_path(__dir__)
root = File.expand_path('../../..', component)
catalog = JSON.parse(File.read(File.join(component, 'vendor.json')))
versions = ARGV.empty? ? catalog.keys : ARGV
raise ArgumentError, 'Unsupported Spring Cloud Config release' unless (versions - catalog.keys).empty?

cache = File.join(root, 'tmp', 'module-target-springcloud-artifacts')
FileUtils.mkdir_p(cache)

# Stream immutable layers without adding them to the Docker backing filesystem.
# Registry redirects receive a new request, with no cross-host bearer header.
def download(uri, destination, token: nil, redirects: 5)
  raise IOError, 'Too many vendor redirects' if redirects.zero?
  raise ArgumentError, 'Vendor downloads require HTTPS' unless uri.scheme == 'https'

  request = Net::HTTP::Get.new(uri)
  request['Authorization'] = "Bearer #{token}" if token && uri.host == 'registry-1.docker.io'
  location = nil
  Net::HTTP.start(uri.host, uri.port, nil, use_ssl: true, open_timeout: 20, read_timeout: 60) do |http|
    http.request(request) do |response|
      if response.is_a?(Net::HTTPRedirection)
        location = URI.join(uri, response.fetch('location'))
      else
        raise IOError, "Vendor download failed: HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

        File.open(destination, 'wb') { |file| response.read_body { |chunk| file.write(chunk) } }
      end
    end
  end
  download(location, destination, redirects: redirects - 1) if location
end

def verified?(path, record)
  return false unless File.file?(path) && Digest::SHA256.file(path).hexdigest == record.fetch('jar_sha256')

  Zip::File.open(path) do |archive|
    record.fetch('config_libraries').all? do |name, digest|
      entry = archive.find_entry(name)
      entry && Digest::SHA256.hexdigest(entry.get_input_stream.read) == digest
    end
  end
end

File.open(File.join(cache, 'prepare.lock'), 'w') do |lock|
  raise 'Another Spring Cloud Config preparation is active' unless lock.flock(File::LOCK_EX | File::LOCK_NB)

  inventory, status = Open3.capture2('docker', 'ps', '--all', '--quiet')
  raise 'Finish the current container pipeline before preparing artifacts' unless status.success? && inventory.strip.empty?

  versions.each do |version|
    record = catalog.fetch(version)
    artifact = File.join(cache, "#{version}.jar")
    repaired = !verified?(artifact, record)
    if repaired
      layer = File.join(cache, "#{version}.layer.tgz")
      digest = record.fetch('layer').fetch('digest').delete_prefix('sha256:')
      unless File.file?(layer) && Digest::SHA256.file(layer).hexdigest == digest
        token_file = File.join(cache, 'registry-token.json')
        begin
          download(URI("https://auth.docker.io/token?service=registry.docker.io&scope=repository:#{record.fetch('image')}:pull"), token_file)
          token = JSON.parse(File.read(token_file)).fetch('token')
        ensure
          FileUtils.rm_f(token_file)
        end
        temporary = "#{layer}.partial"
        begin
          download(URI("https://registry-1.docker.io/v2/#{record.fetch('image')}/blobs/#{record.fetch('layer').fetch('digest')}"), temporary, token: token)
          raise IOError, "Vendor layer checksum differs for #{version}" unless Digest::SHA256.file(temporary).hexdigest == digest

          File.rename(temporary, layer)
        ensure
          FileUtils.rm_f(temporary)
        end
      end
      raise IOError, 'Vendor layer length differs' unless File.size(layer) == record.fetch('layer').fetch('size')

      temporary = "#{artifact}.partial"
      begin
        Zlib::GzipReader.open(layer) do |gzip|
          Gem::Package::TarReader.new(gzip) do |archive|
            archive.each do |entry|
              next unless entry.file? && entry.full_name == record.fetch('jar_path')

              File.open(temporary, 'wb') do |file|
                file.write(entry.read(1024 * 1024)) until entry.eof?
              end
              break
            end
          end
        end
        raise IOError, "Extracted artifact differs for #{version}" unless verified?(temporary, record)

        File.rename(temporary, artifact)
      ensure
        FileUtils.rm_f(temporary)
      end
    end
    puts JSON.generate(version: version, verified: true, repaired: repaired, jar_sha256: record.fetch('jar_sha256'), official_libraries: record.fetch('config_libraries').length)
  end
  proof = File.join(cache, 'proof')
  FileUtils.mkdir_p(proof)
  File.binwrite(File.join(proof, 'binary.bin'), (0..255).to_a.pack('C*'))
end
