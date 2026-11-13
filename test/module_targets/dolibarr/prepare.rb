# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'open-uri'
require 'open3'
require 'rubygems/package'
require 'zlib'
require 'yaml'
require_relative '../../../tools/dev/run_guarded_module_target_tests'

component = File.expand_path(__dir__)
root = File.expand_path('../../..', component)
catalog = JSON.parse(File.read(File.join(component, 'vendor.json')))
source_cache = File.join(root, 'tmp', 'module-target-dolibarr-sources')
runtime = catalog.fetch('runtime')
runtime_cache = File.join(root, 'tmp', 'module-target-dolibarr-runtime', "php-#{runtime.fetch('version')}")
FileUtils.mkdir_p([source_cache, runtime_cache, File.dirname(GuardedModuleTargetTests::LOCK_PATH)])

# Original source archives contain only regular files and directories. Refuse
# unexpected archive paths/types rather than interpreting them as local paths.
def extract_source(archive, directory, prefix)
  Zlib::GzipReader.open(archive) do |gzip|
    Gem::Package::TarReader.new(gzip) do |tar|
      tar.each do |entry|
        next if entry.full_name == 'pax_global_header' && entry.header.typeflag == 'g'

        parts = entry.full_name.split('/')
        raise IOError, 'Unexpected source archive root' unless parts.shift == prefix
        raise IOError, 'Unsafe source archive path' if parts.include?('..') || parts.include?('')
        next unless parts.first == 'htdocs' || %w[COPYING COPYRIGHT README.md].include?(parts.first)

        destination = File.join(directory, *parts)
        if entry.directory?
          FileUtils.mkdir_p(destination)
        elsif entry.file?
          FileUtils.mkdir_p(File.dirname(destination))
          File.open(destination, 'wb') { |file| file.write(entry.read(1024 * 1024)) until entry.eof? }
        else
          raise IOError, 'Unexpected source archive entry type'
        end
      end
    end
  end
end

File.open(GuardedModuleTargetTests::LOCK_PATH, File::RDWR | File::CREAT, 0o600) do |lock|
  raise 'Another module-target pipeline is active' unless lock.flock(File::LOCK_EX | File::LOCK_NB)

  lock.close_on_exec = true
  inventory, status = Open3.capture2('docker', 'ps', '--all', '--quiet')
  raise 'Finish existing containers before preparing Dolibarr' unless status.success? && inventory.strip.empty?

  catalog.fetch('versions').each do |version, record|
    directory = File.join(source_cache, version, 'source')
    verified = record.fetch('source_files').all? do |name, file|
      path = File.join(directory, name)
      File.file?(path) && Digest::SHA256.file(path).hexdigest == file.fetch('sha256')
    end
    unless verified
      archive = File.join(source_cache, "#{version}.tar.gz")
      unless File.file?(archive) && Digest::SHA256.file(archive).hexdigest == record.fetch('archive_sha256')
        temporary = "#{archive}.partial"
        begin
          URI.parse(record.fetch('url')).open(open_timeout: 20, read_timeout: 60) do |input|
            File.open(temporary, 'wb') { |file| IO.copy_stream(input, file) }
          end
          raise IOError, "Dolibarr #{version} archive checksum differs" unless Digest::SHA256.file(temporary).hexdigest == record.fetch('archive_sha256')

          File.rename(temporary, archive)
        ensure
          FileUtils.rm_f(temporary)
        end
      end
      FileUtils.rm_rf(directory)
      FileUtils.mkdir_p(directory)
      extract_source(archive, directory, "dolibarr-#{record.fetch('commit')}")
      record.fetch('source_files').each do |name, file|
        raise IOError, "Dolibarr #{version} source differs: #{name}" unless Digest::SHA256.file(File.join(directory, name)).hexdigest == file.fetch('sha256')
      end
    end
    puts JSON.generate(version: version, verified: true, source_files: record.fetch('source_files').size)
  end

  extension = File.join(runtime_cache, 'mysqli.so')
  unless File.file?(extension) && Digest::SHA256.file(extension).hexdigest == runtime.fetch('mysqli_sha256')
    File.chmod(0o777, runtime_cache)
    image = YAML.safe_load_file(File.join(component, 'compose.yaml')).fetch('services').fetch('target').fetch('image')
    name = "msf-target-dolibarr-prepare-#{Process.pid}"
    argv = [
      'docker', 'create', '--name', name, '--platform', 'linux/amd64', '--network', 'none',
      '--label', "com.docker.compose.project=#{name}", '--label', 'com.docker.compose.service=prepare',
      '--user', '1000:1000', '--memory', '384m', '--memory-swap', '384m', '--cpus', '0.7', '--pids-limit', '96',
      '--read-only', '--tmpfs', '/tmp:size=64m,mode=1777,exec',
      '--volume', "#{component}:/lab:ro", '--volume', "#{runtime_cache}:/output", '--entrypoint', '/bin/sh',
      image, '/lab/runtime-build.sh'
    ]
    output, status = Open3.capture2e(*argv)
    raise IOError, "Runtime container creation failed: #{output}" unless status.success?

    identifier = output.strip
    raise IOError, 'Unexpected runtime container ID' unless identifier.match?(/\A[0-9a-f]{64}\z/)

    evidence = File.join(runtime_cache, "prepare-#{Time.now.utc.strftime('%Y%m%dT%H%M%S')}-#{Process.pid}.json")
    receipt = { argv: argv, container: JSON.parse(Open3.capture2('docker', 'inspect', identifier).first).first }
    begin
      process = Process.spawn('docker', 'start', '--attach', identifier)
      _, completed = Process.wait2(process)
      receipt[:start_pid] = process
      receipt[:actual_exit] = completed.exitstatus
      raise IOError, 'mysqli compilation failed' unless completed.success?
      raise IOError, 'Compiled mysqli checksum differs' unless Digest::SHA256.file(extension).hexdigest == runtime.fetch('mysqli_sha256')
    ensure
      details, inspected = Open3.capture2('docker', 'inspect', identifier)
      receipt[:final_container] = JSON.parse(details).first if inspected.success?
      output, removed = Open3.capture2e('docker', 'rm', '--force', identifier)
      receipt[:removal_actual_exit] = removed.exitstatus
      File.write(evidence, JSON.pretty_generate(receipt) + "\n")
      raise IOError, "Runtime container removal failed: #{output}" unless removed.success?
    end
  end
  puts JSON.generate(php: runtime.fetch('version'), mysqli_verified: true, extension_sha256: Digest::SHA256.file(extension).hexdigest)
end
