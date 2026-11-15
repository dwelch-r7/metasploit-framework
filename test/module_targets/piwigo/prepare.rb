# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'open-uri'
require 'open3'
require 'zip'
require_relative '../../../tools/dev/run_guarded_module_target_tests'

# Existing WordPress preparation keeps archives intact. Piwigo needs its full
# application extracted before the ordinary web installer can run.
catalog = JSON.parse(File.read(File.join(__dir__, 'releases.json')))
versions = ARGV.empty? ? catalog.keys : ARGV
raise ArgumentError, 'Unsupported Piwigo release' unless (versions - catalog.keys).empty?

cache = File.expand_path('../../../tmp/module-target-piwigo-sources', __dir__)
FileUtils.mkdir_p([cache, File.dirname(GuardedModuleTargetTests::LOCK_PATH)])
File.open(GuardedModuleTargetTests::LOCK_PATH, File::RDWR | File::CREAT, 0o600) do |lock|
  raise 'Another module-target pipeline is active' unless lock.flock(File::LOCK_EX | File::LOCK_NB)

  lock.close_on_exec = true
  inventory, status = Open3.capture2('docker', 'ps', '--all', '--quiet')
  raise 'Finish existing containers before preparing Piwigo sources' unless status.success? && inventory.strip.empty?

  versions.each do |version|
    release = catalog.fetch(version)
    archive = File.join(cache, "#{version}.zip")
    unless File.file?(archive) && Digest::SHA256.file(archive).hexdigest == release.fetch('sha256')
      temporary = "#{archive}.partial"
      begin
        URI.parse(release.fetch('url')).open(open_timeout: 20, read_timeout: 60) do |input|
          File.open(temporary, 'wb') { |file| IO.copy_stream(input, file) }
        end
        raise IOError, "Piwigo #{version} checksum differs" unless Digest::SHA256.file(temporary).hexdigest == release.fetch('sha256')

        File.rename(temporary, archive)
      ensure
        FileUtils.rm_f(temporary)
      end
    end
    raise IOError, "Piwigo #{version} length differs" unless File.size(archive) == release.fetch('bytes')

    extracted = File.join(cache, version)
    digests = {}
    Zip::File.open(archive) do |zip|
      zip.each do |entry|
        components = entry.name.split('/')
        unless components.first == 'piwigo' && !components.intersect?(%w[. ..]) && !entry.name.include?('\\') && !entry.symlink?
          raise IOError, "Unsafe Piwigo archive entry: #{entry.name}"
        end
        next if entry.directory?

        data = entry.get_input_stream.read
        destination = File.join(extracted, entry.name)
        FileUtils.mkdir_p(File.dirname(destination))
        File.binwrite(destination, data)
        digests[entry.name] = Digest::SHA256.hexdigest(data)
      end
    end
    actual = Dir.glob(File.join(extracted, '**', '*'), File::FNM_DOTMATCH).select { |name| File.file?(name) }
    expected = digests.keys.map { |name| File.join(extracted, name) }
    raise IOError, 'Extracted Piwigo files differ' unless actual.sort == expected.sort && expected.all? { |name| Digest::SHA256.file(name).hexdigest == digests.fetch(name.delete_prefix(extracted + '/')) }

    File.write(File.join(cache, "#{version}-files.json"), JSON.pretty_generate(digests.sort.to_h) + "\n")
    puts JSON.generate(version: version, verified: true, files: digests.length, sha256: release.fetch('sha256'))
  end
end
