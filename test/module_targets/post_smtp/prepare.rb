# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'open-uri'
require 'open3'
require_relative '../../../tools/dev/run_guarded_module_target_tests'

catalog = JSON.parse(File.read(File.join(__dir__, 'releases.json')))
cache = File.expand_path('../../../tmp/module-target-post-smtp-sources', __dir__)
FileUtils.mkdir_p([cache, File.dirname(GuardedModuleTargetTests::LOCK_PATH)])

File.open(GuardedModuleTargetTests::LOCK_PATH, File::RDWR | File::CREAT, 0o600) do |lock|
  raise 'Another module-target pipeline is active' unless lock.flock(File::LOCK_EX | File::LOCK_NB)

  lock.close_on_exec = true
  inventory, status = Open3.capture2('docker', 'ps', '--all', '--quiet')
  raise 'Finish existing containers before preparing POST SMTP' unless status.success? && inventory.strip.empty?

  catalog.each do |version, release|
    archive = File.join(cache, "#{version}.zip")
    unless File.file?(archive) && Digest::SHA256.file(archive).hexdigest == release.fetch('sha256')
      temporary = "#{archive}.partial"
      begin
        URI.parse(release.fetch('url')).open(open_timeout: 20, read_timeout: 60) do |input|
          File.open(temporary, 'wb') { |file| IO.copy_stream(input, file) }
        end
        raise IOError, "POST SMTP #{version} checksum differs" unless Digest::SHA256.file(temporary).hexdigest == release.fetch('sha256')

        File.rename(temporary, archive)
      ensure
        FileUtils.rm_f(temporary)
      end
    end
    puts JSON.generate(version: version, sha256: Digest::SHA256.file(archive).hexdigest, verified: true)
  end
end
