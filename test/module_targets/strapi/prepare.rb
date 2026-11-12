# frozen_string_literal: true

require 'English'
require 'fileutils'
require 'json'
require 'open3'
require 'time'
require 'yaml'

component = File.expand_path(__dir__)
root = File.expand_path('../../..', component)
cache = File.join(root, 'tmp', 'module-target-strapi-dependencies')
available = JSON.parse(File.read(File.join(component, 'vendor.json'))).keys
versions = ARGV.empty? ? available : ARGV
raise ArgumentError, 'Unsupported release' unless (versions - available).empty?

image = YAML.safe_load(File.read(File.join(component, 'compose.yaml'))).fetch('services').fetch('target').fetch('image')

FileUtils.mkdir_p(cache)
FileUtils.mkdir_p(File.join(cache, 'npm-cache'))
File.chmod(0o777, File.join(cache, 'npm-cache'))
File.open(File.join(cache, 'prepare.lock'), 'w') do |lock|
  raise 'Another Strapi preparation is active' unless lock.flock(File::LOCK_EX | File::LOCK_NB)

  inventory, status = Open3.capture2('docker', 'ps', '--all', '--quiet')
  raise 'Finish the current container pipeline before preparing Strapi' unless status.success? && inventory.strip.empty?

  versions.each do |version|
    directory = File.join(cache, version)
    FileUtils.mkdir_p(directory)
    File.chmod(0o777, directory)
    %w[package.json package-lock.json].each do |name|
      FileUtils.cp(File.join(component, 'packages', version, name), File.join(directory, name))
    end
    name = "msf-target-strapi-prepare-#{Process.pid}-#{version.delete('.')}"
    argv = [
      'docker', 'create', '--name', name, '--init', '--platform', 'linux/amd64',
      '--label', "com.docker.compose.project=#{name}", '--label', 'com.docker.compose.service=prepare',
      '--user', 'node', '--cpus', '0.7', '--memory', '768m', '--memory-swap', '768m', '--pids-limit', '128',
      '--workdir', '/runtime', '--volume', "#{directory}:/runtime", '--volume', "#{component}:/lab:ro",
      '--volume', "#{cache}/npm-cache:/npm-cache", '--env', 'NODE_OPTIONS=--max-old-space-size=256',
      '--env', 'NPM_CONFIG_CACHE=/npm-cache', '--env', 'npm_config_maxsockets=2', '--env', 'npm_config_prefer_offline=true',
      '--entrypoint', '/bin/sh', image,
      '/lab/prepare.sh', version
    ]
    output, status = Open3.capture2e(*argv)
    raise "Failed to create dependency container: #{output}" unless status.success?

    identifier = output.lines.map(&:strip).reverse.find { |line| line.match?(/\A[0-9a-f]{64}\z/) }
    raise "Unexpected dependency container output: #{output}" unless identifier

    evidence = File.join(cache, 'preparations', "#{Time.now.utc.strftime('%Y%m%dT%H%M%S')}-#{Process.pid}")
    FileUtils.mkdir_p(evidence)
    details, inspected = Open3.capture2e('docker', 'inspect', identifier)
    raise "Failed to inspect dependency container: #{details}" unless inspected.success?

    container = JSON.parse(details).first
    raise 'Dependency container ownership differs' unless container.fetch('Config').fetch('Labels').fetch('com.docker.compose.project') == name

    receipt = { version: version, argv: argv, container: container }
    begin
      puts "Preparing #{version} in #{identifier}"
      $stdout.flush
      success = system('docker', 'start', '--attach', identifier)
      receipt[:start_pid] = $CHILD_STATUS.pid
      receipt[:actual_exit] = $CHILD_STATUS.exitstatus
      raise "Dependency preparation failed for #{version}" unless success
    ensure
      details, inspected = Open3.capture2e('docker', 'inspect', identifier)
      receipt[:final_container] = JSON.parse(details).first if inspected.success?
      removed = system('docker', 'rm', '--force', identifier)
      receipt[:removal_actual_exit] = $CHILD_STATUS.exitstatus
      File.write(File.join(evidence, "#{version}.json"), JSON.pretty_generate(receipt) + "\n")
      raise "Failed to remove dependency container #{identifier}" unless removed
    end
    output, status = Open3.capture2e('docker', 'ps', '--all', '--quiet', '--filter', "label=com.docker.compose.project=#{name}")
    raise "Dependency container remains: #{output}" unless status.success? && output.strip.empty?
  end
end
