#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'open3'
require 'securerandom'
require 'time'
require 'timeout'
require 'yaml'

# Owns only one fresh Compose project at a time. Target data and console state
# must never leak between runs or into the developer's normal ~/.msf4 directory.
class ModuleTargetTests
  ROOT = File.expand_path('../..', __dir__)
  TARGETS = File.join(ROOT, 'test/module_targets')
  # The canonical Dockerfile's dependency-stage inputs plus the files its final
  # build steps require. Runtime source comes from the read-only worktree mount,
  # so editing a test/module does not rebuild or chown the entire Framework tree.
  CONSOLE_BUILD_FILES = %w[
    Gemfile Gemfile.lock Gemfile.local.example metasploit-framework.gemspec Rakefile .dockerignore
    lib/metasploit/framework/version.rb lib/metasploit/framework/rails_version_constraint.rb lib/msf/util/helper.rb
    docker/entrypoint.sh docker/database.yml docker/msfconsole.rc docker/remove_distrusted_cas.rb
  ].freeze

  def initialize
    @run_id = "#{Time.now.utc.strftime('%Y%m%dT%H%M%S')}-#{SecureRandom.hex(3)}"
    @results = File.join(ROOT, 'tmp/module-target-tests', @run_id)
  end

  def run(arguments)
    $stdout.sync = true
    available = Dir[File.join(TARGETS, '*/manifest.yml')].map { |path| File.basename(File.dirname(path)) }.sort
    if arguments == ['--list']
      puts available
      return 0
    end
    selected = arguments == ['--all'] ? available : arguments
    if selected.empty? || (selected - available).any?
      warn 'Usage: bundle exec ruby tools/dev/run_module_target_tests.rb --list | --all | FAMILY [FAMILY ...]'
      warn "Available: #{available.join(', ')}"
      return 2
    end

    FileUtils.mkdir_p(@results)
    puts "Evidence: #{@results}"
    statuses = selected.uniq.map { |family| run_family(family) }
    File.write(File.join(@results, 'summary.json'), JSON.pretty_generate(statuses))
    statuses.all? { |status| status[:status] == 'passed' } ? 0 : 1
  end

  private

  def command(argv, path:, env: {}, timeout: 180, capture: nil, quiet: false)
    File.open(path, 'a') do |log|
      log.puts("$ #{argv.inspect}")
      Open3.popen2e(env, *argv, chdir: ROOT, pgroup: true) do |stdin, output, waiter|
        stdin.close
        reader = Thread.new do
          output.each_line do |line|
            log.write(line)
            log.flush
            capture << line if capture
            $stdout.write(line) unless quiet
          end
        end
        begin
          raise Timeout::Error, "Command exceeded #{timeout}s" unless waiter.join(timeout)

          reader.join(5)
          waiter.value.success?
        ensure
          # A timed-out console may have children, including payload handlers.
          if waiter.alive?
            begin
              Process.kill('TERM', -waiter.pid)
              waiter.join(5)
              Process.kill('KILL', -waiter.pid) if waiter.alive?
            rescue Errno::ESRCH
              nil
            rescue Errno::EPERM => e
              log.puts("Process-group cleanup denied: #{e.message}")
              Process.kill('KILL', waiter.pid) if waiter.alive?
            end
          end
          reader.join(5)
          reader.kill if reader.alive?
        end
      end
    end
  end

  def compose_output(compose, *arguments)
    output = +''
    passed = command(compose + arguments, path: File.join(@results, 'compose-commands.log'), timeout: 30, capture: output, quiet: true)
    raise "Compose #{arguments.inspect} failed: #{output}" unless passed

    output
  end

  def input_digests(family, manifest)
    source_types = { 'exploit' => 'exploits', 'payload' => 'payloads', 'encoder' => 'encoders', 'nop' => 'nops' }
    sources = manifest.fetch('modules').map do |fullname|
      type, path = fullname.split('/', 2)
      "modules/#{source_types.fetch(type, type)}/#{path}.rb"
    end
    files = sources + [manifest.fetch('spec'), 'spec/support/acceptance/module_target.rb', 'spec/support/acceptance/child_process.rb', 'tools/dev/run_module_target_tests.rb']
    files += CONSOLE_BUILD_FILES + %w[Dockerfile test/module_targets/framework.compose.yaml] if manifest['console']
    files += manifest.fetch('support_files', [])
    files += Dir[File.join(TARGETS, family, '**/*')].select { |path| File.file?(path) }.map { |path| path.delete_prefix("#{ROOT}/") }
    files.sort.to_h { |path| [path, Digest::SHA256.file(File.join(ROOT, path)).hexdigest] }
  end

  def run_family(family)
    directory = File.join(@results, family)
    FileUtils.mkdir_p(directory)
    compose = ['docker', 'compose', '--project-name', "msf-target-#{@run_id.downcase}-#{family}", '--file', File.join(TARGETS, family, 'compose.yaml')]
    result = { family: family, status: 'setup_failed', started_at: Time.now.utc.iso8601 }
    begin
      manifest = YAML.safe_load_file(File.join(TARGETS, family, 'manifest.yml'))
      if manifest['console']
        # Compose interpolation uses the process environment, including for later
        # exec/down commands emitted in runtime.json and the reproduction logs.
        ENV['MODULE_TARGET_ROOT'] = ROOT
        ENV['MODULE_TARGET_ARTIFACTS'] = directory
        ENV['MODULE_TARGET_UID'] = Process.uid.to_s
        ENV['MODULE_TARGET_GID'] = Process.gid.to_s
        ENV['MODULE_TARGET_BUILD_CONTEXT'] = prepare_console_context(directory)
        compose += ['--file', File.join(TARGETS, 'framework.compose.yaml')]
      end
      result[:inputs_sha256] = input_digests(family, manifest)
      File.write(File.join(directory, 'compose.yaml'), compose_output(compose, 'config'))
      revision, = Open3.capture2('git', 'rev-parse', 'HEAD', chdir: ROOT)
      changes, = Open3.capture2('git', 'diff', '--stat', chdir: ROOT)
      result[:revision] = revision.strip
      result[:tracked_changes] = changes
      # A cold canonical Framework image compiles gems and Go. This setup cost
      # is cached; the functional suite itself retains its separate short bound.
      setup_timeout = manifest['console'] ? 1800 : 600
      if command(compose + ['up', '--detach', '--build', '--wait', '--wait-timeout', '120'], path: File.join(directory, 'setup.log'), timeout: setup_timeout)
        endpoints = manifest.fetch('ports').to_h do |service, port|
          binding = compose_output(compose, 'port', service, port.to_s).strip
          raise "Expected a loopback port for #{service}, got #{binding}" unless binding.match?(/\A127\.0\.0\.1:\d+\z/)

          [service, { 'host' => '127.0.0.1', 'port' => binding.split(':').last.to_i }]
        end
        runtime = { 'compose' => compose, 'endpoints' => endpoints, 'artifacts' => directory }
        if manifest['console']
          runtime['module_endpoints'] = manifest.fetch('ports').to_h do |service, port|
            [service, { 'host' => container_ip(compose, service), 'port' => port }]
          end
          runtime['listener_host'] = container_ip(compose, 'framework')
          runtime['console_command'] = compose + ['exec', '-T', '--user', "#{Process.uid}:#{Process.gid}", '--env', "MSF_CFGROOT_CONFIG=#{directory}/msf-config", 'framework', 'bundle', 'exec', 'ruby', 'msfconsole', '--no-readline', '--quiet']
        end
        File.write(File.join(directory, 'runtime.json'), JSON.pretty_generate(runtime))
        env = manifest.fetch('test_env', {}).merge(
          'MODULE_TARGET_RUNTIME' => File.join(directory, 'runtime.json'),
          'MSF_CFGROOT_CONFIG' => File.join(directory, 'msf-config'),
          'SPEC_HELPER_LOAD_METASPLOIT' => 'false',
          'SPEC_OPTS' => '--tag acceptance'
        )
        manifest.fetch('connection_env', {}).each do |service, prefix|
          endpoint = runtime.fetch('module_endpoints', endpoints).fetch(service)
          env["#{prefix}_RHOST"] = endpoint.fetch('host')
          env["#{prefix}_RPORT"] = endpoint.fetch('port').to_s
        end
        # Config.get_config_root only honors an existing directory.
        FileUtils.mkdir_p(env.fetch('MSF_CFGROOT_CONFIG'))
        result[:status] = 'test_failed_unclassified'
        passed = command(
          ['bundle', 'exec', 'rspec', manifest.fetch('spec'), '--format', 'documentation', '--format', 'json', '--out', File.join(directory, 'rspec.json')],
          path: File.join(directory, 'rspec.log'), env: env, timeout: 600
        )
        report_path = File.join(directory, 'rspec.json')
        if File.file?(report_path)
          report = JSON.parse(File.read(report_path))
          result[:examples] = report.dig('summary', 'example_count')
          result[:failures] = report.dig('summary', 'failure_count')
          result[:pending] = report.dig('summary', 'pending_count')
          result[:errors_outside_examples] = report.dig('summary', 'errors_outside_of_examples_count')
          # A filtered/empty/pending suite is not evidence that modules work.
          if passed && result[:examples] == manifest.fetch('expected_examples') && result[:failures] == 0 && result[:pending] == 0 && result[:errors_outside_examples] == 0
            result[:status] = 'passed'
          end
          result[:status] = 'inputs_changed_during_run' unless input_digests(family, manifest) == result[:inputs_sha256]
        end
      end
    rescue Interrupt
      result[:status] = 'interrupted'
      raise
    rescue StandardError => e
      result[:error] = "#{e.class}: #{e.message}"
      warn result[:error]
    ensure
      # Preserve the target's own logs, image IDs and health before destroying it.
      %w[ps images].each do |action|
        command(compose + [action, '--format', 'json'], path: File.join(directory, "#{action}.log"), timeout: 30)
      rescue StandardError => e
        warn "Could not capture #{action}: #{e.message}"
      end
      begin
        identifiers = compose_output(compose, 'ps', '--all', '--quiet').split
        command(['docker', 'inspect', *identifiers], path: File.join(directory, 'inspect.log'), timeout: 30, quiet: true) unless identifiers.empty?
      rescue StandardError => e
        warn "Could not capture container health details: #{e.message}"
      end
      begin
        command(compose + ['logs', '--no-color'], path: File.join(directory, 'target.log'), timeout: 30)
        cleaned = command(compose + ['down', '--volumes', '--remove-orphans'], path: File.join(directory, 'cleanup.log'), timeout: 60)
        result[:cleanup] = cleaned ? 'passed' : 'failed'
        result[:status] = 'cleanup_failed' unless cleaned
      rescue StandardError => e
        result[:cleanup] = e.message
        result[:status] = 'cleanup_failed'
      end
      result[:finished_at] = Time.now.utc.iso8601
      File.write(File.join(directory, 'result.json'), JSON.pretty_generate(result))
      puts "#{family}: #{result[:status]}"
    end
    result
  end

  def container_ip(compose, service)
    identifier = compose_output(compose, 'ps', '--quiet', service).strip
    output, status = Open3.capture2('docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', identifier)
    raise "Could not inspect the #{service} network" unless status.success?

    networks = JSON.parse(output).values
    raise "Expected one isolated network for #{service}" unless networks.length == 1

    networks.first.fetch('IPAddress').tap do |address|
      raise "No IPv4 address assigned to #{service}" if address.empty?
    end
  end

  def prepare_console_context(directory)
    context = File.join(directory, 'framework-build')
    FileUtils.mkdir_p(File.join(context, 'config'))
    CONSOLE_BUILD_FILES.each do |path|
      destination = File.join(context, path)
      FileUtils.mkdir_p(File.dirname(destination))
      FileUtils.cp(File.join(ROOT, path), destination, preserve: true)
    end
    context
  end
end

exit ModuleTargetTests.new.run(ARGV) if $PROGRAM_NAME == __FILE__
