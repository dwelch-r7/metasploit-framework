#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../../../tools/dev/run_guarded_module_target_tests'

# Native preparation is separate from module qualification. Reuse the campaign
# lock and bounded process-group runner; keep target-specific facts here.
class SupersetNativeGate
  ROOT = File.expand_path('../../..', __dir__)
  DIRECTORY = __dir__
  SERVICES = %w[app reporting_db gateway].freeze
  RESOURCES = { 'app' => [1024, 900_000_000, 128], 'reporting_db' => [256, 150_000_000, 128], 'gateway' => [96, 100_000_000, 64] }.freeze
  INVENTORY = { 'containers' => %w[docker ps --all --quiet --no-trunc], 'networks' => %w[docker network ls --quiet --no-trunc], 'volumes' => %w[docker volume ls --quiet] }.freeze

  class Error < StandardError; end

  def initialize(profile: '2.0.0')
    @profile = profile
    @configuration = JSON.parse(File.read(File.join(DIRECTORY, 'profiles.json'))).fetch(profile)
    @project = "msf-superset-native-#{Time.now.utc.strftime('%Y%m%dT%H%M%S').downcase}-#{SecureRandom.hex(3)}"
    @directory = File.join(ROOT, 'tmp', 'module-target-superset', @project)
    @runner = GuardedModuleTargetTests.new
    @compose = ['docker', 'compose', '--project-name', @project, '--file', File.join(DIRECTORY, 'compose.yaml')]
    @compose += ['--file', File.join(DIRECTORY, @configuration.fetch('compose'))] if @configuration['compose']
    @owned = INVENTORY.keys.to_h { |kind| [kind, []] }
    @result = {
      'status' => 'setup_failed', 'project' => @project, 'started_at' => Time.now.utc.iso8601,
      'inputs_sha256' => inputs, 'commands' => [], 'capture_errors' => [], 'framework_calls' => 0, 'profile' => profile
    }
  end

  # @return [Boolean] actual native controls, capture and exact teardown passed
  def run
    FileUtils.mkdir_p(@directory)
    @deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 900
    $stdout.sync = true
    puts "Superset evidence/project: #{@directory}"
    lock = nil
    previous = %w[INT TERM].to_h { |name| [name, Signal.trap(name) { raise Interrupt, "Superset #{name}" }] }
    begin
      lock = @runner.send(:acquire_lock)
      raise Error, 'Existing containers require cleanup before startup' unless required(INVENTORY.fetch('containers'), 'initial-containers').split.empty?

      definition = JSON.parse(required(@compose + ['config', '--format', 'json'], 'compose-config'))
      validate_definition(definition)
      SERVICES.each do |service|
        reference = definition.fetch('services').fetch(service).fetch('image')
        required(['docker', 'pull', '--platform', 'linux/amd64', reference], "pull-#{service}", timeout: 600)
        image = JSON.parse(required(['docker', 'image', 'inspect', reference], "image-#{service}")).fetch(0)
        raise Error, "Unexpected #{service} image platform/digest" unless image['Architecture'] == 'amd64' && image['Os'] == 'linux' && image.fetch('RepoDigests').any? { |digest| digest.end_with?(reference.split('@').last) }
      end
      required(@compose + ['up', '--detach', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '240'], 'up', timeout: 270)
      collect_owned
      raise Error, 'Unexpected runtime inventory' unless @owned['containers'].length == 3 && @owned['networks'].length == 2 && @owned['volumes'].length == 2 && required(INVENTORY.fetch('containers'), 'running-containers').split.sort == @owned['containers'].sort

      validate_runtime
      port = required(@compose + ['port', 'gateway', '80'], 'port').strip
      raise Error, 'Gateway must publish only random loopback' unless port.match?(/\A127\.0\.0\.1:\d+\z/)

      sql = 'SELECT current_user, current_database(), 41 + 1'
      output = required(@compose + ['exec', '-T', '-e', 'PGPASSWORD=module-target-superset-database-password', 'reporting_db', 'psql', '-h', '127.0.0.1', '-U', 'module_native', '-d', 'module_native', '-Atc', sql], 'native-postgres')
      raise Error, 'Native datasource login/query differs' unless output.strip == 'module_native|module_native|42'

      runtime = {
        'compose' => @compose, 'origin' => "http://#{port}", 'artifacts' => @directory, 'version' => @profile,
        'source_sha256' => JSON.parse(File.read(File.join(DIRECTORY, @configuration.fetch('sources')))).transform_values { |row| row.fetch('sha256') }
      }
      File.write(File.join(@directory, 'runtime.json'), JSON.pretty_generate(runtime) + "\n")
      required(['python3', '-B', File.join(DIRECTORY, 'native_probe.py'), File.join(@directory, 'runtime.json')], 'native-controls', timeout: 240)
      native = JSON.parse(File.read(File.join(@directory, 'native-result.json')))
      raise Error, 'Native application controls did not pass' unless native['status'] == 'native_passed'

      @result['native'] = native
      @result['status'] = 'passed'
    rescue Interrupt, StandardError => e
      @result['error'] = "#{e.class}: #{e.message}"
      warn @result['error']
    ensure
      %w[INT TERM].each { |name| Signal.trap(name, 'IGNORE') }
      begin
        capture
      ensure
        cleanup
        @result['inputs_current'] = inputs == @result.fetch('inputs_sha256')
        @result['status'] = 'inputs_changed' unless @result['inputs_current']
        @result['status'] = 'capture_failed' if @result['status'] == 'passed' && !@result['capture_errors'].empty?
        @result['owned'] = @owned
        @result['finished_at'] = Time.now.utc.iso8601
        File.write(File.join(@directory, 'result.json'), JSON.pretty_generate(@result) + "\n")
        puts "Superset terminal: #{@result['status']}; cleanup: #{@result['cleanup']}"
        lock&.close
        previous.each { |name, handler| Signal.trap(name, handler) }
      end
    end
    @result['status'] == 'passed' && @result['cleanup'] == 'passed'
  end

  private

  def inputs
    names = Dir[File.join(DIRECTORY, '*')].select { |path| File.file?(path) }
    names += %w[tools/dev/run_guarded_module_target_tests.rb tools/dev/run_module_target_tests.rb test/module_targets/credential_reporting/compose.yaml test/module_targets/druid/compose.yaml].map { |name| File.join(ROOT, name) }
    names.sort.to_h { |path| [path.delete_prefix("#{ROOT}/"), Digest::SHA256.file(path).hexdigest] }
  end

  def required(argv, name, timeout: 30, bounded: true)
    remaining = @deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
    raise Error, 'The 900-second operation bound was reached' if bounded && remaining <= 0

    output = +''
    row = { 'argv' => argv, 'started_at' => Time.now.utc.iso8601, 'timeout' => bounded ? [timeout, remaining.ceil].min : timeout }
    begin
      environment = {
        'MODULE_TARGET_ARTIFACTS' => @directory, 'MODULE_TARGET_ROOT' => ROOT,
        'MODULE_TARGET_BUILD_CONTEXT' => @directory, 'MODULE_TARGET_UID' => Process.uid.to_s, 'MODULE_TARGET_GID' => Process.gid.to_s
      }
      row['passed'] = @runner.send(:command, argv, path: File.join(@directory, "#{name}.log"), env: environment, timeout: row.fetch('timeout'), capture: output, quiet: true)
    ensure
      row['finished_at'] = Time.now.utc.iso8601
      @result['commands'] << row
      File.binwrite(File.join(@directory, "#{name}.out"), output)
    end
    raise Error, "Required operation failed: #{name}" unless row['passed']

    output
  end

  def safely(name)
    yield
  rescue StandardError => e
    @result['capture_errors'] << { 'operation' => name, 'error' => "#{e.class}: #{e.message}" }
  end

  def validate_definition(definition)
    services = definition.fetch('services')
    raise Error, 'Unexpected service set/networks' unless services.keys.sort == SERVICES.sort && definition.dig('networks', 'default', 'internal') == true && definition.dig('networks', 'public', 'internal') != true

    services.each do |name, service|
      memory, cpus, pids = RESOURCES.fetch(name)
      raise Error, "#{name} limits differ" unless service.fetch('mem_limit').to_i == memory * 1024 * 1024 && service['memswap_limit'] == service['mem_limit'] && Rational(service.fetch('cpus').to_s) == Rational(cpus, 1_000_000_000) && service['pids_limit'] == pids
      raise Error, "#{name} lacks pinned image" unless service.fetch('image').match?(/@sha256:[0-9a-f]{64}\z/)
      raise Error, "#{name} network/ports differ" unless service.fetch('networks').keys.sort == (name == 'gateway' ? %w[default public] : ['default']) && (name == 'gateway' || Array(service['ports']).empty?)
    end
  end

  def validate_runtime
    @owned.fetch('containers').each do |identifier|
      item = JSON.parse(required(['docker', 'inspect', identifier], "live-#{identifier}")).fetch(0)
      service = item.dig('Config', 'Labels', 'com.docker.compose.service')
      memory, cpus, pids = RESOURCES.fetch(service)
      host = item.fetch('HostConfig')
      raise Error, "#{service} running limits differ" unless item.dig('State', 'Running') && !item.dig('State', 'OOMKilled') && host['Memory'] == memory * 1024 * 1024 && host['MemorySwap'] == host['Memory'] && host['NanoCpus'] == cpus && host['PidsLimit'] == pids
    end
  end

  def collect_owned
    INVENTORY.each do |kind, argv|
      safely("owned-#{kind}") { @owned[kind] |= required(argv + ['--filter', "label=com.docker.compose.project=#{@project}"], "owned-#{kind}", bounded: false).split }
    end
  end

  def capture
    collect_owned
    @owned.fetch('containers').each do |identifier|
      %w[inspect logs top].each do |action|
        safely("#{action}-#{identifier}") { required(['docker', action, identifier], "final-#{action}-#{identifier}", bounded: false) }
      end
      safely("cgroups-#{identifier}") do
        script = %w[memory.max memory.peak memory.events memory.swap.max pids.max cpu.max].map { |name| "printf '\\n#{name}='; cat /sys/fs/cgroup/#{name}" }.join('; ')
        output = required(['docker', 'exec', identifier, 'sh', '-c', script], "cgroups-#{identifier}", bounded: false)
        raise Error, 'Target recorded an OOM kill' if output.match?(/^oom_kill [1-9]\d*$/)
      end
    end
  end

  def cleanup
    collect_owned
    safely('compose-down') { required(@compose + ['down', '--volumes', '--remove-orphans', '--timeout', '10'], 'down', timeout: 60, bounded: false) }
    # Fallback removes only the collected task IDs, never unrelated volumes.
    safely('fallback-inventory') do
      remaining = required(INVENTORY.fetch('containers'), 'fallback-containers', bounded: false).split
      (@owned.fetch('containers') & remaining).each do |identifier|
        safely("remove-#{identifier}") { required(['docker', 'rm', '--force', '--volumes', identifier], "remove-#{identifier}", bounded: false) }
      end
    end
    after = {}
    labels = {}
    INVENTORY.each do |kind, argv|
      safely("after-#{kind}") { after[kind] = required(argv, "after-#{kind}", bounded: false).split }
      safely("after-label-#{kind}") { labels[kind] = required(argv + ['--filter', "label=com.docker.compose.project=#{@project}"], "after-label-#{kind}", bounded: false).split }
    end
    exact = @owned.to_h { |kind, ids| [kind, ids.to_h { |identifier| [identifier, after.key?(kind) && !after.fetch(kind).include?(identifier)] }] }
    passed = after.keys.sort == INVENTORY.keys.sort && labels.keys.sort == INVENTORY.keys.sort && after['containers'] == [] && labels.values.all?(&:empty?) && exact.values.all? { |ids| ids.values.all? }
    @result['cleanup_proof'] = { 'after' => after, 'project_labels' => labels, 'exact_absence' => exact }
    @result['cleanup'] = passed ? 'passed' : 'failed'
    @result['status'] = 'cleanup_failed' unless passed
  end
end

if $PROGRAM_NAME == __FILE__
  if ARGV == ['--native'] || (ARGV.length == 2 && ARGV.first == '--native' && %w[2.0.0 2.0.1].include?(ARGV.last))
    exit(SupersetNativeGate.new(profile: ARGV.fetch(1, '2.0.0')).run ? 0 : 1)
  end
  warn 'Usage: bundle exec ruby test/module_targets/superset/native_gate.rb --native [2.0.0|2.0.1]'
  exit 2
end
