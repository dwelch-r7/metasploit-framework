#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../superset/native_gate'

# Reuse the existing native gate's bounded commands, lock, capture and exact
# cleanup. Ray-specific initialization, limits and prerequisites stay here.
class RayLogsNativeGate < SupersetNativeGate
  DIRECTORY = __dir__
  RESOURCES = { 'ray' => [5120, 1_000_000_000, 1536], 'unrelated' => [64, 100_000_000, 64] }.freeze

  def initialize(profile: '2.56.0') # rubocop:disable Lint/MissingSuper -- The parent initializer selects a Superset-specific profile.
    raise ArgumentError, 'Unsupported native Ray profile' unless %w[2.56.0 2.57.0].include?(profile)

    @profile = profile
    @resources = RESOURCES.transform_values(&:dup)
    @project = "msf-ray-logs-native-#{Time.now.utc.strftime('%Y%m%dT%H%M%S').downcase}-#{SecureRandom.hex(3)}"
    @directory = File.join(ROOT, 'tmp', 'module-target-ray-logs', @project)
    @runner = GuardedModuleTargetTests.new
    @compose = ['docker', 'compose', '--project-name', @project, '--file', File.join(DIRECTORY, 'compose.yaml')]
    @compose += ['--file', File.join(DIRECTORY, "compose-#{@profile}.yaml")] unless @profile == '2.56.0'
    @owned = INVENTORY.keys.to_h { |kind| [kind, []] }
    @result = {
      'status' => 'setup_failed', 'project' => @project, 'started_at' => Time.now.utc.iso8601,
      'inputs_sha256' => inputs, 'commands' => [], 'capture_errors' => [], 'framework_calls' => 0,
      'profile' => @profile, 'scope' => 'Native core/log SDK and traversal prerequisites only; no owning module'
    }
  end

  # @return [Boolean] actual prerequisites, capture and exact teardown passed
  def run
    FileUtils.mkdir_p(@directory)
    @deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 900
    $stdout.sync = true
    puts "Ray evidence/project: #{@directory}"
    lock = nil
    previous = %w[INT TERM].to_h { |name| [name, Signal.trap(name) { raise Interrupt, "Ray #{name}" }] }
    begin
      lock = @runner.send(:acquire_lock)
      raise Error, 'Existing containers require cleanup before startup' unless required(INVENTORY.fetch('containers'), 'initial-containers').split.empty?

      @result['revision'] = required(%w[git rev-parse HEAD], 'revision').strip
      @result['tracked_changes'] = required(%w[git status --porcelain --untracked-files=no], 'tracked-changes')
      definition = JSON.parse(required(@compose + ['config', '--format', 'json'], 'compose-config'))
      validate_definition(definition)
      @resources.each_key do |service|
        reference = definition.fetch('services').fetch(service).fetch('image')
        required(['docker', 'pull', '--platform', 'linux/amd64', reference], "pull-#{service}", timeout: 600)
        image = JSON.parse(required(['docker', 'image', 'inspect', reference], "image-#{service}")).fetch(0)
        raise Error, "Unexpected #{service} image platform/digest" unless image['Architecture'] == 'amd64' && image['Os'] == 'linux' && image.fetch('RepoDigests').any? { |digest| digest.end_with?(reference.split('@').last) }
      end
      required(@compose + ['up', '--detach', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '240'], 'up', timeout: 270)
      collect_owned
      raise Error, 'Unexpected runtime resource count/inventory' unless @owned['containers'].length == 2 && @owned['networks'].length == 2 && @owned['volumes'].empty? && required(INVENTORY.fetch('containers'), 'running-containers').split.sort == @owned['containers'].sort

      validate_runtime
      ray_environment = definition.fetch('services').fetch('ray').fetch('environment')
      native_ports = {
        'head' => ['ray', ray_environment.fetch('MODULE_TARGET_RAY_HEAD_PORT')],
        'agent' => ['ray', ray_environment.fetch('MODULE_TARGET_RAY_AGENT_PORT')],
        'unrelated' => ['unrelated', definition.fetch('services').fetch('unrelated').fetch('ports').fetch(0).fetch('target').to_s]
      }
      endpoints = native_ports.to_h do |name, (service, port)|
        address = required(@compose + ['port', service, port], "port-#{name}").strip
        raise Error, 'Only random loopback publishing is permitted' unless address.match?(/\A127\.0\.0\.1:\d+\z/)

        [name, "http://#{address}"]
      end
      runtime = {
        'compose' => @compose, 'endpoints' => endpoints, 'artifacts' => @directory,
        'source_manifest' => JSON.parse(File.read(File.join(DIRECTORY, "sources-#{@profile}.json")))
      }
      File.write(File.join(@directory, 'runtime.json'), JSON.pretty_generate(runtime) + "\n")
      required(['python3', '-B', File.join(DIRECTORY, 'native_probe.py'), File.join(@directory, 'runtime.json')], 'native-controls', timeout: 300)
      native = JSON.parse(File.read(File.join(@directory, 'native-result.json')))
      raise Error, 'Native Ray prerequisites did not pass and restore owned state' unless native.values_at('status', 'owned_state_restored', 'framework_calls') == ['native_passed', true, 0]

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
        puts "Ray terminal: #{@result['status']}; cleanup: #{@result['cleanup']}"
        lock&.close
        previous.each { |name, handler| Signal.trap(name, handler) }
      end
    end
    @result['status'] == 'passed' && @result['cleanup'] == 'passed'
  end

  private

  def inputs
    names = Dir[File.join(DIRECTORY, '*')].select { |path| File.file?(path) }
    names += %w[test/module_targets/superset/native_gate.rb test/module_targets/druid/compose.yaml tools/dev/run_guarded_module_target_tests.rb tools/dev/run_module_target_tests.rb modules/auxiliary/gather/ray_dashboard_logs_api_path_traversal.rb test/module_targets/ray/bootstrap.sh test/module_targets/ray/compose.yaml test/module_targets/ray/unrelated.conf test/module_targets/ray/native_probe.py test/module_targets/ray/native_target.py test/module_targets/ray/diagnostics.py].map { |name| File.join(ROOT, name) }
    names.sort.to_h { |path| [path.delete_prefix("#{ROOT}/"), Digest::SHA256.file(path).hexdigest] }
  end

  def capture
    super
    safely('ray-internal-diagnostics') do
      identifier = @owned.fetch('containers').find do |candidate|
        JSON.parse(required(['docker', 'inspect', candidate], "diagnostic-role-#{candidate}")).fetch(0).dig('Config', 'Labels', 'com.docker.compose.service') == 'ray'
      end
      raise Error, 'Ray container was not collected for diagnostics' unless identifier

      item = JSON.parse(required(['docker', 'inspect', identifier], 'diagnostic-ray-state')).fetch(0)
      if item.dig('State', 'Running')
        source = File.read(File.join(DIRECTORY, '../ray/diagnostics.py'))
        required(@compose + ['exec', '-T', 'ray', 'python', '-c', source], 'ray-internal-diagnostics', bounded: false)
      else
        required(['python3', File.join(DIRECTORY, 'dead_diagnostics.py'), identifier, File.join(@directory, 'dead-ray-internal-diagnostics.json')], 'dead-ray-internal-diagnostics', bounded: false)
      end
    end
  end

  def validate_definition(definition)
    raise Error, 'Unexpected Ray service/network plan' unless definition.fetch('services').keys.sort == @resources.keys.sort && definition.dig('networks', 'default', 'internal') == true && definition.dig('networks', 'public', 'internal') != true

    definition.fetch('services').each do |name, service|
      memory, cpus, pids = @resources.fetch(name)
      raise Error, "#{name} resource limits differ" unless service.fetch('mem_limit').to_i == memory * 1024 * 1024 && service['memswap_limit'] == service['mem_limit'] && Rational(service.fetch('cpus').to_s) == Rational(cpus, 1_000_000_000) && service['pids_limit'] == pids
      raise Error, "#{name} image/networks differ" unless service['image'].match?(/@sha256:[0-9a-f]{64}\z/) && service.fetch('networks').keys.sort == %w[default public] && service['privileged'] != true
      raise Error, 'Unexpected host publishing' unless Array(service['ports']).all? { |row| row['host_ip'] == '127.0.0.1' && !row.key?('published') }
    end
  end

  def validate_runtime
    @owned.fetch('containers').each do |identifier|
      item = JSON.parse(required(['docker', 'inspect', identifier], "live-#{identifier}")).fetch(0)
      role = item.dig('Config', 'Labels', 'com.docker.compose.service')
      memory, cpus, pids = @resources.fetch(role)
      host = item.fetch('HostConfig')
      raise Error, "#{role} running limits differ" unless item.dig('State', 'Running') && !item.dig('State', 'OOMKilled') && host['Memory'] == memory * 1024 * 1024 && host['MemorySwap'] == host['Memory'] && host['NanoCpus'] == cpus && host['PidsLimit'] == pids && host['Privileged'] == false
      raise Error, "#{role} project ownership differs" unless item.dig('Config', 'Labels', 'com.docker.compose.project') == @project
    end
  end
end

if $PROGRAM_NAME == __FILE__
  raise ArgumentError, 'Usage: bundle exec ruby test/module_targets/ray_logs/native_gate.rb --native [2.56.0|2.57.0]' unless ARGV == ['--native'] || (ARGV.length == 2 && ARGV.first == '--native')

  exit(RayLogsNativeGate.new(profile: ARGV.fetch(1, '2.56.0')).run ? 0 : 1)
end
