# frozen_string_literal: true

require_relative 'native_gate'
require_relative 'functional_support'

module MinioTarget
  # Uses genuine NativeGate validators without changing its three-service CLI.
  class FunctionalGate < NativeGate
    def initialize(assembly, profile, framework_review)
      super(assembly, profile)
      @settings = Functional.settings
      @framework_review = Functional.framework_review(framework_review)
      @seconds = @settings.fetch('seconds')
      @project = @project.sub('-native-', '-functional-')
      @directory = File.join(OUTPUT, 'runs', @project)
      @compose[3] = @project
      @environment['MINIO_GATEWAY_CONFIG'] = File.join(@directory, 'gateway.conf')
      @environment.merge!(
        'MINIO_FRAMEWORK_IMAGE' => @framework_review.fetch('image'), 'MODULE_TARGET_ROOT' => ROOT,
        'MODULE_TARGET_ARTIFACTS' => @directory, 'MODULE_TARGET_UID' => Process.uid.to_s,
        'MODULE_TARGET_GID' => Process.gid.to_s
      )
      @result.merge!('operation' => 'framework_minio_validation', 'project' => @project,
                     'functional_inputs_sha256' => Functional.inputs,
                     'framework_review' => File.realpath(framework_review),
                     'framework_review_sha256' => Digest::SHA256.file(framework_review).hexdigest)
      @result.delete('framework_console_module_calls')
    end

    # @return [Boolean] actual owners pass after native qualification and restoration
    def run
      perform do
        start_native
        @before = native_control('before')
        start_auxiliary
        runtime = write_runtime
        client_states = File.join(@directory, Functional::CLIENT_STATES_FILE)
        File.write(client_states, JSON.pretty_generate(Functional.initial_client_states(@profile)) + "\n")
        @result['status'] = 'owner_failed'
        suite = observe(
          [
            'bundle', 'exec', 'rspec', '--options', '/dev/null', 'spec/acceptance/module_targets/minio_spec.rb',
            '--tag', 'acceptance', '--example', 'Genuine MinIO owners and credential evidence', '--order', 'defined', '--fail-fast', '--format', 'documentation', '--format', 'json', '--out', File.join(@directory, 'rspec.json')
          ],
          'owner-suite', timeout: @settings.fetch('suite_seconds'),
                         env: @environment.merge('MODULE_TARGET_RUNTIME' => runtime, 'MSF_CFGROOT_CONFIG' => File.join(@directory, 'msf-config'), 'SPEC_HELPER_LOAD_METASPLOIT' => 'false')
        ).last
        report = JSON.parse(File.read(File.join(@directory, 'rspec.json')))
        @result['client_states'] = JSON.parse(File.read(client_states))
        @result['rspec_summary'] = report.fetch('summary')
        summary = report.fetch('summary')
        raise Error, 'Owner suite failed or actual case count differs' unless suite && summary['example_count'] == @settings.fetch('expected_examples').fetch(@profile) && summary['failure_count'] == 0 && summary['pending_count'] == 0 && summary['errors_outside_of_examples_count'] == 0

        Functional.validate_client_states(@result.fetch('client_states'), @profile)
        @result['status'] = 'passed'
      ensure
        if @before
          safely('final-native-control') do
            after = native_control('after')
            raise Error, 'Native baseline changed across owner execution' unless after.fetch('facts').fetch('baseline') == @before.fetch('facts').fetch('baseline')

            @result['native_baseline_restored'] = true
          end
        end
        raise Error, 'Functional inputs changed' unless Functional.inputs == @result.fetch('functional_inputs_sha256')
      end
    end

    private

    def start_native
      engine = JSON.parse(required(['docker', 'info', '--format', '{{json .}}'], 'engine'))
      raise Error, 'Reviewed native linux/amd64 engine required' unless engine['ID'] == @framework_review.fetch('engine_id') && engine['OSType'] == 'linux' && %w[x86_64 amd64].include?(engine['Architecture'])

      actual = JSON.parse(required(['docker', 'image', 'inspect', @image.fetch('name')], 'native-image')).fetch(0)
      base = @assets.fetch('images').fetch('runtime').fetch('rootfs')
      raise Error, 'Assembled image identity/ancestry changed' unless actual['Id'] == @image.fetch('id') && actual.dig('Config', 'User') == '1000:1000' && actual.dig('Config', 'Entrypoint') == ['/usr/local/bin/minio'] && actual.dig('RootFS', 'Layers').first(base.length) == base

      prepare_gateway
      validate_compose(JSON.parse(required(@compose + ['config', '--format', 'json'], 'native-compose', env: @environment)))
      empty_inventory!('before-up')
      @up_attempted = true
      required(@compose + ['up', '--detach', '--no-build', '--wait', '--wait-timeout', '120'], 'native-up', timeout: 120, env: @environment)
      collect_owned
      assert_owned(3, 4)
      @endpoints = @assets.fetch('native').fetch('services').to_h do |service|
        port = @assets.fetch('native').fetch('gateway').fetch('ports').fetch(service)
        binding = required(@compose + ['port', 'gateway', port.to_s], "port-#{service}", env: @environment).strip
        raise Error, 'Only genuine loopback publications are permitted' unless binding.match?(/\A127\.0\.0\.1:[1-9][0-9]*\z/)

        validate_resources(service, @assets.fetch('native'))
        [service, { 'host' => '127.0.0.1', 'port' => binding.split(':').last.to_i }]
      end
      validate_resources('gateway', @assets.fetch('native').fetch('gateway'))
    end

    def assert_owned(containers, volumes)
      ids = required(%w[docker ps --all --quiet --no-trunc], "only-#{containers}").split.sort
      raise Error, 'Exact project resources/global container inventory differs' unless @owned['containers'].length == containers && ids == @owned['containers'].sort && @owned['networks'].length == 2 && @owned['volumes'].length == volumes
    end

    def native_control(phase)
      directory = File.join(@directory, "native-#{phase}")
      FileUtils.mkdir_p(directory)
      runtime = {
        'compose' => @compose, 'compose_environment' => @environment, 'endpoints' => @endpoints,
        'artifacts' => directory, 'assets' => File.join(DIRECTORY, 'assets.json'), 'profile' => @profile
      }
      path = File.join(directory, 'runtime.json')
      File.write(path, JSON.pretty_generate(runtime) + "\n")
      summary = JSON.parse(required(['python3', '-B', File.join(DIRECTORY, 'native.py'), path], "native-#{phase}", timeout: 180, env: @environment))
      raise Error, 'Genuine native controls did not restore their state' unless summary['status'] == 'native_passed' && summary['restored'] == true

      facts = JSON.parse(File.read(File.join(directory, 'native-control.json')))
      @result["native_#{phase}"] = summary
      facts
    end

    def start_auxiliary
      frame = JSON.parse(required(['docker', 'image', 'inspect', @framework_review.fetch('image')], 'framework-image')).fetch(0)
      raise Error, 'Independently reviewed cached canonical Framework image changed' unless frame['Id'] == @framework_review.fetch('image_id') && frame['Os'] == 'linux' && frame['Architecture'] == 'amd64'

      postgres = @settings.fetch('reporting_db').fetch('image')
      db = JSON.parse(required(['docker', 'image', 'inspect', postgres], 'postgres-image')).fetch(0)
      raise Error, 'Pinned preloaded PostgreSQL differs' unless db['Os'] == 'linux' && db['Architecture'] == 'amd64' && Array(db['RepoDigests']).any? { |reference| reference.end_with?("@#{postgres.split('@').last}") }

      @compose += ['--file', File.join(DIRECTORY, 'functional.compose.yaml')]
      definition = JSON.parse(required(@compose + ['config', '--format', 'json'], 'functional-compose', env: @environment))
      native_definition = definition.merge('services' => definition.fetch('services').slice('node1', 'node2', 'gateway'))
      validate_compose(native_definition)
      Functional.validate_compose(definition, @framework_review.fetch('image'))
      required(@compose + ['up', '--detach', '--no-build', '--wait', '--wait-timeout', '120', 'framework', 'reporting_db'], 'auxiliary-up', timeout: 120, env: @environment)
      collect_owned
      assert_owned(5, 5)
      %w[framework reporting_db].each do |service|
        limits = @settings.fetch(service)
        raw = required(@compose + ['exec', '-T', service, 'sh', '-c', 'cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max /sys/fs/cgroup/pids.max /sys/fs/cgroup/memory.events'], "limits-#{service}", env: @environment)
        lines = raw.lines.map(&:strip)
        quota, period = lines.fetch(1).split.map(&:to_i)
        raise Error, 'Auxiliary actual limits or OOM differs' unless lines[0] == limits.fetch('memory_bytes').to_s && Rational(quota, period) == Rational(limits.fetch('nano_cpus'), 1_000_000_000) && lines[2] == '128' && !raw.match?(/^oom_kill [1-9]\d*$/)
      end
      required(dependency_check_command, 'actual-dependency-sources', env: @environment)
    end

    def dependency_check_command
      # The canonical image WORKDIR is the mounted repository, not its host path.
      @compose + ['exec', '-T', '--user', "#{Process.uid}:#{Process.gid}", 'framework', 'bundle', 'exec', 'ruby', 'test/module_targets/minio/dependency_check.rb']
    end

    def write_runtime
      containers = JSON.parse(required(['docker', 'inspect', *@owned.fetch('containers')], 'runtime-identities'))
      networks = JSON.parse(required(['docker', 'network', 'inspect', *@owned.fetch('networks')], 'runtime-networks'))
      Functional.actual_resources(containers)
      endpoints, listener = Functional.internal_endpoints(containers, networks, @project)
      config = File.join(@directory, 'msf-config')
      FileUtils.mkdir_p(File.join(config, 'store'))
      metadata_cache = File.join(@directory, '.metadata-cache', 'container')
      raise Error, 'Metadata snapshot destination must be fresh' if File.exist?(metadata_cache) || File.symlink?(metadata_cache)

      runtime = {
        'compose' => @compose, 'compose_environment' => @environment, 'endpoints' => @endpoints,
        'module_endpoints' => endpoints, 'listener_host' => listener, 'artifacts' => @directory, 'metadata_cache' => metadata_cache,
        'assets' => File.join(DIRECTORY, 'assets.json'), 'profile' => @profile, 'native_before' => File.join(@directory, 'native-before/native-control.json'),
        'console_command' => @compose + ['exec', '-T', '--user', "#{Process.uid}:#{Process.gid}", '--env', "MSF_CFGROOT_CONFIG=#{config}", 'framework', 'bundle', 'exec', 'ruby', 'msfconsole', '--no-readline', '--quiet']
      }
      path = File.join(@directory, 'runtime.json')
      File.write(path, JSON.pretty_generate(runtime) + "\n")
      path
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    case ARGV
    in ['--check']
      puts JSON.pretty_generate(MinioTarget::Functional.inputs)
    in ['--run', assembly, profile, review]
      exit(MinioTarget::FunctionalGate.new(assembly, profile, review).run ? 0 : 1)
    else
      warn 'Usage: functional_gate.rb --check | --run ASSEMBLY_JSON vulnerable|fixed FRAMEWORK_REVIEW_JSON'
      exit 2
    end
  rescue MinioTarget::Error, SystemCallError, JSON::ParserError => e
    warn "MinIO functional setup failed: #{e.message}"
    exit 1
  end
end
