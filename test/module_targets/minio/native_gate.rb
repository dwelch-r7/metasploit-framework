# frozen_string_literal: true

require 'shellwords'
require 'erb'
require_relative 'assemble_images'

module MinioTarget
  # Separate, genuine two-node/four-drive native qualification. No Framework.
  class NativeGate < Operation
    def initialize(assembly_path, profile)
      native = MinioTarget.assets.fetch('native')
      super('native', native.fetch('readiness_seconds') + native.fetch('seconds') + 60)
      raise Error, 'Native profile must be vulnerable or fixed' unless %w[vulnerable fixed].include?(profile)

      @assembly = JSON.parse(File.read(assembly_path))
      raise Error, 'Assembly must have naturally passed and cleaned up' unless @assembly['status'] == 'passed' && @assembly['cleanup'] == 'passed' && @assembly['operation'] == 'runtime_assembly'
      raise Error, 'Assembly inputs changed' unless @assembly['inputs_sha256'] == MinioTarget.inputs
      raise Error, 'Assembly import receipt changed' unless Digest::SHA256.file(@assembly.fetch('import')).hexdigest == @assembly.fetch('import_sha256')

      RuntimeAssembly.verify_import(@assembly.fetch('import'))
      @profile = profile
      @image = @assembly.fetch('images').fetch(profile)
      @compose = ['docker', 'compose', '--project-name', @project, '--file', File.join(DIRECTORY, 'base.compose.yaml')]
      @environment = compose_environment
      @result['operation'] = 'native_distributed_s3'
      @result['profile'] = profile
      @result['framework_console_module_calls'] = 0
    end

    # @return [Boolean] mandatory real distributed/S3/API controls and exact teardown
    def run
      perform do
        native = @assets.fetch('native')
        engine = JSON.parse(required(['docker', 'info', '--format', '{{json .}}'], 'native-engine'))
        raise Error, 'Native linux/amd64 engine required' unless engine['OSType'] == 'linux' && %w[x86_64 amd64].include?(engine['Architecture'])

        image = JSON.parse(required(['docker', 'image', 'inspect', @image.fetch('name')], 'native-image')).fetch(0)
        raise Error, 'Verified local runtime image changed' unless image['Id'] == @image.fetch('id')
        raise Error, 'Runtime entrypoint/identity differs' unless image.dig('Config', 'Entrypoint') == ['/usr/local/bin/minio'] && image.dig('Config', 'User') == "#{@assets.fetch('assembly').fetch('uid')}:#{@assets.fetch('assembly').fetch('gid')}"

        base = @assets.fetch('images').fetch('runtime').fetch('rootfs')
        raise Error, 'Runtime base ancestry changed' unless image.dig('RootFS', 'Layers').first(base.length) == base

        prepare_gateway
        rendered = required(@compose + ['config', '--format', 'json'], 'native-compose-config', env: @environment)
        validate_compose(JSON.parse(rendered))
        empty_inventory!('before-up')
        @up_attempted = true
        required(@compose + ['up', '--detach', '--no-build', '--wait', '--wait-timeout', native.fetch('readiness_seconds').to_s], 'native-up', timeout: native.fetch('readiness_seconds') + 30, env: @environment)
        collect_owned
        ids = required(%w[docker ps --all --quiet --no-trunc], 'native-only').split
        raise Error, 'Expected exactly two owned servers and their gateway' unless @owned['containers'].length == native.fetch('services').length + 1 && ids.sort == @owned['containers'].sort
        raise Error, 'Expected two owned networks and four drive volumes' unless @owned['networks'].length == 2 && @owned['volumes'].length == native.fetch('services').length * native.fetch('drives').length

        endpoints = {}
        native.fetch('services').each do |service|
          gateway = native.fetch('gateway')
          binding = required(@compose + ['port', gateway.fetch('service'), gateway.fetch('ports').fetch(service).to_s], "port-#{service}", env: @environment).strip
          raise Error, 'Native API must publish only loopback' unless binding.match?(/\A127\.0\.0\.1:\d+\z/)

          endpoints[service] = { 'host' => '127.0.0.1', 'port' => binding.split(':').last.to_i }
          validate_resources(service, native)
        end
        validate_resources(native.fetch('gateway').fetch('service'), native.fetch('gateway'))
        runtime = {
          'compose' => @compose, 'compose_environment' => @environment, 'endpoints' => endpoints,
          'artifacts' => @directory, 'assets' => File.join(DIRECTORY, 'assets.json'), 'profile' => @profile
        }
        File.write(File.join(@directory, 'runtime.json'), JSON.pretty_generate(runtime) + "\n")
        output = required(['python3', '-B', File.join(DIRECTORY, 'native.py'), File.join(@directory, 'runtime.json')], 'native-control', timeout: native.fetch('seconds'), env: @environment)
        facts = JSON.parse(output)
        raise Error, 'Native control did not prove restoration' unless facts['status'] == 'native_passed' && facts['restored'] == true

        @result['native'] = facts
        @result['status'] = 'passed'
      end
    end

    private

    def compose_environment
      native = @assets.fetch('native')
      port = native.fetch('api_port')
      endpoints = native.fetch('services').flat_map { |service| native.fetch('drives').map { |drive| "http://#{service}:#{port}#{drive}" } }
      command = ['server', '--address', ":#{port}", '--console-address', ":#{native.fetch('console_port')}", *endpoints]
      gateway = native.fetch('gateway')
      {
        'MINIO_TARGET_IMAGE' => @image.fetch('name'), 'MINIO_UID' => @assets.fetch('assembly').fetch('uid').to_s,
        'MINIO_GID' => @assets.fetch('assembly').fetch('gid').to_s, 'MINIO_SERVER_COMMAND' => Shellwords.join(command),
        'MINIO_MEMORY_BYTES' => native.fetch('memory_bytes').to_s, 'MINIO_CPUS' => (native.fetch('nano_cpus') / 1e9).to_s,
        'MINIO_PIDS' => native.fetch('pids').to_s, 'MINIO_API_PORT' => port.to_s,
        'MINIO_DRIVE1' => native.fetch('drives').fetch(0), 'MINIO_DRIVE2' => native.fetch('drives').fetch(1),
        'MINIO_ROOT_USER' => native.fetch('root_user'), 'MINIO_ROOT_PASSWORD' => native.fetch('root_password'),
        'MINIO_SENTINEL_ENV' => "#{native.fetch('sentinel_key')}=#{native.fetch('sentinel_value')}",
        'MINIO_EXCLUDED_ENV' => "#{native.fetch('excluded_key')}=#{native.fetch('excluded_value')}",
        'MINIO_GOMAXPROCS' => native.fetch('environment').fetch('GOMAXPROCS'), 'MINIO_GOGC' => native.fetch('environment').fetch('GOGC'),
        'MINIO_GOMEMLIMIT' => native.fetch('environment').fetch('GOMEMLIMIT'),
        'MINIO_HEALTH_URL' => "http://127.0.0.1:#{port}", 'MINIO_HEALTH_INTERVAL' => "#{native.fetch('health_interval_seconds')}s",
        'MINIO_HEALTH_TIMEOUT' => "#{native.fetch('health_timeout_seconds')}s", 'MINIO_HEALTH_RETRIES' => native.fetch('health_retries').to_s,
        'MINIO_GATEWAY_IMAGE' => gateway.fetch('image'), 'MINIO_GATEWAY_CONFIG' => File.join(@directory, 'gateway.conf'),
        'MINIO_GATEWAY_MEMORY_BYTES' => gateway.fetch('memory_bytes').to_s, 'MINIO_GATEWAY_CPUS' => (gateway.fetch('nano_cpus') / 1e9).to_s,
        'MINIO_GATEWAY_PIDS' => gateway.fetch('pids').to_s,
        'MINIO_GATEWAY_NODE1_PORT' => gateway.fetch('ports').fetch('node1').to_s, 'MINIO_GATEWAY_NODE2_PORT' => gateway.fetch('ports').fetch('node2').to_s
      }
    end

    def prepare_gateway
      gateway = @assets.fetch('native').fetch('gateway')
      image = JSON.parse(required(['docker', 'image', 'inspect', gateway.fetch('image')], 'gateway-image')).fetch(0)
      digest = "@#{gateway.fetch('image').split('@').last}"
      raise Error, 'Preloaded gateway image digest/platform differs' unless image['Architecture'] == 'amd64' && image['Os'] == 'linux' && Array(image['RepoDigests']).any? { |reference| reference.end_with?(digest) }

      @result['gateway_image'] = { 'reference' => gateway.fetch('image'), 'id' => image.fetch('Id') }
      template = File.read(File.join(DIRECTORY, 'gateway.conf.erb'))
      configuration = ERB.new(template, trim_mode: '-').result_with_hash(native: @assets.fetch('native'))
      File.write(@environment.fetch('MINIO_GATEWAY_CONFIG'), configuration)
      @result['gateway_config_sha256'] = Digest::SHA256.hexdigest(configuration)
    end

    def validate_compose(definition)
      native = @assets.fetch('native')
      gateway = native.fetch('gateway')
      services = definition.fetch('services')
      raise Error, 'Resolved native service set differs' unless services.keys.sort == (native.fetch('services') + [gateway.fetch('service')]).sort
      raise Error, 'Native backend must remain internal and frontend public' unless definition.fetch('networks').fetch('default')['internal'] == true && definition.fetch('networks').fetch('public')['internal'] != true

      services.each do |name, service|
        frontend = name == gateway.fetch('service')
        limits = frontend ? gateway : native
        image = frontend ? gateway.fetch('image') : @image.fetch('name')
        limits_match = service.fetch('mem_limit').to_i == limits.fetch('memory_bytes') && service.fetch('memswap_limit').to_i == limits.fetch('memory_bytes') && Rational(service.fetch('cpus').to_s) == Rational(limits.fetch('nano_cpus'), 1_000_000_000) && service.fetch('pids_limit').to_i == limits.fetch('pids')
        raise Error, 'Resolved native image/resources/build policy differs' unless service['image'] == image && service['pull_policy'] == 'never' && !service.key?('build') && limits_match

        raise Error, 'Resolved native UID/capability policy differs' unless service['user'] == "#{@assets.fetch('assembly').fetch('uid')}:#{@assets.fetch('assembly').fetch('gid')}" && service['cap_drop'] == ['ALL'] && service['security_opt'] == ['no-new-privileges:true']

        networks = frontend ? %w[default public] : ['default']
        raise Error, 'MinIO servers must remain isolated behind their gateway' unless service.fetch('networks').keys.sort == networks

        ports = service.fetch('ports', [])
        valid_ports = if frontend
                        ports.length == native.fetch('services').length && ports.map { |entry| entry.fetch('target').to_i }.sort == gateway.fetch('ports').values.sort && ports.all? { |entry| entry['host_ip'] == '127.0.0.1' && entry['protocol'] == 'tcp' }
                      else
                        ports.empty?
                      end
        raise Error, 'Only the gateway may publish loopback API listeners' unless valid_ports
      end
    end

    def validate_resources(service, limits)
      raw = required(@compose + ['exec', '-T', service, 'sh', '-c', 'set -eu; id -u; cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max /sys/fs/cgroup/pids.max /sys/fs/cgroup/memory.events'], "resources-#{service}", env: @environment)
      lines = raw.lines.map(&:strip)
      quota, period = lines.fetch(2).split.map(&:to_i)
      raise Error, 'Actual native UID or cgroup limits differ' unless lines[0] == @assets.fetch('assembly').fetch('uid').to_s && lines[1] == limits.fetch('memory_bytes').to_s && Rational(quota, period) == Rational(limits.fetch('nano_cpus'), 1_000_000_000) && lines[3] == limits.fetch('pids').to_s
      raise Error, 'Native target recorded an OOM kill' if raw.match?(/^oom_kill [1-9]\d*$/)
    end

    def remove_owned
      return unless @up_attempted

      safely('compose-down') { required(@compose + ['down', '--volumes', '--remove-orphans'], 'native-down', timeout: 60, bounded: false, env: @environment) }
    end

    def capture_before_down
      super
    ensure
      # A readiness failure must still retain the actual user/drive state when
      # exec remains available; configured ownership alone is not that evidence.
      @owned.fetch('containers').each do |identifier|
        safely("drive-state-#{identifier}") do
          container = JSON.parse(required(['docker', 'inspect', identifier], "drive-container-identity-#{identifier}", bounded: false)).fetch(0)
          next unless @assets.fetch('native').fetch('services').include?(container.fetch('Config').fetch('Labels').fetch('com.docker.compose.service'))

          script = 'set -eu; id; stat -c "%u:%g %a %n" -- "$@"'
          required(['docker', 'exec', identifier, 'sh', '-c', script, 'minio-drive-state', *@assets.fetch('native').fetch('drives')],
                   "final-drive-state-#{identifier}", bounded: false)
        end
      end
      @owned.fetch('networks').each do |identifier|
        safely("network-state-#{identifier}") do
          required(['docker', 'network', 'inspect', identifier], "final-network-state-#{identifier}", bounded: false)
        end
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    case ARGV
    in ['--check']
      puts JSON.pretty_generate(MinioTarget.inputs)
    in ['--run', assembly, profile]
      exit(MinioTarget::NativeGate.new(assembly, profile).run ? 0 : 1)
    else
      warn 'Usage: native_gate.rb --check | --run ASSEMBLY_JSON vulnerable|fixed'
      exit 2
    end
  rescue MinioTarget::Error, SystemCallError, JSON::ParserError => e
    warn "MinIO native setup failed: #{e.message}"
    exit 1
  end
end
