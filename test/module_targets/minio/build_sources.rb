# frozen_string_literal: true

require_relative 'support'

module MinioTarget
  # The public, serial source compiler. Runtime image assembly is separate.
  class SourceBuild < Operation
    def initialize
      super('source-build', MinioTarget.assets.fetch('build').fetch('limits').fetch('total_seconds'))
      @result['operation'] = 'source_build'
    end

    # @return [Boolean] three complete reference artifacts with exact teardown
    def run
      passed = perform do
        build = @assets.fetch('build')
        limits = build.fetch('limits')
        image = @assets.fetch('images').fetch('builder')
        info = JSON.parse(required(['docker', 'info', '--format', '{{json .}}'], 'engine'))
        raise Error, 'Native linux/amd64 engine required' unless info['OSType'] == 'linux' && %w[x86_64 amd64].include?(info['Architecture'])

        required(['docker', 'pull', '--platform', @assets.fetch('platform'), image.fetch('reference')], 'builder-pull', timeout: limits.fetch('pull_seconds'))
        actual = JSON.parse(required(['docker', 'image', 'inspect', image.fetch('reference')], 'builder-image')).fetch(0)
        raise Error, 'Official builder config/RootFS differs' unless actual['Id'] == image['config_digest'] && actual.dig('RootFS', 'Layers') == image['rootfs']

        empty_inventory!('before-create')
        network = required(['docker', 'network', 'create', '--label', "com.docker.compose.project=#{@project}", @project], 'network-create').strip
        raise Error, 'Network did not return a full ID' unless network.match?(/\A[0-9a-f]{64}\z/)

        @owned['networks'] << network
        env = build.fetch('environment').flat_map { |key, value| ['--env', "#{key}=#{value}"] }
        argv = [
          'docker', 'create', '--name', "#{@project}-compiler", '--label', "com.docker.compose.project=#{@project}",
          '--label', 'com.docker.compose.service=compiler', '--network', network, '--init', '--cap-drop', 'ALL',
          '--security-opt', 'no-new-privileges=true', '--memory', limits.fetch('memory_bytes').to_s,
          '--memory-swap', limits.fetch('memory_bytes').to_s, '--cpus', (limits.fetch('nano_cpus') / 1e9).to_s,
          '--pids-limit', limits.fetch('pids').to_s, *env, image.fetch('reference'),
          'sh', '-c', 'umask 077; mkdir -p /work/home /work/cache /outputs; exec sleep infinity'
        ]
        @container = required(argv, 'compiler-create').strip
        raise Error, 'Compiler did not return a full ID' unless @container.match?(/\A[0-9a-f]{64}\z/)

        @owned['containers'] << @container
        required(['docker', 'start', @container], 'compiler-start')
        prepare_inputs
        required(['docker', 'cp', File.join(@directory, 'compiler-inputs'), "#{@container}:/inputs"], 'copy-inputs')
        inspect = JSON.parse(required(['docker', 'inspect', @container], 'compiler-inspect')).fetch(0)
        raise Error, 'Compiler mounts/limits differ' unless inspect['Mounts'] == [] && inspect.dig('HostConfig', 'Memory') == limits['memory_bytes'] && inspect.dig('HostConfig', 'NanoCpus') == limits['nano_cpus'] && inspect.dig('HostConfig', 'MemorySwap') == limits['memory_bytes'] && inspect.dig('HostConfig', 'PidsLimit') == limits['pids']

        current = required(%w[docker ps --all --quiet --no-trunc], 'compiler-only').split
        raise Error, 'Expected only the owned compiler' unless current == [@container]

        cgroups('before')
        @assets.fetch('build_order').each do |profile|
          source = @assets.fetch('sources').fetch(profile)
          args = [profile, source.fetch('repository'), source.fetch('tag'), source.fetch('commit'), source.fetch('release_variable'), limits.fetch('git_fetch_seconds').to_s, limits.fetch('generator_seconds').to_s]
          required(['docker', 'exec', @container, 'bash', '/inputs/build.sh', *args], "build-#{profile}", timeout: limits.fetch('component_seconds'))
          cgroups("after-#{profile}")
        end
        @result['artifact_status'] = 'built'
        @result['status'] = 'passed'
      end
      if passed
        begin
          verified = VerifiedBuild.new(@directory).verify
          File.write(File.join(@directory, 'verified-build.json'), JSON.pretty_generate(verified) + "\n")
        rescue Error => e
          @result['status'] = 'artifact_verification_failed'
          @result['error'] = e.message
          File.write(File.join(@directory, 'result.json'), JSON.pretty_generate(@result) + "\n")
          return false
        end
      end
      passed
    end

    private

    def prepare_inputs
      path = File.join(@directory, 'compiler-inputs')
      FileUtils.mkdir_p(path)
      FileUtils.cp(File.join(DIRECTORY, 'build.sh'), path)
      rows = @assets.fetch('sources').flat_map do |profile, source|
        source.fetch('files').map { |name, sha| "#{profile}\t#{sha}\t#{name}" }
      end
      File.write(File.join(path, 'source-checks.tsv'), rows.join("\n") + "\n")
      File.binwrite(File.join(path, 'build-arguments'), @assets.fetch('build').fetch('arguments').join("\0") + "\0")
    end

    def cgroups(phase)
      limits = @assets.fetch('build').fetch('limits')
      script = "set -eu; test \"$(cat /sys/fs/cgroup/memory.max)\" = #{limits.fetch('memory_bytes')}; set -- $(cat /sys/fs/cgroup/cpu.max); test \"$1\" = \"$2\"; cat /sys/fs/cgroup/memory.events; go version"
      output = required(['docker', 'exec', @container, 'sh', '-c', script], "#{phase}-resource-check")
      raise Error, 'Compiler recorded an OOM kill' if output.match?(/^oom_kill [1-9]\d*$/)
    end

    def capture_before_down
      super
      return unless @container

      safely('copy-artifacts') do
        path = File.join(@directory, 'artifacts')
        FileUtils.mkdir_p(path)
        required(['docker', 'cp', "#{@container}:/outputs/.", path], 'copy-artifacts', timeout: 60, bounded: false)
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  Dir.chdir(MinioTarget::ROOT)
  case ARGV
  when ['--check']
    puts JSON.pretty_generate(MinioTarget.inputs)
  when ['--build']
    exit(MinioTarget::SourceBuild.new.run ? 0 : 1)
  else
    warn 'Usage: bundle exec ruby test/module_targets/minio/build_sources.rb --check | --build'
    exit 2
  end
end
