# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'securerandom'
require_relative '../../../tools/dev/run_guarded_module_target_tests'

# Component-owned build, import and native lab contracts. Loading never runs Docker.
module MinioTarget
  ROOT = File.expand_path('../../..', __dir__)
  DIRECTORY = __dir__
  OUTPUT = File.join(ROOT, 'tmp/module-target-minio')
  CGROUPS = %w[memory.max memory.current memory.peak memory.events cpu.max pids.max].freeze

  class Error < StandardError; end

  # @return [Hash] the single source of pinned sources, resources and local reference facts
  def self.assets
    JSON.parse(File.read(File.join(DIRECTORY, 'assets.json')))
  end

  # @return [Hash<String, String>] current selected source digests, excluding generated binaries
  def self.inputs
    files = Dir[File.join(DIRECTORY, '**/*')].select { |path| File.file?(path) }
    files += %w[
      tools/dev/run_module_target_tests.rb tools/dev/run_guarded_module_target_tests.rb
      modules/auxiliary/gather/minio_bootstrap_verify_info_disc.rb
      modules/post/multi/gather/minio_client.rb
    ].map { |name| File.join(ROOT, name) }
    files += [File.join(ROOT, 'spec/tools/module_targets/minio_contract_spec.rb')]
    files += Dir[File.join(ROOT, 'spec/file_fixtures/tools/module_targets/minio/**/*')].select { |path| File.file?(path) }
    closure = File.join(DIRECTORY, 'functional-inputs.json')
    if File.file?(closure)
      definition = JSON.parse(File.read(closure))
      definition.fetch('paths').each do |name|
        path = File.join(ROOT, name)
        raise Error, "Missing functional source input: #{name}" unless File.file?(path)

        files << path
      end
      definition.fetch('globs').each do |pattern|
        matches = Dir[File.join(ROOT, pattern)].select { |path| File.file?(path) }
        raise Error, "Missing functional source closure: #{pattern}" if matches.empty?

        files += matches
      end
      files += ModuleTargetTests::CONSOLE_BUILD_FILES.map { |name| File.join(ROOT, name) }
    end
    files.sort.to_h { |path| [path.delete_prefix("#{ROOT}/"), Digest::SHA256.file(path).hexdigest] }
  end

  # @param profile [String] vulnerable or fixed
  # @return [String] explicit local image name; never a floating vendor fallback
  def self.image_name(profile)
    configuration = assets
    sources = configuration.fetch('sources')
    identity = [sources.fetch(profile).fetch('reference'), sources.fetch('client').fetch('reference'), configuration.fetch('images').fetch('builder').fetch('config_digest')]
    "#{configuration.fetch('assembly').fetch('image_prefix')}:#{profile}-#{Digest::SHA256.hexdigest(JSON.generate(identity))[0, 16]}"
  end

  # Reads locally built artifacts without executing any binary.
  class VerifiedBuild
    REQUIRED = %w[
      binary source.tar source-before.status source-after.status source-commit.txt
      expected-source.sha256 source-checks-before.txt source-checks-after.txt
      go-environment.json go-build-info.txt ldflags.txt version.txt module-verification.txt
    ].freeze

    # @param directory [String] compiler evidence directory containing result.json and artifacts/
    # @param configuration [Hash] pinned component assets
    def initialize(directory, configuration: MinioTarget.assets)
      @directory = File.realpath(directory)
      @assets = configuration
    end

    # @param profile [String] source profile
    # @param text [String] real go version -m output
    # @return [true] when the platform, toolchain and clean revision match
    def validate_build_info(profile, text)
      source = @assets.fetch('sources').fetch(profile)
      settings = @assets.fetch('build').fetch('environment')
      entries = text.scan(/^\tbuild\t([^=\n]+)=(.*)$/)
      expected = {
        'vcs' => 'git', 'vcs.revision' => source.fetch('commit'), 'vcs.modified' => 'false',
        'GOARCH' => settings.fetch('GOARCH'), 'GOOS' => settings.fetch('GOOS'), 'CGO_ENABLED' => settings.fetch('CGO_ENABLED'),
        '-trimpath' => 'true', '-tags' => @assets.fetch('build').fetch('arguments').fetch(1)
      }
      valid = text.lines.first.to_s.strip.end_with?(": #{@assets.fetch('build').fetch('toolchain')}") && entries.map(&:first).uniq.length == entries.length && expected.all? { |key, value| entries.to_h[key] == value }
      raise Error, "#{profile} build info differs from the pinned clean toolchain/source" unless valid

      true
    end

    # @return [Hash] verified local provenance; missing/partial/tampered inputs raise Error
    def verify
      result = JSON.parse(File.read(regular('result.json')))
      reference = Digest::SHA256.file(regular('result.json')).hexdigest == @assets.fetch('build').fetch('reference_receipt_sha256') && result['status'] == 'built'
      current = result['operation'] == 'source_build' && result['status'] == 'passed' && result['artifact_status'] == 'built'
      unless (reference || current) && result['cleanup'] == 'passed' && result['capture_errors'] == []
        raise Error, 'Import requires a completed source build with successful capture and cleanup'
      end

      components = @assets.fetch('build_order').to_h do |profile|
        source = @assets.fetch('sources').fetch(profile)
        reference = source.fetch('reference')
        paths = REQUIRED.to_h { |name| [name, regular("artifacts/#{profile}/#{name}")] }
        raise Error, "#{profile} Git checkout was dirty" unless %w[source-before.status source-after.status].all? { |name| File.empty?(paths.fetch(name)) }
        raise Error, "#{profile} source commit receipt differs" unless File.read(paths.fetch('source-commit.txt')).match?(/^commit #{Regexp.escape(source.fetch('commit'))}$/)
        raise Error, "#{profile} module verification failed" unless File.read(paths.fetch('module-verification.txt')).strip == 'all modules verified'

        expected = source.fetch('files').sort.map { |name, sha| "#{sha}  #{name}" }.sort
        actual = File.readlines(paths.fetch('expected-source.sha256'), chomp: true).sort
        raise Error, "#{profile} source checksum selection differs" unless actual == expected

        %w[source-checks-before.txt source-checks-after.txt].each do |name|
          successes = File.readlines(paths.fetch(name), chomp: true).sort
          raise Error, "#{profile} source checks did not all pass" unless successes == source.fetch('files').keys.map { |file| "#{file}: OK" }.sort
        end
        checks = {
          'binary' => reference.fetch('binary_sha256'), 'source.tar' => reference.fetch('source_archive_sha256'),
          'ldflags.txt' => reference.fetch('ldflags_sha256'), 'go-build-info.txt' => reference.fetch('go_build_info_sha256')
        }
        checks.each do |name, sha|
          raise Error, "#{profile}/#{name} differs from the measured local reference" unless Digest::SHA256.file(paths.fetch(name)).hexdigest == sha
        end
        raise Error, "#{profile} binary size differs" unless File.size(paths.fetch('binary')) == reference.fetch('binary_bytes')

        header = File.binread(paths.fetch('binary'), 20)
        elf = header.start_with?("\x7fELF".b) && header.getbyte(4) == 2 && header.getbyte(5) == 1 && header.byteslice(18, 2).unpack1('v') == 62
        raise Error, "#{profile} binary is not ELF64 little-endian AMD64" unless elf

        validate_build_info(profile, File.read(paths.fetch('go-build-info.txt')))
        version = File.read(paths.fetch('version.txt'))
        raise Error, "#{profile} CLI identity differs" unless version.include?(source.fetch('tag')) && version.include?(source.fetch('commit'))

        environment = JSON.parse(File.read(paths.fetch('go-environment.json')))
        @assets.fetch('build').fetch('environment').each do |key, value|
          next unless environment.key?(key)

          raise Error, "#{profile} compiler environment differs: #{key}" unless environment.fetch(key) == value
        end
        [
          profile, {
            'directory' => File.dirname(paths.fetch('binary')), 'sha256' => reference.fetch('binary_sha256'),
            'bytes' => reference.fetch('binary_bytes'), 'version' => version, 'commit' => source.fetch('commit')
          }
        ]
      end
      {
        'kind' => 'Verified locally compiled reference, not publisher binaries/signatures',
        'source' => @directory, 'result_sha256' => Digest::SHA256.file(regular('result.json')).hexdigest,
        'assets_sha256' => Digest::SHA256.file(File.join(DIRECTORY, 'assets.json')).hexdigest, 'components' => components
      }
    rescue JSON::ParserError, KeyError, Errno::ENOENT => e
      raise Error, "Incomplete source-build provenance: #{e.message}"
    end

    private

    def regular(relative)
      path = File.join(@directory, relative)
      raise Error, "Missing regular build artifact: #{relative}" unless File.file?(path) && !File.symlink?(path) && File.realpath(path).start_with?("#{@directory}/")

      path
    end
  end

  # Common lock, bounded command capture and task-owned teardown for the three
  # explicit public operations. No constructor or input check invokes Docker.
  class Operation
    attr_reader :directory, :result

    # @param kind [String] evidence directory prefix
    # @param seconds [Integer] operation bound excluding independent capture/cleanup
    def initialize(kind, seconds)
      @assets = MinioTarget.assets
      @project = "msf-minio-#{kind}-#{Time.now.utc.strftime('%Y%m%dT%H%M%S').downcase}-#{SecureRandom.hex(3)}"
      @directory = File.join(OUTPUT, 'runs', @project)
      @seconds = seconds
      @runner = GuardedModuleTargetTests.new
      @owned = { 'containers' => [], 'networks' => [], 'volumes' => [] }
      @result = {
        'status' => 'setup_failed', 'project' => @project, 'started_at' => Time.now.utc.iso8601,
        'commands' => [], 'capture_errors' => [], 'inputs_sha256' => MinioTarget.inputs
      }
    end

    # @yield operation after lock/inventory checks
    # @return [Boolean] successful operation with capture, conservation and teardown
    def perform
      FileUtils.mkdir_p(@directory)
      @runner.instance_variable_set(:@results, @directory)
      @deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @seconds
      $stdout.sync = true
      puts "MinIO evidence/project: #{@directory}"
      lock = nil
      previous_int = Signal.trap('INT') { raise Interrupt, 'MinIO operation interrupted' }
      previous_term = Signal.trap('TERM') { raise Interrupt, 'MinIO operation terminated' }
      begin
        lock = @runner.send(:acquire_lock)
        empty_inventory!('initial')
        yield
      rescue Interrupt, StandardError => e
        @result['error'] = "#{e.class}: #{e.message}"
        warn @result['error']
      ensure
        Signal.trap('INT', 'IGNORE')
        Signal.trap('TERM', 'IGNORE')
        begin
          safely('capture-before-down') { capture_before_down }
        ensure
          begin
            cleanup
          rescue StandardError => e
            @result['cleanup'] = 'failed'
            @result['status'] = 'cleanup_failed'
            @result['cleanup_error'] = "#{e.class}: #{e.message}"
          end
          @result['inputs_current'] = MinioTarget.inputs == @result.fetch('inputs_sha256')
          @result['status'] = 'inputs_changed' unless @result['inputs_current']
          @result['status'] = 'capture_failed' if @result['status'] == 'passed' && !@result['capture_errors'].empty?
          @result['owned'] = @owned
          @result['finished_at'] = Time.now.utc.iso8601
          File.write(File.join(@directory, 'result.json'), JSON.pretty_generate(@result) + "\n")
          puts "MinIO terminal: #{@result['status']}; cleanup: #{@result['cleanup']}"
          lock&.close
          Signal.trap('INT', previous_int)
          Signal.trap('TERM', previous_term)
        end
      end
      @result['status'] == 'passed' && @result['cleanup'] == 'passed'
    end

    private

    def observe(argv, name, timeout: 30, bounded: true, env: {})
      remaining = @deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      raise Error, "The #{@seconds}-second operation bound was reached" if bounded && remaining <= 0

      output = +''
      record = {
        'argv' => argv, 'environment' => env, 'timeout' => bounded ? [timeout, remaining.ceil].min : timeout,
        'started_at' => Time.now.utc.iso8601
      }
      begin
        record['passed'] = @runner.send(:command, argv, path: File.join(@directory, "#{name}.log"), env: env,
                                                        timeout: record.fetch('timeout'), capture: output, quiet: true)
      rescue StandardError => e
        record['passed'] = false
        record['error'] = "#{e.class}: #{e.message}"
      ensure
        File.binwrite(File.join(@directory, "#{name}.out"), output)
        record['finished_at'] = Time.now.utc.iso8601
        @result.fetch('commands') << record
      end
      [output, record['passed']]
    end

    def required(argv, name, **)
      output, passed = observe(argv, name, **)
      raise Error, "Required operation failed: #{name}" unless passed

      output
    end

    def safely(name)
      yield
    rescue StandardError => e
      @result.fetch('capture_errors') << { 'operation' => name, 'error' => "#{e.class}: #{e.message}" }
      nil
    end

    def empty_inventory!(phase)
      ids = required(%w[docker ps --all --quiet --no-trunc], "#{phase}-containers").split
      raise Error, "Existing containers must be handled by their owner: #{ids.inspect}" unless ids.empty?
    end

    def collect_owned
      inventory_commands.each do |kind, argv|
        safely("owned-#{kind}") do
          @owned[kind] |= required(argv + ['--filter', "label=com.docker.compose.project=#{@project}"], "owned-#{kind}", bounded: false).split
        end
      end
    end

    def capture_before_down
      collect_owned
      @owned.fetch('containers').each do |identifier|
        %w[inspect logs top].each do |action|
          argv = ['docker', action, identifier]
          argv += ['-eo', 'pid,ppid,args'] if action == 'top'
          safely("#{action}-#{identifier}") do
            output = required(argv, "final-#{action}-#{identifier}", bounded: false)
            if action == 'inspect' && @result['status'] == 'passed'
              state = JSON.parse(output).fetch(0).fetch('State')
              raise Error, 'A successful operation lost a running target or recorded OOM' unless state['Running'] && !state['OOMKilled']
            end
          end
        end
        script = CGROUPS.map { |name| "if test -r /sys/fs/cgroup/#{name}; then printf '\\n#{name}='; cat /sys/fs/cgroup/#{name}; fi" }.join('; ')
        safely("cgroups-#{identifier}") do
          output = required(['docker', 'exec', identifier, 'sh', '-c', script], "final-cgroups-#{identifier}", bounded: false)
          raise Error, 'Target cgroup recorded an OOM kill' if output.match?(/^oom_kill [1-9]\d*$/)
        end
      end
    end

    def remove_owned
      @owned.fetch('containers').each do |identifier|
        safely("stop-#{identifier}") { required(['docker', 'stop', '--time', '10', identifier], "stop-#{identifier}", bounded: false) }
        safely("stopped-inspect-#{identifier}") { required(['docker', 'inspect', identifier], "stopped-inspect-#{identifier}", bounded: false) }
        safely("remove-#{identifier}") { required(['docker', 'rm', '--force', '--volumes', identifier], "remove-#{identifier}", bounded: false) }
      end
      { 'networks' => 'network', 'volumes' => 'volume' }.each do |kind, command|
        @owned.fetch(kind).each { |identifier| safely("remove-#{identifier}") { required(['docker', command, 'rm', identifier], "remove-#{identifier}", bounded: false) } }
      end
    end

    def inventory_commands
      {
        'containers' => %w[docker ps --all --quiet --no-trunc],
        'networks' => %w[docker network ls --quiet --no-trunc], 'volumes' => %w[docker volume ls --quiet]
      }
    end

    def cleanup
      remove_owned
      after = {}
      labels = {}
      inventory_commands.each do |kind, argv|
        safely("after-#{kind}") { after[kind] = required(argv, "after-#{kind}", bounded: false).split }
        safely("after-label-#{kind}") { labels[kind] = required(argv + ['--filter', "label=com.docker.compose.project=#{@project}"], "after-label-#{kind}", bounded: false).split }
      end
      exact = @owned.to_h { |kind, ids| [kind, ids.to_h { |id| [id, after.key?(kind) && !after[kind].include?(id)] }] }
      passed = after.keys.sort == %w[containers networks volumes] && labels.keys.sort == after.keys.sort && after['containers'] == [] && labels.values.all?(&:empty?) && exact.values.all? { |ids| ids.values.all? }
      @result['cleanup_proof'] = { 'after' => after, 'project_labels' => labels, 'exact_absence' => exact }
      @result['cleanup'] = passed ? 'passed' : 'failed'
      @result['status'] = 'cleanup_failed' unless passed
    end
  end
end
