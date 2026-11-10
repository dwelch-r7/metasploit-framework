#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'run_module_target_tests'

# Opt in with this launcher instead of run_module_target_tests.rb. All guarded
# worktrees share one user-scoped advisory lock. Manual/unguarded Docker users
# do not participate; this is not a Docker daemon isolation mechanism.
class GuardedModuleTargetTests < ModuleTargetTests
  MAX_CONTAINERS = 5
  SOURCE_PATH = 'tools/dev/run_guarded_module_target_tests.rb'
  LOCK_PATH = File.join(Dir.home, '.cache', 'metasploit-framework', 'module-target-tests.lock')

  class ResourceRefusal < StandardError; end

  def initialize(lock_path: LOCK_PATH)
    super()
    @lock_path = lock_path
  end

  def run(arguments)
    available = Dir[File.join(TARGETS, '*/manifest.yml')].map { |path| File.basename(File.dirname(path)) }
    selected = arguments == ['--all'] ? available.sort : arguments
    # Informational/usage requests must not inspect Docker or acquire the lock.
    return super if arguments == ['--list']

    if selected.empty? || (selected - available).any?
      warn "Usage: bundle exec ruby #{SOURCE_PATH} --list | --all | FAMILY [FAMILY ...]"
      warn "Available: #{available.sort.join(', ')}"
      return 2
    end

    @resource_refusal = nil
    lock = acquire_lock
    existing_containers!
    super
  rescue ResourceRefusal => e
    FileUtils.mkdir_p(@results)
    statuses = selected.uniq.map { |family| refused_family(family, e) }
    File.write(File.join(@results, 'summary.json'), JSON.pretty_generate(statuses))
    warn "Resource guard refused startup: #{e.message}. Evidence: #{@results}"
    1
  ensure
    # Do not unlink: another opener must keep using this same locked inode.
    lock&.close
  end

  private

  def acquire_lock
    FileUtils.mkdir_p(File.dirname(@lock_path), mode: 0o700)
    lock = File.open(@lock_path, File::RDWR | File::CREAT, 0o600)
    lock.close_on_exec = true
    unless lock.flock(File::LOCK_EX | File::LOCK_NB)
      lock.close
      raise ResourceRefusal, 'Another guarded module-target invocation holds the lock'
    end

    lock
  rescue SystemCallError => e
    lock&.close
    raise ResourceRefusal, "Could not acquire the resource lock: #{e.message}"
  end

  def existing_containers!
    FileUtils.mkdir_p(@results)
    output = +''
    passed = command(['docker', 'ps', '--all', '--quiet', '--no-trunc'], path: File.join(@results, 'resource-inventory.log'), timeout: 30, capture: output, quiet: true)
    raise ResourceRefusal, 'Container inventory failed; startup is unsafe' unless passed

    identifiers = output.lines.map(&:strip).reject(&:empty?)
    unless identifiers.all? { |identifier| identifier.match?(/\A[0-9a-f]{64}\z/) }
      raise ResourceRefusal, 'Container inventory was malformed; startup is unsafe'
    end
    raise ResourceRefusal, "#{identifiers.length} existing container(s) must be handled by their owner" unless identifiers.empty?
  rescue Timeout::Error, SystemCallError, IOError => e
    raise ResourceRefusal, "Container inventory failed: #{e.message}"
  end

  def run_family(family)
    return refused_family(family, @resource_refusal) if @resource_refusal

    preflight_family(family)
    result = super
    unless result[:cleanup] == 'passed'
      @resource_refusal = ResourceRefusal.new("Previous family #{family} did not finish cleanup")
    end
    result
  rescue ResourceRefusal => e
    @resource_refusal = e
    refused_family(family, e)
  end

  def preflight_family(family)
    manifest = YAML.safe_load_file(File.join(TARGETS, family, 'manifest.yml'))
    raise ResourceRefusal, "Manifest for #{family} is not a mapping" unless manifest.is_a?(Hash)

    directory = File.join(@results, family)
    compose = ['docker', 'compose', '--project-name', "msf-target-#{@run_id.downcase}-#{family}", '--file', File.join(TARGETS, family, 'compose.yaml')]
    environment = {}
    if manifest['console']
      environment = {
        'MODULE_TARGET_ROOT' => ROOT, 'MODULE_TARGET_ARTIFACTS' => directory,
        'MODULE_TARGET_UID' => Process.uid.to_s, 'MODULE_TARGET_GID' => Process.gid.to_s,
        'MODULE_TARGET_BUILD_CONTEXT' => prepare_console_context(directory)
      }
      compose += ['--file', File.join(TARGETS, 'framework.compose.yaml')]
    end
    preview = File.join(@results, 'resource-guard')
    FileUtils.mkdir_p(preview)
    resolved = File.join(preview, "#{family}.json")
    # --output separates valid JSON from Compose warnings retained in the log.
    passed = command(compose + ['config', '--format', 'json', '--output', resolved], path: File.join(preview, 'preflight.log'), env: environment, timeout: 30, quiet: true)
    raise ResourceRefusal, "Compose preflight failed for #{family}" unless passed

    counts = service_counts(JSON.parse(File.read(resolved)))
    plan = { family: family, services: counts, containers: counts.values.sum, limit: MAX_CONTAINERS }
    File.write(File.join(preview, "#{family}-count.json"), JSON.pretty_generate(plan))
    raise ResourceRefusal, "#{family} resolves to #{plan[:containers]} containers; limit is #{MAX_CONTAINERS}" if plan[:containers] > MAX_CONTAINERS

    existing_containers!
  rescue JSON::ParserError, Psych::Exception, SystemCallError, IOError, Timeout::Error => e
    raise ResourceRefusal, "Invalid preflight for #{family}: #{e.message}"
  end

  def service_counts(config)
    services = config['services'] if config.is_a?(Hash)
    raise ResourceRefusal, 'Resolved Compose services must be a nonempty mapping' unless services.is_a?(Hash) && !services.empty?

    services.to_h do |name, settings|
      raise ResourceRefusal, "Invalid resolved service #{name}" unless settings.is_a?(Hash)

      deploy = settings.fetch('deploy', {})
      unless deploy.is_a?(Hash) && [nil, 'replicated'].include?(deploy['mode'])
        raise ResourceRefusal, "Cannot bound deployment mode for #{name}"
      end

      replicas = [[settings, 'scale'], [deploy, 'replicas']].filter_map do |values, key|
        next unless values.key?(key)

        value = values[key]
        unless value.is_a?(Integer) || (value.is_a?(String) && value.match?(/\A\d+\z/))
          raise ResourceRefusal, "Invalid replica count for #{name}"
        end

        count = value.to_i
        raise ResourceRefusal, "Negative replica count for #{name}" if count.negative?

        count
      end
      # Count every resolved service, including disabled profiles/zero replicas.
      [name, ([1] + replicas).max]
    end
  end

  def input_digests(family, manifest)
    super.merge(SOURCE_PATH => Digest::SHA256.file(__FILE__).hexdigest).sort.to_h
  end

  def refused_family(family, error)
    directory = File.join(@results, family)
    FileUtils.mkdir_p(directory)
    result = {
      family: family, status: 'setup_resource_refused', module_verdict: nil,
      error: error.message, cleanup: 'not_started', finished_at: Time.now.utc.iso8601,
      inputs_sha256: { SOURCE_PATH => Digest::SHA256.file(__FILE__).hexdigest }
    }
    File.write(File.join(directory, 'result.json'), JSON.pretty_generate(result))
    warn "#{family}: setup_resource_refused (#{error.message})"
    result
  end
end

exit GuardedModuleTargetTests.new.run(ARGV) if $PROGRAM_NAME == __FILE__
