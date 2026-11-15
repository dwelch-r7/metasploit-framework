# frozen_string_literal: true

require 'base64'
require 'digest'
require 'fileutils'
require 'json'
require 'rbconfig'
require 'timeout'

# Host capture only: the guarded runner owns the image/container lifecycle.
module PHPReverseTarget
  class InfrastructureError < StandardError; end

  # Generate once under Bundle and retain the real interpreter's whole matrix.
  class Probe
    ROOT = File.expand_path('../../..', __dir__)
    OWNER = File.join(ROOT, 'modules/payloads/singles/php/reverse_php.rb')

    def initialize(runtime)
      @runtime = runtime
      @artifacts = runtime.fetch('artifacts')
      FileUtils.mkdir_p(@artifacts)
    end

    def capture
      source = File.expand_path(ENV.fetch('PHP_REVERSE_TARGET_SOURCE', OWNER), ROOT)
      payload = File.join(@artifacts, 'generated_payload.php')
      generation = command('generation', ['bundle', 'exec', RbConfig.ruby, '-Ilib', File.join(__dir__, 'generate.rb'), source, payload], 30)
      raise InfrastructureError, 'Payload generation failed; see generation.stderr' unless generation.fetch(:exitstatus) == 0

      identity = JSON.parse(File.read("#{payload}.json"))
      identity['source_override'] = source != OWNER
      input = File.join(@artifacts, 'native-request.json')
      File.write(input, JSON.generate(payload_base64: Base64.strict_encode64(File.binread(payload)), source_identity: identity))
      native = command('native', @runtime.fetch('compose') + ['exec', '-T', 'target', 'php', '/probe/controller.php'], 70, input: input)
      rows = File.readlines(File.join(@artifacts, 'native.stdout')).map { |line| JSON.parse(line) }
      final = rows.reverse.find { |row| row.fetch('kind') == 'final' }
      raise InfrastructureError, 'Native controller did not complete; see native stdout/stderr' unless final

      matrix = final.fetch('data')
      matrix['controller_exitstatus'] = native.fetch(:exitstatus)
      File.write(File.join(@artifacts, 'matrix.json'), JSON.pretty_generate(matrix))
      prerequisites!(matrix, identity)
      matrix
    rescue JSON::ParserError, KeyError => e
      raise InfrastructureError, "Native matrix metadata is incomplete: #{e.message}"
    end

    def self.resource_errors(matrix, phase)
      matrix.fetch(phase).flat_map do |file, values|
        next [] if values.nil? # cgroup v2 counters are unavailable on this host.

        keys = file == 'memory.events' ? %w[max oom oom_kill oom_group_kill] : %w[max]
        keys.filter_map do |key|
          if !values.key?(key)
            "#{phase} #{file} missing #{key}"
          elsif !(file == 'memory.events' && key == 'max') && values.fetch(key) != 0
            "#{phase} #{file} #{key} is nonzero"
          end
        end
      end
    end

    private

    def prerequisites!(matrix, identity)
      errors = self.class.resource_errors(matrix, 'before')
      errors << 'Generated payload hash differs' unless matrix.fetch('source_sha256') == identity.fetch('payload_sha256')
      %w[controller.php exception_probe.php cases.json bin/0].each do |file|
        errors << "Container source differs: #{file}" unless matrix.fetch('source_files_sha256').fetch(file) == Digest::SHA256.file(File.join(__dir__, file)).hexdigest
      end
      fixture = JSON.parse(File.read(File.join(__dir__, 'cases.json')))
      expected = fixture.fetch('cases').map { |item| item.fetch('name') }
      names = matrix.fetch('cases').map { |item| item.fetch('name') }
      errors << 'Native case names/count differ from the fixture' unless names == expected
      failures = matrix.fetch('cases').count { |item| !item.fetch('errors').empty? }
      errors << 'Controller failure count differs' unless matrix.fetch('failures') == failures
      errors << 'Controller exit status differs from case results' unless matrix.fetch('controller_exitstatus') == (failures.zero? ? 0 : 1)
      unless errors.empty?
        File.write(File.join(@artifacts, 'prerequisite-errors.json'), JSON.pretty_generate(errors))
        raise InfrastructureError, "Native prerequisites failed: #{errors.join('; ')}"
      end
    end

    def command(phase, argv, timeout, input: File::NULL)
      record = { argv: argv, timeout: timeout }
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      pid = Process.spawn(*argv, chdir: ROOT, pgroup: true, in: input, out: File.join(@artifacts, "#{phase}.stdout"), err: File.join(@artifacts, "#{phase}.stderr"))
      record[:pid] = pid
      begin
        _, status = Timeout.timeout(timeout) { Process.wait2(pid) }
        record[:exitstatus] = status.exitstatus
      rescue Timeout::Error
        record[:timed_out] = true
        begin
          Process.kill('KILL', -pid)
          Process.wait(pid)
        rescue Errno::ESRCH, Errno::ECHILD => e
          record[:cleanup_notice] = "#{e.class}: #{e.message}"
        end
        raise InfrastructureError, "#{phase.capitalize} exceeded #{timeout} seconds"
      ensure
        record[:elapsed_seconds] = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
        File.write(File.join(@artifacts, "#{phase}-command.json"), JSON.pretty_generate(record))
      end
      record
    end
  end
end
