# frozen_string_literal: true

require_relative '../ray_jobs/acceptance'

module Acceptance
  # Observe native profiler behavior without coupling it to owner success.
  module RayProfiler
    include RayJobs

    def profiler_native(phase)
      source = File.read('test/module_targets/ray_profiler/native_control.py')
      output = target_exec('ray', 'python', '-c', source, @ray_root, SecureRandom.hex(12))
      lines = output.lines.grep(/^MODULE_TARGET_PROFILER_JSON:/)
      expect(lines.length).to eq(1), output
      result = JSON.parse(lines.first.delete_prefix('MODULE_TARGET_PROFILER_JSON:'))
      expect(result).to include('uid' => 1000, 'exact_native_command_marker' => true)
      File.write(File.join(target_runtime.fetch('artifacts'), "profiler-native-#{phase}.json"), JSON.pretty_generate(result))
    end
  end
end
