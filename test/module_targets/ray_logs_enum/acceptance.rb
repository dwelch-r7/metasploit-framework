# frozen_string_literal: true

require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Keep native State API observations separate from owning console/loot output.
  module RayLogEnumeration
    def logs_phase(phase)
      output = +''
      argv = ['python3', '-B', 'test/module_targets/ray_logs_enum/native_runtime.py', ENV.fetch('MODULE_TARGET_RUNTIME'), phase]
      path = File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log")
      expect(ModuleTargetTests.new.send(:command, argv, path: path, timeout: 360, capture: output, quiet: true)).to be(true), output
      native = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}/native-result.json")))
      expect(native.fetch('status')).to eq('native_passed')
    end

    def logs_loot_files
      Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config/loot/**/*')].select { |path| File.file?(path) }.sort
    end

    def verify_enumeration(owner, name, **extra)
      item = @fixture.fetch('patterns').fetch(name)
      before = logs_loot_files
      output = run_target_module(owner, 'ray', { 'FILE_PATH' => item.fetch('glob') }.merge(extra))
      clean = output.gsub(/\e\[[0-9;]*m/, '')
      path = clean[/Loot stored in: ([^\r\n]+)/, 1]
      expect(path).not_to be_nil, output
      expect(path).to start_with(File.join(target_runtime.fetch('artifacts'), 'msf-config/loot/'))
      expect(before).not_to include(path)
      rows = File.binread(path).lines.map(&:chomp)
      expect(rows.shift).to eq("Node ID: #{@fixture.fetch('node_id')}".b)
      expected = name == 'ordinary' ? [File.basename(@fixture.fetch('log_file'))] : item.fetch('expected')
      expect(rows.reject(&:empty?).sort).to eq(expected.map(&:b).sort)
      expected.each { |entry| expect(output.b).to include("  #{entry}".b) }
      expect(output).to include("Filesystem entries found for node ID #{@fixture.fetch('node_id')}:")
    end
  end
end
