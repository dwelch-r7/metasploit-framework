# frozen_string_literal: true

require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Exercise owning entry points against independently captured native state.
  module Listmonk
    OWNER = 'auxiliary/gather/listmonk_env_disclosure'
    CUSTOM = 'MODULE_TARGET_MARKER,MODULE_TARGET_SPECIAL,MODULE_TARGET_EMPTY,MODULE_TARGET_UNSET'

    def listmonk_native(phase)
      output = +''
      argv = ['python3', 'test/module_targets/listmonk/native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME'), ENV.fetch('LISTMONK_PROFILE'), phase]
      passed = ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 120, capture: output, quiet: true)
      expect(passed).to be(true), output
      JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
    end

    def listmonk_call(action: 'run', options: {})
      previous = Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/*')]
      datastore = { 'USERNAME' => 'labadmin', 'PASSWORD' => 'module-target-admin-password', 'HttpClientTimeout' => 5 }.merge(options)
      output = run_target_module(OWNER, 'target', datastore, action: action, allow_errors: true)
      created = Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/*')] - previous
      File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') do |log|
        log.puts(JSON.generate(action: action, options: options, output: output, loot_created: created))
      end
      expect(output).not_to include('Unknown datastore option')
      [output, created]
    end

    def listmonk_extract(kind = 'default', options: {})
      options = { 'ENVVAR' => CUSTOM }.merge(options) if kind == 'custom'
      output, files = listmonk_call(options: options)
      if listmonk_profile.fetch('vulnerable')
        expect(output).to include('Environment variable(s) extracted:')
        expect(files.length).to eq(1), output
        expect(File.binread(files.first)).to eq(@native.fetch('expected_loot').fetch(kind))
      else
        expect(output).to include('Preview failed with code: 400')
        expect(files).to eq([])
      end
      expect(output).not_to include('Failed to delete campaign')
    end
  end
end
