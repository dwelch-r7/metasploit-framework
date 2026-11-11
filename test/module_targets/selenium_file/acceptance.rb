# frozen_string_literal: true

require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Verify file output against actual target bytes and independent browser DOMs.
  module SeleniumFile
    OWNER = 'auxiliary/gather/selenium_file_read'

    def selenium_native(phase)
      output = +''
      argv = ['python3', 'test/module_targets/selenium_file/native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME'), ENV.fetch('SELENIUM_PROFILE'), phase]
      passed = ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 180, capture: output, quiet: true)
      expect(passed).to be(true), output
      JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
    end

    def selenium_call(action: 'run', options: {})
      datastore = { 'BROWSER' => selenium_profile.fetch('browser'), 'TIMEOUT' => 75, 'HttpClientTimeout' => 10 }.merge(options)
      output = run_target_module(OWNER, 'target', datastore, action: action, allow_errors: true, command_timeout: 120)
      text = output.dup.force_encoding(Encoding::UTF_8)
      expect(text.valid_encoding?).to be(true)
      File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') do |log|
        log.puts(JSON.generate(action: action, options: options, output: text))
      end
      index = Dir[File.join(target_runtime.fetch('artifacts'), 'native-audit-*.json')].size + 1
      audit = selenium_native("audit-#{index}")
      expect(audit.fetch('active_before_recovery')).to eq([]), "Owning call left browser sessions; native recovery recorded in audit #{index}"
      expect(audit.fetch('recovered')).to eq([])
      expect(output).not_to include('Unknown datastore option')
      output
    end

    def selenium_read(kind, options: {}, default: false)
      file = @native.fetch('files').fetch(kind)
      options = { 'FILEPATH' => file.fetch('path') }.merge(options) unless default
      output = selenium_call(options: options)
      expect(output).to include("[+] #{file.fetch('path')}\n")
      expect(output.b).to include(file.fetch('text').b)
      expect(output).to include('Started session (', 'Deleted session (')
      expect(output).not_to include('Failed to delete', 'Failed to read', 'Auxiliary aborted')
    end
  end
end
