# frozen_string_literal: true

require 'base64'
require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Compare public module output and loot with independently read target bytes.
  module OneDevFile
    OWNER = 'auxiliary/gather/onedev_arbitrary_file_read'
    PROJECT = 'module-target-project'
    WORDLIST = '/usr/src/metasploit-framework/test/module_targets/onedev_file/wordlists/projects.txt'

    def onedev_native(phase)
      output = +''
      argv = ['python3', 'test/module_targets/onedev_file/native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME'), ENV.fetch('ONEDEV_VERSION'), phase]
      passed = ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 180, capture: output, quiet: true)
      expect(passed).to be(true), output
      JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
    end

    def onedev_loot
      Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '**', '*')].select { |path| File.file?(path) }.sort
    end

    def onedev_call(options = {}, action: 'run', omit_project: false)
      data = { 'TARGETURI' => '/', 'HttpClientTimeout' => 20 }
      data['PROJECT_NAME'] = PROJECT unless omit_project
      data.merge!(options)
      before = onedev_loot
      output = nil
      begin
        output = run_target_module(OWNER, 'target', data, action: action, allow_errors: true, command_timeout: 90)
      ensure
        text = (output || console.all_data).dup.force_encoding(Encoding::UTF_8)
        File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') do |log|
          log.puts(JSON.generate(action: action, options: options, omit_project: omit_project,
                                 anonymous: @anonymous, wrapper_returned: !output.nil?, output: text,
                                 new_loot: onedev_loot - before))
        end
      end
      expect(text.valid_encoding?).to be(true)
      expect(text).not_to include('Unknown datastore option')
      [text, onedev_loot - before]
    end

    def onedev_read(kind, loot: false, options: {}, omit_project: false)
      file = @native.fetch('files').fetch(kind)
      values = { 'TARGETFILE' => file.fetch('path'), 'STORE_LOOT' => loot }.merge(options)
      output, paths = onedev_call(values, omit_project: omit_project)
      if @vulnerable
        expect(output).not_to include('[-]', 'Auxiliary aborted')
        if loot
          expect(output).to include('file stored in loot.')
          expect(paths.size).to eq(1)
          expect(File.binread(paths.fetch(0))).to eq(Base64.strict_decode64(file.fetch('base64')))
        else
          expect(output).to include('file retrieved with success.')
          marker = "#{file.fetch('path')} file retrieved with success.\n"
          start = output.index(marker)
          expect(start).not_to be_nil
          start += marker.length
          finish = output.index("\n[*] Auxiliary module execution completed", start)
          expect(finish).not_to be_nil
          expect(output[start...finish].b).to eq(Base64.strict_decode64(file.fetch('base64')))
          expect(paths).to eq([])
        end
      else
        expect(output).to include('[-]')
        expect(output).not_to include('file retrieved with success.', 'file stored in loot.')
        expect(paths).to eq([])
      end
      output
    end
  end
end
