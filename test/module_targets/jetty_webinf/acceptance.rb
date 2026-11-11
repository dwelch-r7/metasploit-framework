# frozen_string_literal: true

require 'base64'
require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Compare owning output/loot with independent target file and HTTP captures.
  module JettyWebinf
    OWNER = 'auxiliary/gather/jetty_web_inf_disclosure'

    def jetty_native(phase, program: 'native_probe.py')
      output = +''
      argv = ['python3', "test/module_targets/jetty_webinf/#{program}", ENV.fetch('MODULE_TARGET_RUNTIME'), ENV.fetch('JETTY_PROFILE'), phase]
      passed = ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 90, capture: output, quiet: true)
      expect(passed).to be(true), output
      native = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
      expect(native.fetch('status')).to eq('native_passed')
      native
    end

    def jetty_call(cve, file: nil, action: 'run', options: {})
      previous = Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/*')]
      datastore = { 'CVE' => cve, 'ConnectTimeout' => 2 }.merge(options)
      datastore['FILE'] = file if file
      output = run_target_module(OWNER, 'target', datastore, action: action, allow_errors: true)
      after = Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/*')]
      # Console bytes are evidence too. Preserve non-UTF8 output without changing
      # the actual module, encoder, transport or console presentation.
      text = output.dup.force_encoding(Encoding::UTF_8)
      record = { cve: cve, file: file, action: action, options: options, loot_created: after - previous }
      record[text.valid_encoding? ? :output : :output_base64] = text.valid_encoding? ? text : Base64.strict_encode64(output)
      File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') { |log| log.puts(JSON.generate(record)) }
      expect(output).not_to include('Unknown datastore option')
      [output, after - previous]
    end

    def jetty_loot(cve, name = 'web.xml', default: false)
      output, created = jetty_call(cve, file: default ? nil : name)
      if jetty_profile.fetch('vulnerable').fetch(cve)
        matches = output.scan(/File stored to ([^\r\n]+)/).flatten.map(&:strip)
        expect(matches.size).to eq(1), output
        expect(created).to eq(matches)
        expect(File.expand_path(matches.first)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
        expect(File.binread(matches.first)).to eq(Base64.strict_decode64(@native.fetch('files').fetch(name).fetch('base64')))
      else
        expect(output).to include('not-vulnerable', "Jetty #{jetty_profile.fetch('server_version')} is not vulnerable")
        expect(created).to eq([])
      end
    end
  end
end
