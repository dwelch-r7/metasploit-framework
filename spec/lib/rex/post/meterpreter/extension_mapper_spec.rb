require 'rspec'
require 'json'
require 'open3'
require 'rbconfig'
require 'tmpdir'

RSpec.describe 'Cold Meterpreter extension loading' do
  # Each child uses real msfenv/Bootsnap/Stdapi/ExtensionMapper. TracePoint only
  # holds the first loader after the actual fs/dir circular require. No require,
  # namespace, class, mapper or cache response is replaced with a test double.
  # Fresh subprocesses keep the cold state isolated from the rest of RSpec.
  {
    'cached' => 'synchronizes simultaneous cold class lookups',
    'module_first' => 'synchronizes a cold module lookup with a class lookup',
    'uncached' => 'retains native require synchronization without the load-path cache',
    'reentrant' => 'allows a same-thread module lookup during the actual circular import',
    'failure_then_valid' => 'releases loading synchronization after an actual missing-extension error',
    'sequential' => 'retains sequential cold loading and cached class identity'
  }.each do |mode, label|
    it label do
      root = File.expand_path('../../../../..', __dir__)
      probe = File.join(root, 'spec/file_fixtures/rex/post/meterpreter/extension_loading_probe.rb')
      stdout = stderr = status = nil
      Dir.mktmpdir('meterpreter-extension-loading-') do |config|
        stdout, stderr, status = Open3.capture3({ 'MSF_CFGROOT_CONFIG' => config }, RbConfig.ruby, '-I', File.join(root, 'lib'), probe, mode, chdir: root)
      end
      record = stdout.lines.find { |line| line.start_with?('EXTENSION_LOADING_PROBE=') }
      data = record && JSON.parse(record.delete_prefix('EXTENSION_LOADING_PROBE='))
      if (output = ENV['METERPRETER_EXTENSION_PROBE_OUTPUT_DIR'])
        File.write(File.join(output, "#{mode}.stdout"), stdout)
        File.write(File.join(output, "#{mode}.stderr"), stderr)
        File.write(File.join(output, "#{mode}.process.json"), JSON.pretty_generate(actual_exit: status.exitstatus, mode: mode, result: data) + "\n")
      end

      expect([status.exitstatus, data&.fetch('success'), data&.fetch('threads_alive_at_exit')]).to eq([0, true, 0]), "Actual loader result: #{data.inspect}; stderr: #{stderr}"
    end
  end
end
