require 'rspec'
require 'tmpdir'
require_relative '../../../tools/dev/run_module_target_tests'
require_relative '../../../tools/dev/module_target_endpoint'

RSpec.describe 'Manifest-driven module endpoint selection' do
  let(:runner) { ModuleTargetTests.new }
  let(:capture) { JSON.parse(File.read(File.expand_path('../../file_fixtures/tools/module_targets/network_selection/topology.json', __dir__))) }
  let(:containers) { capture.fetch('containers') }
  let(:networks) { capture.fetch('networks') }
  let(:calls) { [] }
  let(:command_records) { [] }
  let(:manifest) { { 'console' => true, 'spec' => 'spec/fake.rb', 'modules' => [], 'expected_examples' => 1, 'ports' => { 'gateway' => 80 } } }

  around do |example|
    original = ENV.to_h.select { |name, _value| name.start_with?('MODULE_TARGET_') }
    Dir.mktmpdir('module-target-network-spec') do |directory|
      @directory = directory
      example.run
    end
  ensure
    ENV.keys.grep(/\AMODULE_TARGET_/).each { |name| ENV.delete(name) }
    ENV.update(original)
  end

  before do
    stub_const('ModuleTargetTests::ROOT', @directory)
    stub_const('ModuleTargetTests::TARGETS', File.join(@directory, 'test/module_targets'))
    runner.instance_variable_set(:@results, File.join(@directory, 'results'))
    runner.instance_variable_set(:@run_id, 'capture')
    capture['project'] = 'msf-target-capture-alpha'
    (containers.values + networks.values).each do |object|
      labels = object['Config'] ? object.fetch('Config').fetch('Labels') : object.fetch('Labels')
      labels['com.docker.compose.project'] = capture.fetch('project')
    end
    files = ModuleTargetTests::CONSOLE_BUILD_FILES + %w[
      Dockerfile test/module_targets/framework.compose.yaml spec/fake.rb
      spec/support/acceptance/module_target.rb spec/support/acceptance/child_process.rb
      lib/msf/core/modules/metadata/store.rb lib/msf/core/option_container.rb
      lib/msf/ui/console/module_argument_parsing.rb tools/dev/run_module_target_tests.rb
      tools/dev/module_target_endpoint.rb
    ]
    files.each do |name|
      path = File.join(@directory, name)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, "Fixture\n")
    end
    family = File.join(@directory, 'test/module_targets/alpha')
    FileUtils.mkdir_p(family)
    File.write(File.join(family, 'manifest.yml'), YAML.dump(manifest))
    File.write(File.join(family, 'compose.yaml'), "services: {}\n")
    allow(Open3).to receive(:capture2) do |*argv, **_options|
      if argv == ['git', 'rev-parse', 'HEAD']
        ["fixture-revision\n", nil]
      elsif argv == ['git', 'diff', '--stat']
        ['', nil]
      elsif argv[0, 4] == ['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}']
        calls << argv
        service = argv.last.delete_suffix('-container-id')
        [JSON.generate(containers.fetch(service).fetch('NetworkSettings').fetch('Networks')), double(success?: true)]
      else
        raise "Unexpected external process: #{argv.inspect}"
      end
    end
    allow(Open3).to receive(:popen2e) { raise 'Actual process execution is forbidden in this spec' }
    allow(Open3).to receive(:capture3) { raise 'Actual process execution is forbidden in this spec' }
    allow(runner).to receive(:command) do |argv, **options|
      calls << argv
      command_records << { argv: argv, options: options }
      value = if argv[0, 3] == ['docker', 'container', 'inspect']
                JSON.generate([containers.fetch(argv.last.delete_suffix('-container-id'))])
              elsif argv[0, 3] == ['docker', 'network', 'inspect']
                JSON.generate([networks.fetch(argv.last)])
              elsif argv.include?('port')
                "127.0.0.1:50000\n"
              elsif argv.include?('ps') && argv.include?('--quiet') && !argv.include?('--all')
                "#{argv.last}-container-id\n"
              elsif argv[0, 3] == ['bundle', 'exec', 'rspec'] && argv[3] == 'spec/fake.rb'
                ''
              elsif argv[0, 2] == ['docker', 'compose'] && (argv & %w[config up ps images logs down]).length == 1
                ''
              else
                raise "Unexpected runner command: #{argv.inspect}"
              end
      options[:capture]&.concat(value)
      if argv.include?('rspec')
        File.write(argv.fetch(argv.index('--out') + 1), JSON.generate(summary: { example_count: 1, failure_count: 0, pending_count: 0, errors_outside_of_examples_count: 0 }))
      end
      true
    end
  end

  def runtime
    JSON.parse(File.read(File.join(@directory, 'results/alpha/runtime.json')))
  end

  context 'without a network selector' do
    before do
      containers.fetch('gateway').fetch('NetworkSettings').fetch('Networks').delete('msf-target-capture_public')
    end

    it 'keeps the existing two-argument address method and inspect commands' do
      expect(runner).not_to receive(:endpoint_selector)
      expect(runner).to receive(:container_ip).with(kind_of(Array), 'gateway').and_call_original
      expect(runner).to receive(:container_ip).with(kind_of(Array), 'framework').and_call_original

      expect(runner.send(:run_family, 'alpha')).to include(status: 'passed')
      expect(calls.select { |argv| argv[0, 2] == ['docker', 'inspect'] }).to eq([
        ['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', 'gateway-container-id'],
        ['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', 'framework-container-id']
      ])
      expect(runtime.fetch('module_endpoints')).to eq('gateway' => { 'host' => '192.0.2.9', 'port' => 80 })
    end

    it 'does not add the opt-in helper to the existing input closure' do
      result = runner.send(:run_family, 'alpha')

      expect(result).to include(status: 'passed')
      expect(result.fetch(:inputs_sha256)).not_to have_key('tools/dev/module_target_endpoint.rb')
    end

    it 'retains the original refusal of an unopted dual-network endpoint' do
      containers.fetch('gateway').fetch('NetworkSettings').fetch('Networks')['public'] = { 'NetworkID' => 'public-network-id', 'IPAddress' => '192.0.2.10' }

      expect(runner.send(:run_family, 'alpha')).to include(status: 'setup_failed', error: 'RuntimeError: Expected one isolated network for gateway')
    end
  end

  context 'with an explicit internal network' do
    let(:manifest) { super().merge('module_endpoint_network' => 'default') }

    it 'wires the captured two-network topology through the ordinary shared runner' do
      expect(runner).not_to receive(:container_ip)

      expect(runner.send(:run_family, 'alpha')).to include(status: 'passed')
      expect(runtime.fetch('module_endpoints')).to eq('gateway' => { 'host' => '192.0.2.9', 'port' => 80 })
      expect(runtime.fetch('listener_host')).to eq('192.0.2.8')
    end

    it 'fingerprints the opt-in selector source' do
      result = runner.send(:run_family, 'alpha')

      expect(result).to include(status: 'passed')
      expect(result.fetch(:inputs_sha256)).to include('tools/dev/module_target_endpoint.rb' => Digest::SHA256.file(File.join(@directory, 'tools/dev/module_target_endpoint.rb')).hexdigest)
    end

    it 'uses the bounded capture for every new inspect command' do
      expect(runner.send(:run_family, 'alpha')).to include(status: 'passed')
      inspections = command_records.select { |record| record.fetch(:argv)[0, 3] == ['docker', 'network', 'inspect'] }

      expect(inspections).not_to be_empty
      expect(inspections.map { |record| record.fetch(:options) }).to all(include(timeout: 30, quiet: true, capture: kind_of(String)))
    end

    it 'refuses a container inspect response for a different ID' do
      containers.fetch('gateway')['Id'] = 'another-container-id'

      expect(runner.send(:run_family, 'alpha')).to include(status: 'setup_failed', error: 'ArgumentError: Inspected module endpoint container ID differs')
      expect(calls.none? { |argv| argv.include?('rspec') }).to be(true)
    end
  end

  context 'with a malformed selector' do
    let(:manifest) { super().merge('module_endpoint_network' => nil) }

    it 'rejects the configuration before startup' do
      expect(runner.send(:run_family, 'alpha')).to include(status: 'setup_failed', error: 'ArgumentError: Module endpoint network must be a logical Compose network name')
      expect(calls.none? { |argv| argv.include?('up') }).to be(true)
    end
  end
end
