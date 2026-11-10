require 'rspec'
require 'tmpdir'
require_relative '../../../tools/dev/run_guarded_module_target_tests'

RSpec.describe GuardedModuleTargetTests do
  let(:lock_path) { File.join(@directory, 'shared', 'runner.lock') }
  let(:runner) { described_class.new(lock_path: lock_path) }
  let(:calls) { [] }
  let(:inventory) { '' }
  let(:inventory_success) { true }
  let(:inventory_timeout) { false }
  let(:preflight_success) { true }
  let(:cleanup_success) { true }
  let(:interrupt_startup) { false }
  # Service names/shape follow the recorded compact Druid Compose config. Only
  # count-related data is needed here; no command starts Docker or a target.
  let(:resolved_config) do
    { 'services' => { 'metadata' => {}, 'zookeeper' => {}, 'app' => {}, 'gateway' => {}, 'framework' => {} } }
  end
  let(:resolved_json) { JSON.generate(resolved_config) }

  around do |example|
    original_environment = ENV.to_h.select { |name, _value| name.start_with?('MODULE_TARGET_') }
    Dir.mktmpdir('module-target-guard-spec') do |directory|
      @directory = directory
      files = ModuleTargetTests::CONSOLE_BUILD_FILES + %w[
        Dockerfile test/module_targets/framework.compose.yaml spec/fake.rb
        spec/support/acceptance/module_target.rb spec/support/acceptance/child_process.rb
        lib/msf/core/modules/metadata/store.rb lib/msf/core/option_container.rb
        lib/msf/ui/console/module_argument_parsing.rb tools/dev/run_module_target_tests.rb
      ]
      files.each do |name|
        path = File.join(directory, name)
        FileUtils.mkdir_p(File.dirname(path))
        File.write(path, "Fixture\n")
      end
      example.run
    end
  ensure
    ENV.keys.grep(/\AMODULE_TARGET_/).each { |name| ENV.delete(name) }
    ENV.update(original_environment)
  end

  before do
    stub_const('ModuleTargetTests::ROOT', @directory)
    stub_const('ModuleTargetTests::TARGETS', File.join(@directory, 'test/module_targets'))
    family('alpha')
    allow(Open3).to receive(:capture2) do |*arguments, **_options|
      case arguments
      when ['git', 'rev-parse', 'HEAD']
        ["fixture-revision\n", nil]
      when ['git', 'diff', '--stat']
        ['', nil]
      when ['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', 'framework-id']
        [JSON.generate('default' => { 'IPAddress' => '192.0.2.8' }), double(success?: true)]
      else
        raise "Unexpected external command: #{arguments.inspect}"
      end
    end
    allow(runner).to receive(:command) do |arguments, **options|
      calls << { argv: arguments, options: options }
      if arguments[0, 2] == ['docker', 'ps']
        raise Timeout::Error, 'Inventory deadline' if inventory_timeout

        options.fetch(:capture) << (inventory.respond_to?(:call) ? inventory.call : inventory)
        inventory_success
      elsif arguments.include?('--output')
        File.write(arguments.fetch(arguments.index('--output') + 1), resolved_json)
        preflight_success
      elsif arguments.include?('up')
        expect_lock_held
        raise Interrupt if interrupt_startup

        true
      elsif arguments.include?('rspec')
        report = arguments.fetch(arguments.index('--out') + 1)
        File.write(report, JSON.generate(summary: { example_count: 1, failure_count: 0, pending_count: 0, errors_outside_of_examples_count: 0 }))
        # The existing runner owns this cache and its within-invocation reuse.
        cache = File.join(File.dirname(File.dirname(report)), '.metadata-cache', console_family?(File.dirname(report)) ? 'container' : 'native')
        FileUtils.mkdir_p(cache)
        %w[modules_metadata.json module_metadata_cache.json].each { |name| File.write(File.join(cache, name), JSON.generate('fixture' => {})) }
        true
      elsif arguments.include?('down')
        expect_lock_held
        cleanup_success
      else
        options[:capture]&.concat(arguments.last == 'framework' ? 'framework-id' : '')
        true
      end
    end
  end

  def family(name, console: false)
    directory = File.join(@directory, 'test/module_targets', name)
    FileUtils.mkdir_p(directory)
    File.write(File.join(directory, 'manifest.yml'), YAML.dump('modules' => [], 'spec' => 'spec/fake.rb', 'ports' => {}, 'expected_examples' => 1, 'console' => console))
    File.write(File.join(directory, 'compose.yaml'), "services: {}\n")
  end

  def console_family?(directory)
    YAML.safe_load_file(File.join(@directory, 'test/module_targets', File.basename(directory), 'manifest.yml')).fetch('console')
  end

  def results
    JSON.parse(File.read(File.join(runner.instance_variable_get(:@results), 'summary.json')))
  end

  def expect_lock_held
    File.open(lock_path, File::RDWR) { |file| expect(file.flock(File::LOCK_EX | File::LOCK_NB)).to be(false) }
  end

  def expect_lock_released
    File.open(lock_path, File::RDWR) { |file| expect(file.flock(File::LOCK_EX | File::LOCK_NB)).to eq(0) }
  end

  def expect_no_start_or_cleanup
    expect(calls.none? { |call| (call[:argv] & %w[up down]).any? }).to be(true)
  end

  it 'delegates an allowed family and fingerprints the guard alongside ordinary inputs' do
    expect(runner.run(['alpha'])).to eq(0)
    expect(results.first).to include('status' => 'passed', 'cleanup' => 'passed')
    expect(results.first.fetch('inputs_sha256')).to include(
      described_class::SOURCE_PATH => Digest::SHA256.file(File.expand_path('../../../tools/dev/run_guarded_module_target_tests.rb', __dir__)).hexdigest,
      'tools/dev/run_module_target_tests.rb' => Digest::SHA256.file(File.join(@directory, 'tools/dev/run_module_target_tests.rb')).hexdigest
    )
    expect_lock_released
  end

  it 'keeps the lock across sequential cleanup and ordinary metadata reuse' do
    family('alpha', console: true)
    family('beta', console: true)
    expect(runner.run(%w[alpha beta])).to eq(0)
    expect(results.map { |result| result.fetch('status') }).to eq(%w[passed passed])
    expect(results.last.fetch('metadata_cache_seed_sha256').keys.sort).to eq(%w[module_metadata_cache.json modules_metadata.json])
    expect(calls.select { |call| (call[:argv] & %w[up down]).any? }.map { |call| call[:argv].find { |value| %w[up down].include?(value) } }).to eq(%w[up down up down])
    preview = calls.find { |call| call[:argv].include?('--output') }
    expect(preview[:argv].count('--file')).to eq(2)
    expect(preview[:options].fetch(:env)).to include('MODULE_TARGET_ROOT' => @directory, 'MODULE_TARGET_UID' => Process.uid.to_s)
    expect_lock_released
  end

  it 'refuses an actual competing process lock without running commands' do
    FileUtils.mkdir_p(File.dirname(lock_path))
    ready_reader, ready_writer = IO.pipe
    release_reader, release_writer = IO.pipe
    child = Process.fork do
      ready_reader.close
      release_writer.close
      File.open(lock_path, File::RDWR | File::CREAT, 0o600) do |file|
        file.flock(File::LOCK_EX)
        ready_writer.write('1')
        ready_writer.close
        release_reader.read(1)
      end
      exit! 0
    end
    ready_writer.close
    release_reader.close
    expect(IO.select([ready_reader], nil, nil, 5)).not_to be_nil
    expect(ready_reader.read(1)).to eq('1')
    expect(runner.run(['alpha'])).to eq(1)
    expect(calls).to be_empty
    expect(results.first).to include('status' => 'setup_resource_refused', 'module_verdict' => nil, 'cleanup' => 'not_started')
  ensure
    release_writer&.close
    ready_reader&.close
    Process.waitpid(child) if child
  end

  context 'with an existing container, including a stopped one' do
    let(:inventory) { "#{'a' * 64}\n" }

    it 'refuses before entering any family or invoking its cleanup' do
      expect(runner.run(['alpha'])).to eq(1)
      expect(calls.map { |call| call[:argv] }).to eq([['docker', 'ps', '--all', '--quiet', '--no-trunc']])
      expect(results.first).to include('status' => 'setup_resource_refused', 'module_verdict' => nil)
      expect_no_start_or_cleanup
      expect_lock_released
    end
  end

  context 'with six effective services' do
    let(:resolved_config) { super().tap { |config| config.fetch('services')['extra'] = {} } }

    it 'refuses before base startup/cleanup and stops later families' do
      family('beta')
      expect(runner.run(%w[alpha beta])).to eq(1)
      expect(results.map { |result| result.fetch('status') }).to eq(%w[setup_resource_refused setup_resource_refused])
      expect(calls.count { |call| call[:argv].include?('--output') }).to eq(1)
      expect_no_start_or_cleanup
      expect_lock_released
    end
  end

  context 'with replicated services above the cap' do
    let(:resolved_config) { { 'services' => { 'worker' => { 'deploy' => { 'replicas' => 5 } }, 'framework' => {} } } }

    it 'counts replicas rather than only service keys' do
      expect(runner.run(['alpha'])).to eq(1)
      expect(results.first.fetch('error')).to include('6 containers')
      expect_no_start_or_cleanup
    end
  end

  context 'with scale and replicas describing the same service' do
    let(:resolved_config) { { 'services' => { 'worker' => { 'scale' => 4, 'deploy' => { 'replicas' => 4 } }, 'framework' => {} } } }

    it 'accepts exactly five containers without double counting' do
      expect(runner.run(['alpha'])).to eq(0)
    end
  end

  context 'with disabled or zero-replica services' do
    let(:resolved_config) { super().tap { |config| config.fetch('services')['optional'] = { 'profiles' => ['optional'], 'scale' => 0 } } }

    it 'conservatively counts every resolved service' do
      expect(runner.run(['alpha'])).to eq(1)
      expect_no_start_or_cleanup
    end
  end

  context 'with malformed JSON' do
    let(:resolved_json) { '{broken' }

    it 'records a setup/resource refusal without startup or cleanup' do
      expect(runner.run(['alpha'])).to eq(1)
      expect(results.first).to include('status' => 'setup_resource_refused', 'module_verdict' => nil)
      expect_no_start_or_cleanup
      expect_lock_released
    end
  end

  context 'with a malformed services shape' do
    let(:resolved_config) { { 'services' => [] } }

    it 'fails closed before startup' do
      expect(runner.run(['alpha'])).to eq(1)
      expect_no_start_or_cleanup
    end
  end

  context 'with an unbounded deployment mode' do
    let(:resolved_config) { { 'services' => { 'worker' => { 'deploy' => { 'mode' => 'global' } } } } }

    it 'refuses rather than guessing a node count' do
      expect(runner.run(['alpha'])).to eq(1)
      expect_no_start_or_cleanup
    end
  end

  context 'with a fractional replica count' do
    let(:resolved_config) { { 'services' => { 'worker' => { 'scale' => 2.5 } } } }

    it 'refuses instead of truncating the count' do
      expect(runner.run(['alpha'])).to eq(1)
      expect_no_start_or_cleanup
    end
  end

  context 'with a failed Compose preflight' do
    let(:preflight_success) { false }

    it 'does not enter the base family ensure block' do
      expect(runner.run(['alpha'])).to eq(1)
      expect_no_start_or_cleanup
    end
  end

  context 'with failed inventory' do
    let(:inventory_success) { false }

    it 'fails closed and releases the lock' do
      expect(runner.run(['alpha'])).to eq(1)
      expect_no_start_or_cleanup
      expect_lock_released
    end
  end

  context 'with malformed inventory output' do
    let(:inventory) { "Unexpected banner\n" }

    it 'does not treat it as an empty Docker Engine' do
      expect(runner.run(['alpha'])).to eq(1)
      expect_no_start_or_cleanup
    end
  end

  context 'with an inventory deadline' do
    let(:inventory_timeout) { true }

    it 'classifies the timeout as setup/resource and releases the lock' do
      expect(runner.run(['alpha'])).to eq(1)
      expect(results.first).to include('status' => 'setup_resource_refused', 'module_verdict' => nil)
      expect_no_start_or_cleanup
      expect_lock_released
    end
  end

  context 'when another container appears after the first project' do
    let(:inventory) { -> { calls.any? { |call| call[:argv].include?('down') } ? "#{'b' * 64}\n" : '' } }

    it 'does not start or clean the next project' do
      family('beta')
      expect(runner.run(%w[alpha beta])).to eq(1)
      expect(results.map { |result| result.fetch('status') }).to eq(%w[passed setup_resource_refused])
      expect(calls.count { |call| call[:argv].include?('up') }).to eq(1)
      expect(calls.count { |call| call[:argv].include?('down') }).to eq(1)
      expect_lock_released
    end
  end

  context 'with interrupted startup' do
    let(:interrupt_startup) { true }

    it 'preserves the interruption, keeps normal cleanup and releases the lock' do
      expect { runner.run(['alpha']) }.to raise_error(Interrupt)
      expect(calls.any? { |call| call[:argv].include?('down') }).to be(true)
      expect_lock_released
    end
  end

  context 'with failed normal cleanup' do
    let(:cleanup_success) { false }

    it 'prevents the next project starting' do
      family('beta')
      expect(runner.run(%w[alpha beta])).to eq(1)
      expect(results.map { |result| result.fetch('status') }).to eq(%w[cleanup_failed setup_resource_refused])
      expect(calls.count { |call| call[:argv].include?('up') }).to eq(1)
      expect_lock_released
    end
  end

  it 'lists families without a lock or Docker commands' do
    expect { expect(runner.run(['--list'])).to eq(0) }.to output("alpha\n").to_stdout
    expect(calls).to be_empty
    expect(File.exist?(lock_path)).to be(false)
  end

  it 'retains usage errors without Docker commands or locking' do
    expect { expect(runner.run(['missing'])).to eq(2) }.to output(/Usage:/).to_stderr
    expect(calls).to be_empty
    expect(File.exist?(lock_path)).to be(false)
  end
end
