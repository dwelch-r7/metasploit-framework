require 'spec_helper'
require 'tmpdir'
require 'open3'
require 'rbconfig'
require 'fileutils'
require 'json'

RSpec.describe 'PHP source-variant acceptance lifecycle' do
  let(:root) { File.expand_path('../../..', __dir__) }
  let(:fixture) { File.join(root, 'spec/file_fixtures/module_targets/php_meterpreter_source/lifecycle.rb') }
  let(:source_spec) { 'spec/modules/exploits/linux/http/projectsend_source_target_spec.rb' }
  let(:variant) { 'test/module_targets/php_meterpreter_source/variant.rb' }
  let(:patch) { 'test/module_targets/php_meterpreter_source/stream_framing.patch' }

  # The real source-wrapper hooks and variant helper run under real RSpec in a
  # small project. Only the native/console examples are replaced; payload gem
  # verification, patching, isolated override files and cleanup are genuine.
  def run_lifecycle(selection, mode: nil, runtime: true, config: true, invalid_patch: false, example_failure: false, changed_override: false)
    Dir.mktmpdir('php-source-lifecycle-') do |directory|
      artifacts = File.join(directory, 'artifacts')
      FileUtils.mkdir_p(artifacts)
      File.write(File.join(directory, 'acceptance_spec_helper.rb'), '')
      [source_spec, variant, patch].each do |name|
        destination = File.join(directory, name)
        FileUtils.mkdir_p(File.dirname(destination))
        FileUtils.cp(File.join(root, name), destination)
      end
      File.write(File.join(directory, patch), "This is not a unified diff.\n") if invalid_patch
      shared = File.join(directory, 'test/module_targets/projectsend_sessions/examples.rb')
      FileUtils.mkdir_p(File.dirname(shared))
      File.write(shared, <<~'SHARED')
        RSpec.shared_examples 'ProjectSend default Meterpreter sessions' do
          before(:context) do
            @rc = {}
            lifecycle_event('console_started')
            raise 'Source override missing before console startup' unless File.file?(source_override)
          end
          after(:context) { lifecycle_event('console_stopped') }
          it('native readiness', native: true) { lifecycle_event('native') }
          it('independent controls') { lifecycle_event('control') }
          it 'original owner', owner: true do
            lifecycle_event('owner')
            File.write(source_override, 'unexpected changed bytes') if ENV['SOURCE_LIFECYCLE_CHANGE'] == 'true'
            raise 'Original synthetic owner failure' if ENV['SOURCE_LIFECYCLE_FAIL'] == 'true'
          end
          it('preservation', owner: true) { lifecycle_event('preservation') }
        end
      SHARED
      ordinary = File.join(directory, 'spec/modules/exploits/linux/http/projectsend_sessions_target_spec.rb')
      File.write(ordinary, <<~'ORDINARY')
        require_relative '../../../../../test/module_targets/projectsend_sessions/examples'
        RSpec.describe 'Synthetic ordinary ProjectSend sessions', acceptance: true, order: :defined do
          include_examples 'ProjectSend default Meterpreter sessions'
        end
      ORDINARY
      File.write(File.join(directory, 'unrelated_spec.rb'), <<~'UNRELATED')
        RSpec.describe 'Unrelated ordinary discovery' do
          it('content example', content: true) { lifecycle_event('content') }
        end
      UNRELATED
      runtime_path = File.join(directory, 'runtime.json')
      File.write(runtime_path, JSON.generate(artifacts: artifacts))
      report = File.join(directory, 'report.json')
      events = File.join(directory, 'events.log')
      environment = {
        'MODULE_TARGET_RUNTIME' => runtime ? runtime_path : nil,
        'PHP_METERPRETER_SOURCE_MODE' => mode,
        'MSF_CFGROOT_CONFIG' => config ? File.join(artifacts, 'msf-config') : nil,
        'SOURCE_LIFECYCLE_ARTIFACTS' => artifacts, 'SOURCE_LIFECYCLE_EVENTS' => events,
        'SOURCE_LIFECYCLE_FAIL' => example_failure.to_s, 'SOURCE_LIFECYCLE_CHANGE' => changed_override.to_s,
        'GEM_HOME' => directory, 'GEM_PATH' => directory, 'RUBYLIB' => nil
      }
      stdout, stderr, status = Bundler.with_unbundled_env do
        Open3.capture3(environment, RbConfig.ruby, '-I', $LOAD_PATH.join(File::PATH_SEPARATOR), fixture, directory, report, selection, chdir: directory)
      end
      raise "Child did not produce its JSON report:\n#{stdout}\n#{stderr}" unless File.file?(report) && !File.empty?(report)

      data = JSON.parse(File.read(report))
      journal = File.join(artifacts, 'php-source-variant.json')
      {
        exit: status.exitstatus, output: stdout + stderr + JSON.pretty_generate(data),
        report: data,
        events: File.file?(events) ? File.readlines(events, chomp: true) : [],
        journal: File.file?(journal) ? JSON.parse(File.read(journal)) : nil,
        override_present: File.exist?(File.join(artifacts, 'msf-config/payloads/meterpreter/meterpreter.php')),
        staging_present: File.exist?(File.join(artifacts, 'payload-source-build'))
      }
    end
  end

  it 'runs unrelated content discovery without a lab runtime or source preparation' do
    result = run_lifecycle('content', runtime: false)

    expect(result).to include(exit: 0, events: ['content'], journal: nil, override_present: false, staging_present: false)
    expect(result[:report].fetch('summary')).to include('example_count' => 1, 'failure_count' => 0, 'errors_outside_of_examples_count' => 0)
  end

  it 'does not prepare a requested candidate when its acceptance group is excluded' do
    result = run_lifecycle('content', mode: 'candidate')

    expect(result).to include(exit: 0, events: ['content'], journal: nil, override_present: false, staging_present: false)
  end

  it 'registers selected candidate examples during dry-run without touching source' do
    result = run_lifecycle('dry-run', mode: 'candidate')

    expect(result).to include(exit: 0, events: [], journal: nil, override_present: false, staging_present: false)
    expect(result[:report].fetch('summary')).to include('example_count' => 4, 'failure_count' => 0)
  end

  it 'verifies the baseline source before startup and removes its isolated override' do
    result = run_lifecycle('acceptance', mode: 'baseline')

    expect(result[:exit]).to eq(0), result[:output]
    expect(result[:events]).to eq(%w[console_started bind save native control owner preservation console_stopped])
    expect(result[:journal]).to include('mode' => 'baseline', 'stock_qualification' => false, 'override_removed' => true)
    expect(result[:journal].fetch('installed_after')).to eq(result[:journal].fetch('installed_before'))
    expect(result[:override_present]).to be(false)
  end

  it 'patches and verifies candidate source without downgrading to baseline' do
    result = run_lifecycle('acceptance', mode: 'candidate')

    expect(result[:exit]).to eq(0), result[:output]
    expect(result[:journal].fetch('patch').fetch('exit')).to eq(0)
    expect(result[:journal].fetch('prepared').fetch('sha256')).to eq('e17550cce49a90f2a0922242b8697095d35d2c689df0ef3916fb4f104c23f7a1')
    expect(result[:journal]).to include('mode' => 'candidate', 'stock_qualification' => false, 'override_removed' => true)
  end

  it 'fails closed when a selected variant has no runtime' do
    result = run_lifecycle('acceptance', mode: 'candidate', runtime: false)

    expect(result[:exit]).to eq(1)
    expect(result[:output]).to include('MODULE_TARGET_RUNTIME')
    expect(result[:events]).to eq([])
    expect(result[:override_present]).to be(false)
  end

  it 'fails closed when a selected source comparison has no mode' do
    result = run_lifecycle('acceptance')

    expect(result[:exit]).to eq(1)
    expect(result[:output]).to include('PHP_METERPRETER_SOURCE_MODE')
    expect(result[:events]).to eq([])
  end

  it 'rejects an unknown source mode before starting the console' do
    result = run_lifecycle('acceptance', mode: 'stock')

    expect(result[:exit]).to eq(1)
    expect(result[:output]).to include('Expected baseline or candidate source mode')
    expect(result[:events]).to eq([])
  end

  it 'requires an isolated Framework configuration for selected source comparisons' do
    result = run_lifecycle('acceptance', mode: 'candidate', config: false)

    expect(result[:exit]).to eq(1)
    expect(result[:output]).to include('MSF_CFGROOT_CONFIG')
    expect(result[:events]).to eq([])
  end

  it 'retains a candidate patch error and never runs baseline examples instead' do
    result = run_lifecycle('acceptance', mode: 'candidate', invalid_patch: true)

    expect(result[:exit]).to eq(1)
    expect(result[:output]).to include('Candidate source patch failed')
    expect(result[:journal].fetch('patch').fetch('exit')).not_to eq(0)
    expect(result[:journal].fetch('installed_after')).to eq(result[:journal].fetch('installed_before'))
    expect(result[:events]).to eq([])
    expect(result[:override_present]).to be(false)
  end

  it 'removes the override while retaining an original example failure' do
    result = run_lifecycle('acceptance', mode: 'candidate', example_failure: true)

    expect(result[:exit]).to eq(1)
    expect(result[:output]).to include('Original synthetic owner failure')
    expect(result[:journal].fetch('override_removed')).to be(true)
    expect(result[:report].fetch('summary')).to include('failure_count' => 1, 'errors_outside_of_examples_count' => 0)
  end

  it 'preserves both the original example error and a genuine cleanup integrity error' do
    result = run_lifecycle('acceptance', mode: 'candidate', example_failure: true, changed_override: true)

    expect(result[:exit]).to eq(1)
    expect(result[:output]).to include('Original synthetic owner failure', 'The payload override changed unexpectedly before cleanup')
    expect(result[:override_present]).to be(true)
  end
end
