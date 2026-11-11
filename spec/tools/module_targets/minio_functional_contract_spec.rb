require 'rspec'
require 'tmpdir'
require 'open3'
require 'rbconfig'
require_relative '../../../test/module_targets/minio/functional_gate'

RSpec.describe MinioTarget::Functional do
  let(:fixtures) { File.expand_path('../../file_fixtures/tools/module_targets/minio', __dir__) }
  let(:vulnerable) { JSON.parse(File.read(File.join(fixtures, 'bootstrap-vulnerable.json'))) }
  let(:fixed) { JSON.parse(File.read(File.join(fixtures, 'bootstrap-fixed.json'))) }

  def trace(record)
    # Source-defined wrapping of real native bytes, not an invented owner result.
    headers = record.fetch('headers').map { |key, value| "#{key}: #{value}" }.join("\r\n")
    "####################\n# Response:\n####################\nHTTP/1.1 #{record.fetch('status')} Captured\r\n#{headers}\r\n\r\n#{record.fetch('body')}\n[+] Later owner output\n"
  end

  it 'extracts the exact genuine vulnerable body without subsequent owner output' do
    expect(described_class.bootstrap_trace(trace(vulnerable)).fetch('body')).to eq(vulnerable.fetch('body'))
  end

  it 'preserves the genuine fixed 403 and JWT body' do
    expect(described_class.bootstrap_trace(trace(fixed))).to include('status' => 403, 'body' => 'JWT token missing')
  end

  it 'refuses a truncated genuine disclosure body' do
    text = trace(vulnerable).split(vulnerable.fetch('body'), 2).first + vulnerable.fetch('body')[0, 10]
    expect { described_class.bootstrap_trace(text) }.to raise_error(MinioTarget::Error, /truncated/)
  end

  it 'refuses ambiguous multiple traced responses' do
    expect { described_class.bootstrap_trace(trace(vulnerable) + trace(fixed)) }.to raise_error(MinioTarget::Error, /exactly one/)
  end

  it 'refuses a response without an exact length' do
    text = trace(vulnerable).gsub(/^Content-Length: [0-9]+\r?\n/i, '')
    expect { described_class.bootstrap_trace(text) }.to raise_error(MinioTarget::Error, /content length/)
  end

  it 'accepts strict JSON loot identical to the actual disclosure' do
    expect(described_class.bootstrap_loot(vulnerable.fetch('body'), vulnerable.fetch('body'))).to have_key('MinioEnv')
  end

  it 'rejects Ruby hash representation instead of silently accepting JSON metadata' do
    representation = JSON.parse(vulnerable.fetch('body')).inspect
    expect { described_class.bootstrap_loot(representation, vulnerable.fetch('body')) }.to raise_error(MinioTarget::Error, /not valid JSON/)
  end

  it 'rejects valid JSON that drops an actual environment field' do
    changed = JSON.parse(vulnerable.fetch('body'))
    changed.fetch('MinioEnv').delete('MINIO_ROOT_PASSWORD')
    expect { described_class.bootstrap_loot(JSON.generate(changed), vulnerable.fetch('body')) }.to raise_error(MinioTarget::Error, /complete genuine/)
  end

  context 'when selecting a dual-network gateway' do
    # Explicit protocol data for topology validation; no Framework runtime claim.
    let(:project) { 'msf-minio-contract' }
    let(:networks) do
      [
        { 'Id' => 'internal-id', 'Internal' => true, 'Labels' => { 'com.docker.compose.project' => project, 'com.docker.compose.network' => 'default' } },
        { 'Id' => 'public-id', 'Internal' => false, 'Labels' => { 'com.docker.compose.project' => project, 'com.docker.compose.network' => 'public' } }
      ]
    end
    let(:containers) do
      %w[node1 node2 gateway framework reporting_db].each_with_index.map do |name, index|
        memberships = { 'default-name' => { 'NetworkID' => 'internal-id', 'IPAddress' => "192.0.2.#{10 + index}" } }
        memberships['public-name'] = { 'NetworkID' => 'public-id', 'IPAddress' => '192.0.2.30' } if name == 'gateway'
        { 'Config' => { 'Labels' => { 'com.docker.compose.project' => project, 'com.docker.compose.service' => name } }, 'NetworkSettings' => { 'Networks' => memberships } }
      end
    end

    it 'chooses the explicit internal network rather than the public address' do
      expect(described_class.internal_endpoints(containers, networks, project)).to eq([
        { 'node1' => { 'host' => '192.0.2.12', 'port' => 19001 }, 'node2' => { 'host' => '192.0.2.12', 'port' => 19002 } }, '192.0.2.13'
      ])
    end

    it 'refuses a public MinIO server membership' do
      containers.first['NetworkSettings']['Networks']['public'] = { 'NetworkID' => 'public-id', 'IPAddress' => '192.0.2.31' }
      expect { described_class.internal_endpoints(containers, networks, project) }.to raise_error(MinioTarget::Error, /membership/)
    end

    it 'refuses an internal public-network declaration' do
      networks.last['Internal'] = true
      expect { described_class.internal_endpoints(containers, networks, project) }.to raise_error(MinioTarget::Error, /networks required/)
    end

    it 'refuses a sixth container even if its service label duplicates an owned role' do
      containers << containers.last.dup
      expect { described_class.internal_endpoints(containers, networks, project) }.to raise_error(MinioTarget::Error, /service set/)
    end

    it 'refuses a loopback container address' do
      containers[2]['NetworkSettings']['Networks']['default-name']['IPAddress'] = '127.0.0.1'
      expect { described_class.internal_endpoints(containers, networks, project) }.to raise_error(MinioTarget::Error, /IPv4/)
    end

    it 'writes every required real shared-context runtime field and isolated console config' do
      Dir.mktmpdir('minio-runtime-fields') do |directory|
        gate = MinioTarget::FunctionalGate.allocate
        gate.instance_variable_set(:@project, project)
        gate.instance_variable_set(:@directory, directory)
        gate.instance_variable_set(:@compose, ['docker', 'compose', '--project-name', project])
        gate.instance_variable_set(:@environment, {})
        gate.instance_variable_set(:@profile, 'vulnerable')
        gate.instance_variable_set(:@endpoints, { 'node1' => { 'host' => '127.0.0.1', 'port' => 40001 }, 'node2' => { 'host' => '127.0.0.1', 'port' => 40002 } })
        gate.instance_variable_set(:@owned, { 'containers' => ['owned-container'], 'networks' => ['owned-network'] })
        # Protocol data only: no Docker call or resource/runtime qualification.
        allow(gate).to receive(:required).with(['docker', 'inspect', 'owned-container'], 'runtime-identities').and_return(JSON.generate(containers))
        allow(gate).to receive(:required).with(['docker', 'network', 'inspect', 'owned-network'], 'runtime-networks').and_return(JSON.generate(networks))
        allow(described_class).to receive(:actual_resources).with(containers).and_return(true)
        runtime = JSON.parse(File.read(gate.send(:write_runtime)))
        source = File.read(File.join(MinioTarget::ROOT, 'spec/support/acceptance/module_target.rb'))
        required = source.scan(/target_runtime\.fetch\('([^']+)'/).flatten + source.scan(/target_runtime\['([^']+)'\]/).flatten
        expect(runtime.keys).to include(*required.uniq)
        expect(runtime.fetch('console_command')).to include("MSF_CFGROOT_CONFIG=#{directory}/msf-config")
        expect(File.directory?(File.join(directory, 'msf-config/store'))).to be(true)
        expect(runtime.fetch('metadata_cache')).to eq(File.join(directory, '.metadata-cache', 'container'))
        expect(File.exist?(runtime.fetch('metadata_cache'))).to be(false)
        expect(runtime.fetch('module_endpoints').keys.sort).to eq(%w[node1 node2])
        expect(runtime.fetch('listener_host')).to eq('192.0.2.13')
      end
    end
  end

  it 'requires a separate current Framework review before any Docker command' do
    Dir.mktmpdir('minio-review') do |directory|
      path = File.join(directory, 'review.json')
      File.write(path, JSON.generate(operation: 'canonical_framework_image_review', status: 'passed', context_sha256: {}))
      expect { described_class.framework_review(path) }.to raise_error(MinioTarget::Error, /explicit current/)
    end
  end

  context 'when mapping actual overlay mounts to container command arguments' do
    let(:overlay) { YAML.safe_load_file(File.join(MinioTarget::DIRECTORY, 'functional.compose.yaml')) }

    it 'resolves the real dependency argv through the mounted canonical repository' do
      gate = MinioTarget::FunctionalGate.allocate
      compose = ['docker', 'compose', '--project-name', 'msf-minio-contract']
      gate.instance_variable_set(:@compose, compose)
      command = gate.send(:dependency_check_command)
      expect(command.take(compose.length)).to eq(compose)
      expect(command).to include('framework', 'ruby')
      volume = overlay.fetch('services').fetch('framework').fetch('volumes').find { |value| value.start_with?('${MODULE_TARGET_ROOT:?}:') }
      destination = volume.match(%r{\A\$\{MODULE_TARGET_ROOT:\?\}:(/[^:]+):ro\z})[1]
      recipe = File.read(File.join(MinioTarget::ROOT, 'Dockerfile'))
      app_home = recipe[/^ENV APP_HOME=(\S+)$/, 1]
      expect(recipe.lines.grep(/^WORKDIR /).last.strip).to eq('WORKDIR $APP_HOME')
      expect(app_home).to eq(destination)
      container_script = File.expand_path(command.last, app_home)
      expect(container_script).to start_with(destination + '/')
      relative = container_script.delete_prefix(destination + '/')
      expect(File.join(MinioTarget::ROOT, relative)).to eq(File.join(MinioTarget::DIRECTORY, 'dependency_check.rb'))
      expect(File.file?(File.join(MinioTarget::ROOT, relative))).to be(true)
    end

    it 'preserves artifact paths across the host and Framework mount' do
      volume = overlay.fetch('services').fetch('framework').fetch('volumes').find { |value| value.start_with?('${MODULE_TARGET_ARTIFACTS:?}:') }
      expect(volume).to eq('${MODULE_TARGET_ARTIFACTS:?}:${MODULE_TARGET_ARTIFACTS:?}')
    end
  end

  context 'with actual node1 resource inspection fields' do
    let(:container) { JSON.parse(File.read(File.join(fixtures, 'node1-resource-inspect.json'))) }

    it 'accepts the genuine memory/swap/CPU/PID and no-publication capture' do
      expect(described_class.actual_resources([container])).to be(true)
    end

    it 'rejects unbounded swap despite the correct memory limit' do
      container['HostConfig']['MemorySwap'] = -1
      expect { described_class.actual_resources([container]) }.to raise_error(MinioTarget::Error, /limits/)
    end

    it 'rejects a direct server publication despite otherwise genuine limits' do
      container['HostConfig']['PortBindings'] = { '9000/tcp' => [{ 'HostIp' => '0.0.0.0', 'HostPort' => '9000' }] }
      expect { described_class.actual_resources([container]) }.to raise_error(MinioTarget::Error, /published/)
    end
  end

  it 'keeps the reviewed aggregate budget at 1600 MiB and 2.35 CPU' do
    settings = described_class.settings
    native = MinioTarget.assets.fetch('native')
    memory = 2 * native.fetch('memory_bytes') + native.fetch('gateway').fetch('memory_bytes') + settings.fetch('framework').fetch('memory_bytes') + settings.fetch('reporting_db').fetch('memory_bytes')
    cpu = 2 * native.fetch('nano_cpus') + native.fetch('gateway').fetch('nano_cpus') + settings.fetch('framework').fetch('nano_cpus') + settings.fetch('reporting_db').fetch('nano_cpus')
    expect([memory, cpu]).to eq([1600 * 1024 * 1024, 2_350_000_000])
  end

  it 'binds genuine fixture bytes and every main acceptance helper in the source map' do
    names = described_class.inputs.keys
    expect(names).to include('spec/acceptance/module_targets/minio_spec.rb', 'test/module_targets/minio/client_fixture.py', 'test/module_targets/minio/session_fixture.py', 'spec/support/acceptance/child_process.rb', 'lib/msf/core/auxiliary/report.rb')
  end

  context 'when registering acceptance examples without runtime hooks' do
    def discover(mode, profile: nil)
      Dir.mktmpdir('minio-discovery') do |directory|
        runtime = nil
        if profile
          runtime = File.join(directory, 'runtime.json')
          File.write(runtime, JSON.generate(profile: profile))
        end
        report = File.join(directory, 'report.json')
        # Bundler setup evaluates the Framework gemspec's metadata helpers.
        # Preserve resolved library paths without running setup in the child;
        # CI installs the required gems outside Ruby's default gem directories.
        stdout, stderr, status = Bundler.with_unbundled_env do
          Open3.capture3(
            {
              'MODULE_TARGET_RUNTIME' => runtime, 'SPEC_HELPER_LOAD_METASPLOIT' => 'false',
              'GEM_HOME' => directory, 'GEM_PATH' => directory, 'RUBYLIB' => nil
            },
            RbConfig.ruby, '-I', $LOAD_PATH.join(File::PATH_SEPARATOR), File.join(fixtures, 'spec_discovery.rb'), mode, report,
            chdir: MinioTarget::ROOT
          )
        end
        data = File.file?(report) ? JSON.parse(File.read(report)) : {}
        diagnostics = stdout + stderr + JSON.pretty_generate(data)
        expect(stdout).to include('MINIO_ISOLATED_DISCOVERY_ONLY_NO_FRAMEWORK_OR_PROCESSES'), diagnostics
        expect(status.success?).to be(true), diagnostics
        data.fetch('summary')
      end
    end

    it 'loads an unconfigured excluded spec without fetching campaign runtime' do
      expect(discover('excluded')).to include('example_count' => 0, 'errors_outside_of_examples_count' => 0)
    end

    it 'registers the default vulnerable cases without runtime execution' do
      expect(discover('included')).to include('example_count' => 6, 'errors_outside_of_examples_count' => 0)
    end

    it 'keeps all six configured vulnerable examples registered' do
      expect(discover('included', profile: 'vulnerable')).to include('example_count' => 6, 'errors_outside_of_examples_count' => 0)
    end

    it 'keeps all three configured fixed examples registered' do
      expect(discover('included', profile: 'fixed')).to include('example_count' => 3, 'errors_outside_of_examples_count' => 0)
    end
  end

  context 'when validating named client-state completion' do
    let(:records) do
      # Explicit completion protocol data; this does not qualify real sessions.
      described_class.initial_client_states('vulnerable').each do |row|
        row.merge!('entered' => true, 'completed' => true, 'restored' => true,
                   'owner_calls' => described_class::CLIENT_CALLS.fetch(row.fetch('name')), 'cleanup_errors' => [])
      end
    end

    it 'initializes every named state as unreached rather than a seeded success' do
      planned = described_class.initial_client_states('vulnerable')
      expect(planned.map { |row| row.values_at('kind', 'name') }).to eq(%w[shell meterpreter].product(%w[default_home custom_path missing empty malformed aliases_empty default_after_custom]))
      expect(planned.all? { |row| row.values_at('entered', 'completed', 'restored') == [false, false, false] }).to be(true)
    end

    it 'accepts every completed state with all 22 original owner calls' do
      expect(records.sum { |row| row.fetch('owner_calls') }).to eq(22)
      expect(described_class.validate_client_states(records, 'vulnerable')).to be(true)
    end

    it 'refuses a missing state even when every reported state passed' do
      records.pop
      expect { described_class.validate_client_states(records, 'vulnerable') }.to raise_error(MinioTarget::Error, /Exact client states/)
    end

    it 'refuses a duplicate state replacing a required state' do
      records[-1] = records.first.dup
      expect { described_class.validate_client_states(records, 'vulnerable') }.to raise_error(MinioTarget::Error, /Exact client states/)
    end

    %w[entered completed restored].each do |flag|
      it "refuses a state whose #{flag} action did not succeed" do
        records.first[flag] = false
        expect { described_class.validate_client_states(records, 'vulnerable') }.to raise_error(MinioTarget::Error, /Exact client states/)
      end
    end

    it 'refuses a missing repeat despite all completion flags' do
      records.first['owner_calls'] = 1
      expect { described_class.validate_client_states(records, 'vulnerable') }.to raise_error(MinioTarget::Error, /Exact client states/)
    end

    it 'refuses an independent cleanup failure despite all completion flags' do
      records.first['cleanup_errors'] = [{ 'operation' => 'client-verify', 'error' => 'Captured failure' }]
      expect { described_class.validate_client_states(records, 'vulnerable') }.to raise_error(MinioTarget::Error, /Exact client states/)
    end

    it 'keeps the fixed profile free of client-state claims' do
      expect(described_class.validate_client_states([], 'fixed')).to be(true)
    end
  end

  context 'when binding session process ownership' do
    def process_contract(name)
      program = <<~'PYTHON'
        import base64, importlib.util, json, sys
        from pathlib import Path
        directory = Path('test/module_targets/minio').resolve()
        sys.path.insert(0, str(directory))
        spec = importlib.util.spec_from_file_location('session_fixture', directory / 'session_fixture.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # Explicit proc_pid_stat(5)-derived fields, not a historical capture.
        fields = ['S', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '987654']
        parsed = module.parse_stat(('4101 (owned ) shell) ' + ' '.join(fields)).encode())
        assert parsed['pid'] == 4101 and parsed['starttime'] == 987654 and parsed['ppid'] == 0
        record = dict(kind='meterpreter', uid=1000, gid=1000, payload='/tmp/owned.elf', sha256='a'*64,
                      shell_exe=dict(path='/usr/bin/dash', sha256='b'*64),
                      pre_exec=dict(pid=4101, starttime=987654, uid=[1000]*4, gid=[1000]*4))
        actual = dict(pid=4101, starttime=987654, uid=[1000]*4, gid=[1000]*4, state='S',
                      exe='/tmp/owned.elf', exe_sha256='a'*64, cmdline_base64=base64.b64encode(b'/tmp/owned.elf\0').decode())
        name = sys.argv[1]
        if name == 'pid_reuse': actual.update(starttime=987655, environment_marker='cannot authorize ownership')
        elif name == 'wrong_uid': actual['uid'] = [0]*4
        elif name == 'wrong_gid': actual['gid'] = [0]*4
        elif name == 'zombie': actual['state'] = 'Z'
        elif name == 'stopped': actual['state'] = 'T'
        elif name == 'wrong_executable': actual['exe'] = '/bin/foreign'
        elif name == 'init_pid': actual['pid'] = 1
        try:
            module.validate_owned(record, actual)
            rejected = False
        except AssertionError:
            rejected = True
        print(json.dumps(dict(rejected=rejected)))
      PYTHON
      output, status = Open3.capture2('python3', '-B', '-c', program, name, chdir: MinioTarget::ROOT)
      expect(status.success?).to be(true), output
      JSON.parse(output)
    end

    it 'accepts matching live identity without an environment marker' do
      expect(process_contract('valid')).to eq('rejected' => false)
    end

    it 'rejects PID reuse despite an environment marker' do
      expect(process_contract('pid_reuse')).to eq('rejected' => true)
    end

    it 'rejects a wrong process owner' do
      expect(process_contract('wrong_uid')).to eq('rejected' => true)
    end

    it 'rejects a wrong process group' do
      expect(process_contract('wrong_gid')).to eq('rejected' => true)
    end

    it 'rejects a zombie state' do
      expect(process_contract('zombie')).to eq('rejected' => true)
    end

    it 'rejects a stopped state' do
      expect(process_contract('stopped')).to eq('rejected' => true)
    end

    it 'rejects an unrelated executable' do
      expect(process_contract('wrong_executable')).to eq('rejected' => true)
    end

    it 'rejects PID1' do
      expect(process_contract('init_pid')).to eq('rejected' => true)
    end
  end
end
