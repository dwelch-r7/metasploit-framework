require 'rspec'
require 'tmpdir'
require_relative '../../../test/module_targets/minio/build_sources'
require_relative '../../../test/module_targets/minio/assemble_images'
require_relative '../../../test/module_targets/minio/native_gate'

RSpec.describe 'MinIO source and runtime contracts without Docker' do
  let(:assets) { MinioTarget.assets }
  let(:fixtures) { File.expand_path('../../file_fixtures/tools/module_targets/minio', __dir__) }
  let(:validator) { MinioTarget::VerifiedBuild.new(@directory) }
  let(:runtime_dockerfile) { File.read(File.join(MinioTarget::DIRECTORY, 'Dockerfile')) }

  around do |example|
    Dir.mktmpdir('minio-contract') do |directory|
      @directory = directory
      example.run
    end
  end

  %w[client vulnerable fixed].each do |profile|
    it "accepts the actual #{profile} go-build-info capture" do
      text = File.read(File.join(fixtures, profile, 'go-build-info.txt'))
      expect(validator.validate_build_info(profile, text)).to be(true)
    end
  end

  it 'rejects a dirty-source version of the actual client capture' do
    text = File.read(File.join(fixtures, 'client/go-build-info.txt')).sub('vcs.modified=false', 'vcs.modified=true')
    expect { validator.validate_build_info('client', text) }.to raise_error(MinioTarget::Error, /clean toolchain/)
  end

  it 'rejects a different revision in the actual vulnerable capture' do
    text = File.read(File.join(fixtures, 'vulnerable/go-build-info.txt')).sub(assets['sources']['vulnerable']['commit'], 'f' * 40)
    expect { validator.validate_build_info('vulnerable', text) }.to raise_error(MinioTarget::Error)
  end

  it 'rejects ARM metadata instead of silently treating it as native amd64' do
    text = File.read(File.join(fixtures, 'fixed/go-build-info.txt')).sub('GOARCH=amd64', 'GOARCH=arm64')
    expect { validator.validate_build_info('fixed', text) }.to raise_error(MinioTarget::Error)
  end

  it 'rejects an ambiguous duplicated clean/dirty VCS setting' do
    text = File.read(File.join(fixtures, 'client/go-build-info.txt')) + "\tbuild\tvcs.modified=true\n"
    expect { validator.validate_build_info('client', text) }.to raise_error(MinioTarget::Error)
  end

  it 'rejects a different compiler version in the actual capture' do
    text = File.read(File.join(fixtures, 'client/go-build-info.txt')).sub('go1.19.13', 'go1.19.12')
    expect { validator.validate_build_info('client', text) }.to raise_error(MinioTarget::Error)
  end

  it 'refuses partial source-build receipts before looking for a binary' do
    File.write(File.join(@directory, 'result.json'), JSON.generate(status: 'setup_failed', cleanup: 'passed', capture_errors: []))
    expect { validator.verify }.to raise_error(MinioTarget::Error, /completed source build/)
  end

  it 'refuses symlinked receipt data' do
    File.write(File.join(@directory, 'outside.json'), '{}')
    File.symlink(File.join(@directory, 'outside.json'), File.join(@directory, 'result.json'))
    expect { validator.verify }.to raise_error(MinioTarget::Error, /regular build artifact/)
  end

  it 'accepts the actual no-RUN one-stage runtime recipe' do
    expect(MinioTarget::RuntimeAssembly.validate_dockerfile(runtime_dockerfile)).to be(true)
  end

  it 'refuses a hidden compiler RUN stage' do
    expect { MinioTarget::RuntimeAssembly.validate_dockerfile(runtime_dockerfile + "RUN go build .\n") }.to raise_error(MinioTarget::Error)
  end

  it 'refuses a remote Dockerfile frontend' do
    expect { MinioTarget::RuntimeAssembly.validate_dockerfile("# syntax=docker/dockerfile:1\n" + runtime_dockerfile) }.to raise_error(MinioTarget::Error)
  end

  it 'refuses an external COPY stage' do
    expect { MinioTarget::RuntimeAssembly.validate_dockerfile(runtime_dockerfile + "COPY --from=remote /binary /binary\n") }.to raise_error(MinioTarget::Error)
  end

  it 'includes client provenance in the local server image identity' do
    before = MinioTarget.image_name('vulnerable')
    altered = JSON.parse(JSON.generate(assets))
    altered['sources']['client']['reference']['binary_sha256'] = 'f' * 64
    allow(MinioTarget).to receive(:assets).and_return(altered)
    expect(MinioTarget.image_name('vulnerable')).not_to eq(before)
  end

  it 'runs independent teardown and releases the lock when capture fails' do
    operation = MinioTarget::Operation.new('contract', 1)
    lock = double(close: nil)
    runner = operation.instance_variable_get(:@runner)
    allow(runner).to receive(:acquire_lock).and_return(lock)
    allow(operation).to receive(:empty_inventory!)
    allow(operation).to receive(:capture_before_down).and_raise(IOError, 'Captured diagnostic failure')
    allow(operation).to receive(:cleanup) { operation.result['cleanup'] = 'passed' }
    operation.instance_variable_set(:@directory, @directory)
    expect(operation.perform { operation.result['status'] = 'passed' }).to be(false)
    expect(operation).to have_received(:cleanup)
    expect(lock).to have_received(:close)
    expect(operation.result['status']).to eq('capture_failed')
  end

  it 'accepts the built-in driver and selects the header name rather than a node name' do
    text = "Name: desktop-linux\nDriver: docker\n\nNodes:\nName: worker0\n"
    expect(MinioTarget::RuntimeAssembly.docker_builder(text)).to eq('name' => 'desktop-linux', 'driver' => 'docker')
  end

  %w[docker-container kubernetes remote].each do |driver|
    it "refuses a selected #{driver} driver before building" do
      expect { MinioTarget::RuntimeAssembly.docker_builder("Name: selected\nDriver: #{driver}\nNodes:\n") }.to raise_error(MinioTarget::Error, /built-in docker/)
    end
  end

  it 'refuses an unknown or ambiguous driver descriptor' do
    expect { MinioTarget::RuntimeAssembly.docker_builder("Name: selected\nDriver: docker\nDriver: remote\n") }.to raise_error(MinioTarget::Error)
  end

  it 'inspects without bootstrapping or changing builder configuration' do
    operation = MinioTarget::RuntimeAssembly.allocate
    operation.instance_variable_set(:@result, {})
    operation.instance_variable_set(:@assets, assets)
    allow(operation).to receive(:required).with(%w[docker buildx inspect default], 'builder-inspect').and_return("Name: default\nDriver: docker\nNodes:\nEndpoint: default\n")
    allow(operation).to receive(:required).with(['docker', 'info', '--format', '{{.ID}}'], 'current-engine-id').and_return("derived-same-engine\n")
    allow(operation).to receive(:required).with(['docker', '--context', 'default', 'info', '--format', '{{.ID}}'], 'builder-engine-id').and_return("derived-same-engine\n")
    expect(operation.send(:preflight_builder)).to include('name' => 'default', 'driver' => 'docker', 'endpoint' => 'default', 'builder_engine_id' => 'derived-same-engine')
  end

  it 'refuses an inspection that returns a different builder than explicit default' do
    operation = MinioTarget::RuntimeAssembly.allocate
    operation.instance_variable_set(:@assets, assets)
    allow(operation).to receive(:required).with(%w[docker buildx inspect default], 'builder-inspect').and_return("Name: other\nDriver: docker\nNodes:\nEndpoint: default\n")
    expect { operation.send(:preflight_builder) }.to raise_error(MinioTarget::Error, /identity differs/)
  end

  it 'refuses a built-in endpoint connected to a different engine' do
    operation = MinioTarget::RuntimeAssembly.allocate
    operation.instance_variable_set(:@assets, assets)
    allow(operation).to receive(:required).with(%w[docker buildx inspect default], 'builder-inspect').and_return("Name: default\nDriver: docker\nNodes:\nEndpoint: default\n")
    allow(operation).to receive(:required).with(['docker', 'info', '--format', '{{.ID}}'], 'current-engine-id').and_return("derived-current\n")
    allow(operation).to receive(:required).with(['docker', '--context', 'default', 'info', '--format', '{{.ID}}'], 'builder-engine-id').and_return("derived-other\n")
    expect { operation.send(:preflight_builder) }.to raise_error(MinioTarget::Error, /not the current Docker engine/)
  end

  it 'refuses an ambiguous or non-context builder endpoint' do
    expect { MinioTarget::RuntimeAssembly.builder_endpoint("Nodes:\nEndpoint: default\nEndpoint: other\n") }.to raise_error(MinioTarget::Error)
    expect { MinioTarget::RuntimeAssembly.builder_endpoint("Nodes:\nEndpoint: ssh://unverified\n") }.to raise_error(MinioTarget::Error)
  end

  # These are derived filesystem/verification boundaries, not binary or native
  # build proofs. The real sealed build is separately imported without execution.
  def conservation_operation
    contexts = %w[vulnerable fixed].to_h do |profile|
      directory = File.join(@directory, profile)
      FileUtils.mkdir_p(directory)
      files = %w[mc minio Dockerfile provenance.json].to_h do |name|
        file = File.join(directory, name)
        File.write(file, "Derived conservation fixture #{profile}/#{name}\n")
        [name, Digest::SHA256.file(file).hexdigest]
      end
      [profile, { 'directory' => directory, 'files' => files }]
    end
    receipt = { 'contexts' => contexts }
    path = File.join(@directory, 'import.json')
    File.write(path, JSON.generate(receipt))
    allow(MinioTarget::RuntimeAssembly).to receive(:verify_import).with(path).and_return(receipt)
    state = MinioTarget::RuntimeAssembly.import_state(path)
    operation = MinioTarget::RuntimeAssembly.allocate
    operation.instance_variable_set(:@directory, @directory)
    operation.instance_variable_set(:@import_path, path)
    operation.instance_variable_set(:@initial_import_state, state)
    operation.instance_variable_set(:@result, { 'external_conservation' => [] })
    [operation, path, receipt]
  end

  # Derived command-emission checks never invoke Docker. The context requirement
  # comes from the preserved real build refusal, not a simulated successful build.
  def assembly_commands
    operation, _path, receipt = conservation_operation
    operation.instance_variable_set(:@assets, assets)
    operation.instance_variable_set(:@seconds, assets.fetch('assembly').fetch('seconds'))
    operation.instance_variable_set(:@import, receipt)
    allow(operation).to receive(:assert_import_conservation).and_return(true)
    allow(operation).to receive(:preflight_builder).and_return('name' => 'default', 'endpoint' => 'derived-context')
    allow(operation).to receive(:empty_inventory!)
    allow(operation).to receive(:perform) do |&block|
      block.call
      true
    end
    calls = []
    runtime = assets.fetch('images').fetch('runtime')
    allow(operation).to receive(:required) do |argv, name, **_options|
      calls << argv
      if name == 'runtime-image'
        JSON.generate([{ 'Id' => runtime.fetch('config_digest'), 'RootFS' => { 'Layers' => runtime.fetch('rootfs') }, 'Architecture' => 'amd64', 'Os' => 'linux' }])
      elsif name.start_with?('image-')
        profile = name.delete_prefix('image-')
        server = assets.fetch('sources').fetch(profile)
        labels = {
          'org.opencontainers.image.source' => server.fetch('repository'), 'org.opencontainers.image.revision' => server.fetch('commit'),
          'module-target.minio.server-sha256' => server.fetch('reference').fetch('binary_sha256'),
          'module-target.minio.mc-sha256' => assets.fetch('sources').fetch('client').fetch('reference').fetch('binary_sha256')
        }
        JSON.generate([{ 'Id' => "derived-#{profile}", 'RootFS' => { 'Layers' => runtime.fetch('rootfs') }, 'Config' => { 'Labels' => labels } }])
      else
        ''
      end
    end
    expect(operation.run).to be(true)
    [calls, receipt]
  end

  it 'pins both builds to the same inspected context and builder' do
    calls, receipt = assembly_commands
    builds = calls.select { |argv| argv.include?('build') }
    expect(builds.length).to eq(2)
    expect(builds.map { |argv| argv.take(7) }).to eq([%w[docker --context derived-context buildx build --builder default]] * 2)
    expect(builds.map(&:last)).to eq(receipt.fetch('contexts').values.map { |context| context.fetch('directory') })
  end

  it 'retains pull and image inspection on the engine already verified against the endpoint' do
    calls, = assembly_commands
    image = assets.fetch('images').fetch('runtime').fetch('reference')
    expect(calls).to include(['docker', 'pull', '--platform', assets.fetch('platform'), image])
    expect(calls.select { |argv| argv.include?('inspect') }.map { |argv| argv.take(3) }).to eq([%w[docker image inspect]] * 3)
  end

  it 'conserves all source and nine external context/receipt inputs' do
    operation, = conservation_operation
    state = operation.instance_variable_get(:@initial_import_state)
    expect(state['inputs_sha256'].length).to eq(MinioTarget.inputs.length + 9)
    expect(operation.send(:assert_import_conservation, 'derived-unit')).to be(true)
  end

  it 'rejects a byte-changed receipt even when its parsed verified value is unchanged' do
    operation, path, = conservation_operation
    File.open(path, 'a') { |file| file.write("\n") }
    expect { operation.send(:assert_import_conservation, 'receipt-bytes') }.to raise_error(MinioTarget::Error, /inputs changed/)
    expect(operation.result['external_inputs_current']).to be(false)
  end

  it 'rejects a changed context file before building' do
    operation, _path, receipt = conservation_operation
    File.write(File.join(receipt['contexts']['fixed']['directory'], 'mc'), 'Changed derived fixture')
    expect { operation.send(:assert_import_conservation, 'context-bytes') }.to raise_error(MinioTarget::Error, /Context changed/)
  end

  it 'compares the verified return with the initial import rather than ignoring it' do
    operation, path, receipt = conservation_operation
    replacement = JSON.parse(JSON.generate(receipt)).merge('different_verified_return' => true)
    allow(MinioTarget::RuntimeAssembly).to receive(:verify_import).with(path).and_return(replacement)
    expect { operation.send(:assert_import_conservation, 'verified-return') }.to raise_error(MinioTarget::Error, /inputs changed/)
  end

  it 'does not write a final assembly receipt when post-capture conservation fails' do
    operation, = conservation_operation
    allow(operation).to receive(:perform).and_return(true)
    allow(operation).to receive(:assert_import_conservation).with('after-capture-and-cleanup').and_raise(MinioTarget::Error, 'Changed after capture')
    expect(operation.run).to be(false)
    expect(File.exist?(File.join(@directory, 'assembly.json'))).to be(false)
    expect(operation.result).not_to have_key('import_sha256')
  end

  it 'uses an internal native network with the same two nodes and four drives' do
    definition = YAML.safe_load_file(File.join(MinioTarget::DIRECTORY, 'base.compose.yaml'), aliases: true)
    expect(definition.fetch('networks').fetch('default').fetch('internal')).to be(true)
    expect(definition.fetch('services').keys.sort).to eq(%w[gateway node1 node2])
    expect(definition.fetch('volumes').length).to eq(4)
  end

  def native_python_contract(body)
    source = File.join(MinioTarget::DIRECTORY, 'native.py')
    script = <<~PYTHON
      import importlib.util, json
      spec = importlib.util.spec_from_file_location('minio_native_contract', #{source.inspect})
      module = importlib.util.module_from_spec(spec)
      spec.loader.exec_module(module)
      native = module.Native.__new__(module.Native)
      native.settings = dict(services=['node1', 'node2'], api_port=9000, root_user='derived-user', root_password='derived-secret')
      native.config = '/tmp/module-target-minio-' + 'a' * 32
      native.proof = native.config + '-proof'
      native.config_owned = set()
      native.bucket_attempted = False
      native.facts = {}
      calls = []
      #{body}
    PYTHON
    output, error, status = Open3.capture3('python3', '-B', '-c', script)
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  it 'guards and clears both native configs before either S3 alias initialization' do
    result = native_python_contract(<<~PYTHON)
      aliases = {'node1': {'derived-sample': {}}, 'node2': {'derived-sample': {}}}
      def command(service, *args, **kwargs):
          calls.append([service, *args])
          return (json.dumps({'aliases': aliases[service]}).encode(), 0) if args[0] == 'cat' else (b'', 0)
      def mc(*args, service='node1', **kwargs):
          calls.append([service, 'mc', *args])
          if args[:2] == ('alias', 'rm'):
              del aliases[service][args[2]]
          return b'', 0
      native.command, native.mc = command, mc
      native.initialize_client()
      print(json.dumps(dict(calls=calls, owned=sorted(native.config_owned), guards=native.facts['fresh_owned_config_guards'])))
    PYTHON
    expect(result['owned']).to eq(%w[node1 node2])
    expect(result['guards'].keys.sort).to eq(%w[node1 node2])
    first_set = result['calls'].index { |call| call[1, 3] == %w[mc alias set] }
    expect(result['calls'].take(first_set).count { |call| call[1] == 'cat' }).to eq(4)
    expect(result['calls'].take(first_set).count { |call| call[1, 3] == %w[mc alias rm] }).to eq(2)
  end

  it 'attempts both node cleanups and refuses restored when one config removal fails' do
    result = native_python_contract(<<~PYTHON)
      native.config_owned = {'node1', 'node2'}
      native.snapshot = lambda: {'derived_logical_state': True}
      def command(service, *args, **kwargs):
          calls.append([service, *args])
          if service == 'node1' and args[:2] == ('rm', '-rf'):
              raise OSError('Derived observer/removal failure')
          return b'', 0
      native.command = command
      native.cleanup({'derived_logical_state': True})
      print(json.dumps(dict(calls=calls, facts=native.facts)))
    PYTHON
    expect(result['calls']).to include(['node2', 'rm', '-rf', '--', '/tmp/module-target-minio-' + 'a' * 32])
    expect(result['facts']['cleanup_absence'].keys.sort).to eq(%w[node1 node2])
    expect(result['facts']['restored']).to be(false)
    expect(result['facts']['cleanup_errors'].first['operation']).to eq('node1-remove-config')
  end

  it 'refuses restored when node2 config absence is not proven' do
    result = native_python_contract(<<~PYTHON)
      native.config_owned = {'node1', 'node2'}
      native.snapshot = lambda: {'derived_logical_state': True}
      def command(service, *args, **kwargs):
          calls.append([service, *args])
          if service == 'node2' and args[0] == 'sh' and args[-1] == native.config:
              raise AssertionError('Derived remaining config')
          return b'', 0
      native.command = command
      native.cleanup({'derived_logical_state': True})
      print(json.dumps(dict(calls=calls, facts=native.facts)))
    PYTHON
    expect(result['facts']['cleanup_absence']['node2']).not_to have_key('config')
    expect(result['facts']['restored']).to be(false)
    expect(result['facts']['cleanup_errors'].first['operation']).to eq('node2-config-absence')
  end
end

RSpec.describe 'MinIO native health setup and capture without Docker' do
  let(:assets) { MinioTarget.assets }

  # Derived YAML/environment and command-emission contracts never invoke Docker
  # or execute mc. Alias semantics come from the pinned client's source.
  it 'provides both healthchecks a credential-free loopback environment alias' do
    operation = MinioTarget::NativeGate.allocate
    operation.instance_variable_set(:@assets, assets)
    operation.instance_variable_set(:@image, 'name' => 'derived-runtime-image')
    operation.instance_variable_set(:@directory, '/derived-native-health-contract')
    environment = operation.send(:compose_environment)
    definition = YAML.safe_load_file(File.join(MinioTarget::DIRECTORY, 'base.compose.yaml'), aliases: true)
    aliases = definition.fetch('services').values_at(*assets.fetch('native').fetch('services')).map do |service|
      service.fetch('environment').find { |entry| entry.start_with?('MC_HOST_readiness=') }
    end
    expect(aliases).to eq(['MC_HOST_readiness=${MINIO_HEALTH_URL:?}'] * 2)
    expect(environment.fetch('MINIO_HEALTH_URL')).to eq('http://127.0.0.1:9000')
  end

  it 'uses direct anonymous ready argv with a separate health config' do
    definition = YAML.safe_load_file(File.join(MinioTarget::DIRECTORY, 'base.compose.yaml'), aliases: true)
    commands = definition.fetch('services').values_at(*assets.fetch('native').fetch('services')).map { |service| service.fetch('healthcheck').fetch('test') }
    expect(commands).to eq([['CMD', '/usr/local/bin/mc', '--config-dir', '/tmp/module-target-health', 'ready', 'readiness']] * 2)
  end

  def native_capture_operation
    operation = MinioTarget::NativeGate.allocate
    operation.instance_variable_set(:@assets, assets)
    operation.instance_variable_set(:@owned, 'containers' => %w[derived-node1 derived-node2], 'networks' => [])
    operation.instance_variable_set(:@result, 'status' => 'setup_failed', 'capture_errors' => [])
    allow(operation).to receive(:collect_owned)
    allow(operation).to receive(:required).and_return('')
    %w[node1 node2 gateway].each do |service|
      identity = JSON.generate([{ 'Config' => { 'Labels' => { 'com.docker.compose.service' => service } } }])
      allow(operation).to receive(:required).with(['docker', 'inspect', "derived-#{service}"], "drive-container-identity-derived-#{service}", bounded: false).and_return(identity)
    end
    operation
  end

  it 'captures the actual user and both drive paths on both nodes after readiness failure' do
    operation = native_capture_operation
    calls = []
    allow(operation).to receive(:required) do |argv, name, **options|
      calls << [argv, name, options]
      name.start_with?('drive-container-identity-') ? JSON.generate([{ 'Config' => { 'Labels' => { 'com.docker.compose.service' => argv.last.delete_prefix('derived-') } } }]) : ''
    end
    operation.send(:capture_before_down)
    captures = calls.select { |_argv, name, _options| name.start_with?('final-drive-state-') }
    expected = %w[derived-node1 derived-node2].map do |identifier|
      [
        ['docker', 'exec', identifier, 'sh', '-c', 'set -eu; id; stat -c "%u:%g %a %n" -- "$@"', 'minio-drive-state', '/data1', '/data2'],
        "final-drive-state-#{identifier}", { bounded: false }
      ]
    end
    expect(captures).to eq(expected)
  end

  it 'continues drive-state capture on the second node after the first fails' do
    operation = native_capture_operation
    allow(operation).to receive(:required).with(anything, 'final-drive-state-derived-node1', bounded: false).and_raise(MinioTarget::Error, 'Derived unavailable exec')
    operation.send(:capture_before_down)
    expect(operation).to have_received(:required).with(anything, 'final-drive-state-derived-node2', bounded: false)
    expect(operation.result.fetch('capture_errors')).to eq([{ 'operation' => 'drive-state-derived-node1', 'error' => 'MinioTarget::Error: Derived unavailable exec' }])
  end

  it 'attempts drive-state capture even when the earlier inventory capture raises' do
    operation = native_capture_operation
    allow(operation).to receive(:collect_owned).and_raise(IOError, 'Derived inventory failure')
    expect { operation.send(:capture_before_down) }.to raise_error(IOError, 'Derived inventory failure')
    expect(operation).to have_received(:required).with(anything, 'final-drive-state-derived-node1', bounded: false)
    expect(operation).to have_received(:required).with(anything, 'final-drive-state-derived-node2', bounded: false)
  end

  it 'captures both networks while keeping gateway diagnostics out of server drive assertions' do
    operation = native_capture_operation
    operation.instance_variable_set(:@owned, 'containers' => %w[derived-node1 derived-node2 derived-gateway], 'networks' => %w[derived-backend derived-public])
    operation.send(:capture_before_down)
    expect(operation).not_to have_received(:required).with(anything, 'final-drive-state-derived-gateway', bounded: false)
    expect(operation).to have_received(:required).with(%w[docker network inspect derived-backend], 'final-network-state-derived-backend', bounded: false)
    expect(operation).to have_received(:required).with(%w[docker network inspect derived-public], 'final-network-state-derived-public', bounded: false)
  end
end

RSpec.describe 'MinIO isolated gateway proposal without Docker' do
  let(:assets) { MinioTarget.assets }
  let(:definition) { YAML.safe_load_file(File.join(MinioTarget::DIRECTORY, 'base.compose.yaml'), aliases: true) }

  def derived_resolved_compose
    native = assets.fetch('native')
    gateway = native.fetch('gateway')
    services = (native.fetch('services') + [gateway.fetch('service')]).to_h do |name|
      frontend = name == gateway.fetch('service')
      limits = frontend ? gateway : native
      service = {
        'image' => frontend ? gateway.fetch('image') : 'derived-minio',
        'pull_policy' => 'never', 'mem_limit' => limits.fetch('memory_bytes'), 'memswap_limit' => limits.fetch('memory_bytes'),
        'cpus' => limits.fetch('nano_cpus') / 1e9, 'pids_limit' => limits.fetch('pids'), 'user' => '1000:1000',
        'cap_drop' => ['ALL'], 'security_opt' => ['no-new-privileges:true'],
        'networks' => (frontend ? %w[default public] : ['default']).to_h { |network| [network, {}] }
      }
      service['ports'] = gateway.fetch('ports').values.map { |port| { 'target' => port, 'host_ip' => '127.0.0.1', 'protocol' => 'tcp' } } if frontend
      [name, service]
    end
    { 'services' => services, 'networks' => { 'default' => { 'internal' => true }, 'public' => {} } }
  end

  def validate_gateway_definition(definition)
    operation = MinioTarget::NativeGate.allocate
    operation.instance_variable_set(:@assets, assets)
    operation.instance_variable_set(:@image, 'name' => 'derived-minio')
    operation.send(:validate_compose, definition)
  end

  it 'accepts the separately capped derived gateway and unchanged capped servers' do
    expect { validate_gateway_definition(derived_resolved_compose) }.not_to raise_error
  end

  it 'refuses a public network on either MinIO server' do
    definition = derived_resolved_compose
    definition['services']['node2']['networks']['public'] = {}
    expect { validate_gateway_definition(definition) }.to raise_error(MinioTarget::Error, /isolated behind/)
  end

  it 'refuses an API listener widened beyond loopback' do
    definition = derived_resolved_compose
    definition['services']['gateway']['ports'][0]['host_ip'] = '0.0.0.0'
    expect { validate_gateway_definition(definition) }.to raise_error(MinioTarget::Error, /loopback API listeners/)
  end

  it 'keeps both MinIO nodes internal while publishing only the separate gateway' do
    nodes = definition.fetch('services').values_at('node1', 'node2')
    expect(nodes.map { |node| node.fetch('networks') }).to eq([['default'], ['default']])
    expect(nodes).to all(satisfy { |node| !node.key?('ports') })
    gateway = definition.fetch('services').fetch('gateway')
    expect(gateway.fetch('networks')).to eq(%w[default public])
    expect(gateway.fetch('ports')).to eq(['127.0.0.1::${MINIO_GATEWAY_NODE1_PORT:?}', '127.0.0.1::${MINIO_GATEWAY_NODE2_PORT:?}'])
    expect(gateway.fetch('read_only')).to be(true)
  end

  it 'renders distinct unchanged-path routes to both genuine MinIO endpoints' do
    template = File.read(File.join(MinioTarget::DIRECTORY, 'gateway.conf.erb'))
    rendered = ERB.new(template, trim_mode: '-').result_with_hash(native: assets.fetch('native'))
    expect(rendered.scan(/^Listen (\d+)$/).flatten).to eq(%w[19001 19002])
    expect(rendered.scan(%r{^  ProxyPass / (\S+)}).flatten).to eq(['http://node1:9000/', 'http://node2:9000/'])
    expect(rendered).to include('ProxyRequests Off', 'ProxyPreserveHost On')
  end
end

RSpec.describe 'MinIO captured admin state parsing without Docker' do
  def captured_admin_state(mutation = '')
    source = File.join(MinioTarget::DIRECTORY, 'native.py')
    fixture = File.expand_path('../../file_fixtures/tools/module_targets/minio/admin-info.json', __dir__)
    script = <<~PYTHON
      import importlib.util, json
      from pathlib import Path
      spec = importlib.util.spec_from_file_location('minio_admin_contract', #{source.inspect})
      module = importlib.util.module_from_spec(spec)
      spec.loader.exec_module(module)
      native = module.Native.__new__(module.Native)
      native.assets = json.loads(Path(#{File.join(MinioTarget::DIRECTORY, 'assets.json').inspect}).read_text())
      native.settings = native.assets['native']
      native.runtime = {'profile': 'vulnerable'}
      raw = Path(#{fixture.inspect}).read_bytes()
      document = json.loads(raw)
      #{mutation}
      if #{(!mutation.empty?).to_s.capitalize}:
          raw = json.dumps(document).encode()
      calls = []
      def mc(*args, **kwargs):
          assert args == ('admin', 'info', 'lab') and kwargs['service'] == 'node1'
          calls.append(list(args))
          return raw, 0
      class BeforeHTTP(Exception):
          pass
      def stop_before_http(*args, **kwargs):
          raise BeforeHTTP()
      native.mc, native.request = mc, stop_before_http
      try:
          native.snapshot()
          raise RuntimeError('Expected the network boundary to stop this parser-only contract')
      except BeforeHTTP:
          outcome = 'parsed_before_http'
      except AssertionError:
          outcome = 'rejected'
      print(json.dumps(dict(outcome=outcome, admin_reads=len(calls))))
    PYTHON
    output, error, status = Open3.capture3('python3', '-B', '-c', script)
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  # The real successful CLI stdout is replayed only through field validation.
  # A sentinel stops before HTTP, formats or S3; this is not a native snapshot.
  it 'accepts the captured online servers and ok drives up to the HTTP boundary' do
    expect(captured_admin_state).to eq('outcome' => 'parsed_before_http', 'admin_reads' => 1)
  end

  it 'rejects drive-state ok when incorrectly supplied as the server state' do
    result = captured_admin_state("for server in document['info']['servers']: server['state'] = 'ok'")
    expect(result.fetch('outcome')).to eq('rejected')
  end

  it 'rejects an offline server in the actual captured response' do
    result = captured_admin_state("document['info']['servers'][0]['state'] = 'offline'")
    expect(result.fetch('outcome')).to eq('rejected')
  end

  it 'retains the rejection of a non-ok drive in the actual captured response' do
    result = captured_admin_state("document['info']['servers'][0]['drives'][0]['state'] = 'offline'")
    expect(result.fetch('outcome')).to eq('rejected')
  end
end

RSpec.describe 'MinIO owned bucket cleanup without Docker' do
  def owned_bucket_cleanup(keys: [], fail_key: nil, listing_error: false, bucket_present: true, repeat: false)
    source = File.join(MinioTarget::DIRECTORY, 'native.py')
    fixture = File.expand_path('../../file_fixtures/tools/module_targets/minio/missing-proof-rm.json', __dir__)
    settings = JSON.generate(keys: keys, fail_key: fail_key, listing_error: listing_error, bucket_present: bucket_present, repeat: repeat)
    script = <<~PYTHON
      import importlib.util, json
      from pathlib import Path
      spec = importlib.util.spec_from_file_location('minio_bucket_contract', #{source.inspect})
      module = importlib.util.module_from_spec(spec)
      spec.loader.exec_module(module)
      settings = json.loads(#{settings.inspect})
      missing = json.loads(Path(#{fixture.inspect}).read_text())
      native = module.Native.__new__(module.Native)
      native.settings = {'services': ['node1', 'node2']}
      native.config = '/tmp/module-target-minio-' + 'a' * 32
      native.proof = native.config + '-proof'
      native.bucket = 'module-target-' + 'b' * 32
      native.config_owned = {'node1', 'node2'}
      native.bucket_attempted = True
      native.facts = {}
      state = {'bucket': settings['bucket_present'], 'keys': set(settings['keys'])}
      calls = []
      native.bucket_names = lambda: [native.bucket] if state['bucket'] else []
      native.snapshot = lambda: {'owned_bucket_present': state['bucket']}
      def command(service, *args, **kwargs):
          calls.append(['local', service, *args])
          return b'', 0
      def mc(*args, **kwargs):
          calls.append(['mc', *args])
          if args[0] == 'ls':
              assert args == ('ls', 'lab/' + native.bucket + '/')
              if settings['listing_error']:
                  raise OSError('Derived listing denied')
              rows = [dict(status='success', type='file', key=key) for key in sorted(state['keys'])]
              return ''.join(json.dumps(row) + '\\n' for row in rows).encode(), 0
          if args[0] == 'rm':
              key = args[-1].rsplit('/', 1)[-1]
              if key == settings['fail_key']:
                  raise OSError('Derived object removal denied')
              if key not in state['keys']:
                  raise AssertionError(missing)
              state['keys'].remove(key)
          if args[0] == 'rb':
              assert args == ('rb', 'lab/' + native.bucket)
              if state['keys']:
                  raise AssertionError('Derived nonempty bucket refuses non-force removal')
              state['bucket'] = False
          return b'', 0
      native.command, native.mc = command, mc
      errors = native.cleanup({'owned_bucket_present': False})
      first_errors = list(errors)
      if settings['repeat']:
          errors = native.cleanup({'owned_bucket_present': False})
      print(json.dumps(dict(calls=calls, first_errors=first_errors, errors=errors,
                           facts=native.facts, remaining=sorted(state['keys']), bucket=native.bucket)))
    PYTHON
    output, error, status = Open3.capture3('python3', '-B', '-c', script)
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  # Missing-object error bytes are genuine. Listing rows and logical state are
  # explicit unit data derived from the pinned producer, not real S3 success.
  it 'removes an already empty owned bucket and permits cleanup a second time' do
    result = owned_bucket_cleanup(repeat: true)
    calls = result['calls'].select { |call| call.first == 'mc' }.map { |call| call.drop(1) }
    expect(calls).to eq([['ls', "lab/#{result['bucket']}/"], ['rb', "lab/#{result['bucket']}"]])
    expect(result['first_errors']).to eq([])
    expect(result['facts']['restored']).to be(true)
  end

  it 'skips an absent first proof while deleting the present second proof and bucket' do
    result = owned_bucket_cleanup(keys: ['proof-1.txt'])
    removes = result['calls'].select { |call| call[0, 2] == %w[mc rm] }
    expect(removes).to eq([['mc', 'rm', '--force', "lab/#{result['bucket']}/proof-1.txt"]])
    expect(result['facts']['restored']).to be(true)
  end

  it 'attempts the other owned key and bucket after a listed object deletion fails' do
    result = owned_bucket_cleanup(keys: %w[proof-0.txt proof-1.txt], fail_key: 'proof-0.txt')
    expect(result['calls']).to include(['mc', 'rm', '--force', "lab/#{result['bucket']}/proof-1.txt"], ['mc', 'rb', "lab/#{result['bucket']}"])
    expect(result['errors'].map { |error| error['operation'] }).to include('owned-s3-object-0')
    expect(result['facts']['restored']).to be(false)
  end

  it 'leaves foreign keys untouched and refuses restored when the bucket is not empty' do
    result = owned_bucket_cleanup(keys: ['proof-0.txt', 'foreign.txt'])
    expect(result['calls']).not_to include(['mc', 'rm', '--force', "lab/#{result['bucket']}/foreign.txt"])
    expect(result['calls']).to include(['mc', 'rb', "lab/#{result['bucket']}"])
    expect(result['remaining']).to eq(['foreign.txt'])
    expect(result['facts']['restored']).to be(false)
  end

  it 'retains a listing error and continues both nodes absence checks' do
    result = owned_bucket_cleanup(listing_error: true)
    expect(result['errors'].first).to include('operation' => 'owned-s3-bucket', 'message' => 'Derived listing denied')
    expect(result['facts']['cleanup_absence'].keys.sort).to eq(%w[node1 node2])
    expect(result['facts']['restored']).to be(false)
  end

  it 'does not issue any S3 removal when the owned bucket is already absent' do
    result = owned_bucket_cleanup(bucket_present: false)
    expect(result['calls'].select { |call| call.first == 'mc' }).to eq([])
    expect(result['facts']['restored']).to be(true)
  end
end
