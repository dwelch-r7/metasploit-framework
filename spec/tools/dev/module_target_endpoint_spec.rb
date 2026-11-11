require 'rspec'
require 'json'
require_relative '../../../tools/dev/module_target_endpoint'

RSpec.describe ModuleTargetEndpoint do
  let(:capture) { JSON.parse(File.read(File.expand_path('../../file_fixtures/tools/module_targets/network_selection/topology.json', __dir__))) }
  let(:containers) { capture.fetch('containers') }
  let(:networks) { capture.fetch('networks') }
  let(:name) { 'default' }
  let(:selector) do
    described_class.new(project: capture.fetch('project'), network: name,
                        container: ->(service) { containers.fetch(service) },
                        network_inspection: ->(identifier) { networks.fetch(identifier) })
  end

  it 'selects the captured gateway internal address instead of its public address' do
    expect(selector.address('gateway')).to eq('192.0.2.9')
  end

  it 'selects the isolated Framework address on that same network' do
    expect(selector.address('framework')).to eq('192.0.2.8')
  end

  it 'refuses a selected network that is not internal' do
    networks.fetch('default-network-id')['Internal'] = false

    expect { selector.address('gateway') }.to raise_error(ArgumentError, /must be internal/)
  end

  it 'refuses a foreign selected network project' do
    networks.fetch('default-network-id').fetch('Labels')['com.docker.compose.project'] = 'another-project'

    expect { selector.address('gateway') }.to raise_error(ArgumentError, /ownership differs/)
  end

  it 'refuses a foreign secondary public network project' do
    networks.fetch('public-network-id').fetch('Labels')['com.docker.compose.project'] = 'another-project'

    expect { selector.address('gateway') }.to raise_error(ArgumentError, /ownership differs/)
  end

  it 'refuses a network inspect response bound to another ID' do
    networks.fetch('default-network-id')['Id'] = 'another-network-id'

    expect { selector.address('gateway') }.to raise_error(ArgumentError, /ownership differs/)
  end

  it 'refuses a gateway with a foreign container project' do
    containers.fetch('gateway').fetch('Config').fetch('Labels')['com.docker.compose.project'] = 'another-project'

    expect { selector.address('gateway') }.to raise_error(ArgumentError, %r{container ownership/state differs})
  end

  it 'refuses a Framework inspect response for another service' do
    containers.fetch('framework').fetch('Config').fetch('Labels')['com.docker.compose.service'] = 'gateway'

    expect { selector.address('gateway') }.to raise_error(ArgumentError, %r{container ownership/state differs})
  end

  it 'refuses an endpoint that stopped before selection' do
    containers.fetch('gateway').fetch('State')['Running'] = false

    expect { selector.address('gateway') }.to raise_error(ArgumentError, %r{container ownership/state differs})
  end

  it 'refuses Framework joined to an additional network' do
    containers.fetch('framework').fetch('NetworkSettings').fetch('Networks')['extra'] = { 'NetworkID' => 'public-network-id', 'IPAddress' => '192.0.2.11' }

    expect { selector.address('gateway') }.to raise_error(ArgumentError, /exactly one isolated network/)
  end

  it 'refuses a gateway missing the shared Framework network' do
    containers.fetch('gateway').fetch('NetworkSettings').fetch('Networks').delete('msf-target-capture_default')

    expect { selector.address('gateway') }.to raise_error(ArgumentError, /lacks the selected/)
  end

  it 'refuses duplicate membership IDs behind different names' do
    entries = containers.fetch('gateway').fetch('NetworkSettings').fetch('Networks')
    entries['alias'] = entries.fetch('msf-target-capture_default').dup

    expect { selector.address('gateway') }.to raise_error(ArgumentError, /memberships are ambiguous/)
  end

  it 'refuses two network IDs claiming the same logical name' do
    networks.fetch('public-network-id').fetch('Labels')['com.docker.compose.network'] = 'default'

    expect { selector.address('gateway') }.to raise_error(ArgumentError, /names are ambiguous/)
  end

  ['', 'not-an-ip', '0.0.0.0', '127.0.0.1', '2001:db8::1', '192.0.2.9/24'].each do |address|
    it "refuses invalid IPv4 endpoint data #{address.inspect}" do
      containers.fetch('gateway').fetch('NetworkSettings').fetch('Networks').fetch('msf-target-capture_default')['IPAddress'] = address

      expect { selector.address('gateway') }.to raise_error(ArgumentError, /valid IPv4/)
    end
  end

  [nil, '', '../default', 'default network'].each do |network|
    it "refuses an invalid logical selector #{network.inspect}" do
      expect { described_class.validate_network_name(network) }.to raise_error(ArgumentError, /logical Compose/)
    end
  end

  it 'refuses an absent expected project rather than accepting unlabeled resources' do
    expect { described_class.new(project: nil, network: name, container: ->(_service) {}, network_inspection: ->(_identifier) {}) }.to raise_error(ArgumentError, /explicit Compose project/)
  end
end
