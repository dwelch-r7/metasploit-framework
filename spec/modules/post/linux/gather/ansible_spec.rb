require 'rspec'
require 'json'

RSpec.describe 'Ansible controller collection' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'post', reference_name: 'linux/gather/ansible') }

  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'exploit/ansible/native.json'))) }
  let(:config_path) { '/etc/ansible/ansible.cfg' }
  let(:config) { captures.fetch('configs').fetch(config_path) }
  let(:key_path) { '/etc/ansible/id_ed25519' }
  let(:key_bytes) { 'Arbitrary collected file bytes' }
  let(:stored) { [] }

  before do
    allow(mod).to receive(:session).and_return(nil)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_warning)
    allow(mod).to receive(:elog)
    allow(mod).to receive(:ansible_cfg).and_return(config_path)
    allow(mod).to receive(:file?).and_return(true)
    allow(mod).to receive(:readable?).and_return(true)
    allow(mod).to receive(:read_file).with(config_path).and_return(config)
    allow(mod).to receive(:read_file).with(key_path).and_return(key_bytes)
    allow(mod).to receive(:store_loot) do |kind, _type, _host, data, *_rest|
      stored << { kind: kind, data: data }
      '/tmp/module-target-unit-loot'
    end
  end

  it 'stores actual inventory as valid JSON preserving its native structure' do
    allow(mod).to receive(:ansible_inventory).and_return('/usr/bin/ansible-inventory')
    allow(mod).to receive(:cmd_exec).with('/usr/bin/ansible-inventory --list').and_return(JSON.generate(captures.fetch('inventory')))

    mod.hosts_list

    expect(JSON.parse(stored.fetch(0).fetch(:data).to_s)).to eq(captures.fetch('inventory'))
  end

  it 'passes the selected host group into native ping collection' do
    mod.datastore['HOSTS'] = 'reachable'
    expect(mod).to receive(:ping_hosts).with('reachable').and_return([])

    mod.ping_hosts_print
  end

  {
    'malformed JSON' => '{"_meta":',
    'an array' => '[]',
    'missing host metadata' => '{}',
    'a scalar host entry' => '{"_meta":{"hostvars":{"module_node":7}}}'
  }.each do |description, output|
    it "refuses derived #{description} as inventory without recording successful loot" do
      allow(mod).to receive(:ansible_inventory).and_return('/usr/bin/ansible-inventory')
      allow(mod).to receive(:cmd_exec).with('/usr/bin/ansible-inventory --list').and_return(output)

      expect { mod.hosts_list }.to raise_error(Msf::Post::Failed, /Ansible inventory/)
      expect(stored).to be_empty
    end
  end

  it 'collects bytes referenced by the native standard configuration' do
    mod.conf

    expect(stored).to include(kind: 'ansible.private.key', data: key_bytes)
  end

  context 'with native compact INI syntax' do
    let(:config_path) { '/etc/ansible/compact.cfg' }

    it 'collects the same referenced private file without space-dependent parsing' do
      mod.conf

      expect(stored).to include(kind: 'ansible.private.key', data: key_bytes)
    end
  end

  context 'with the natively protected key' do
    let(:config_path) { '/etc/ansible/protected.cfg' }
    let(:key_path) { '/etc/ansible/root_only_key' }
    let(:key_bytes) { nil }

    it 'retains configuration while omitting unreadable key loot' do
      allow(mod).to receive(:readable?).with(key_path).and_return(false)

      mod.conf

      expect(stored).to eq([{ kind: 'ansible.cfg', data: config }])
    end
  end

  it 'does not record a nil private-file read as successful loot' do
    allow(mod).to receive(:read_file).with(key_path).and_return(nil)

    mod.conf

    expect(stored).to eq([{ kind: 'ansible.cfg', data: config }])
  end

  it 'handles a derived unavailable configuration read without nil loot' do
    allow(mod).to receive(:read_file).with(config_path).and_return(nil)

    expect { mod.conf }.not_to raise_error
    expect(stored).to be_empty
  end
end
