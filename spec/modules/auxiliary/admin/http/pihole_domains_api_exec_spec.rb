require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'Pi-hole Top Domains API version boundaries' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('PIHOLE_DOMAINS_UNIT_MODULE', File.expand_path('../../../../../modules/auxiliary/admin/http/pihole_domains_api_exec.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end

  before do
    mod.datastore['RHOSTS'] = '192.0.2.1'
    mod.datastore['RHOST'] = '192.0.2.1'
    allow(mod).to receive_messages(print_error: nil, vprint_good: nil, vprint_bad: nil)
  end

  {
    '5.3.1' => Msf::Exploit::CheckCode::Appears,
    '5.5' => Msf::Exploit::CheckCode::Appears,
    '5.5.1' => Msf::Exploit::CheckCode::Safe,
    '5.6' => Msf::Exploit::CheckCode::Safe,
    '5.7' => Msf::Exploit::CheckCode::Safe
  }.each do |version, expected|
    it "classifies Web #{version} using the real module check contract" do
      # Discovery is the only protocol boundary double. Real initialization,
      # version comparison and reason-bearing CheckCode results remain intact;
      # no Framework thread manager, HTTP request or target is allocated.
      allow(mod).to receive(:get_versions).and_return([nil, version, nil])

      result = mod.check

      status = expected == Msf::Exploit::CheckCode::Appears ? 'vulnerable' : 'not vulnerable'
      expect([result, result.reason]).to eq([expected, "Pi-hole web interface version #{version} is #{status}"])
    end
  end

  it 'returns unknown with a reason when discovery returns nil' do
    allow(mod).to receive(:get_versions).and_return(nil)

    result = mod.check

    expect([result, result.reason]).to eq([Msf::Exploit::CheckCode::Unknown, 'Could not connect to web service'])
  end
end
