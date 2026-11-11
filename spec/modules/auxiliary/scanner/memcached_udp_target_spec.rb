require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/memcached_udp/acceptance'

RSpec.describe 'Genuine Memcached UDP scanners', acceptance: true do
  include_context 'module target'
  include Acceptance::MemcachedUdp

  before(:all) do
    @native = memcached_native_phase('before')
    observer = 'test/module_targets/ntp/report_observer.rb'
    owners = Acceptance::MemcachedUdp::OWNERS
    code = "load #{observer.inspect}; #{owners.inspect}.each { |name| framework.modules.create(name).class.prepend(ModuleTargetNtpReports) }"
    output = console_command("irb -e '#{code}'")
    expect(output).not_to match(/Error|Exception/)
  end

  after(:all) do
    memcached_native_phase('after') if @native
  end

  %w[legacy modern].each do |service|
    Acceptance::MemcachedUdp::OWNERS.each do |owner|
      it "runs #{owner.split('/').last} twice against #{service} and verifies actual packets/reports" do
        2.times { verify_memcached_scan(owner, [service]) }
      end
    end
  end

  Acceptance::MemcachedUdp::OWNERS.each do |owner|
    it "does not report #{owner.split('/').last} from a working TCP server with UDP disabled, twice" do
      2.times { verify_memcached_scan(owner, ['disabled'], positive: false) }
    end

    it "does not report #{owner.split('/').last} from a closed UDP port, twice" do
      2.times { verify_memcached_scan(owner, ['modern'], port: 11212, positive: false) }
    end

    it "keeps both hosts' #{owner.split('/').last} packets and reports distinct in repeated batches" do
      2.times { verify_memcached_scan(owner, %w[legacy modern]) }
    end
  end
end
