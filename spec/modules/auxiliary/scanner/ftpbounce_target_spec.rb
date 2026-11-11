require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/ftp_bounce/acceptance'

RSpec.describe 'Genuine FTP bounce port scanner', acceptance: true do
  include_context 'module target'
  include_context 'wait_for_expect'
  include Acceptance::FtpBounce

  before(:all) do
    @native = bounce_native_phase('before')
    code = "load \"test/module_targets/ntp/report_observer.rb\"; framework.modules.create(#{Acceptance::FtpBounce::OWNER.inspect}).class.prepend(ModuleTargetNtpReports)"
    output = console_command("irb -e '#{code}'")
    expect(output).not_to match(/Error|Exception/)
  end

  after(:all) do
    bounce_native_phase('after') if @native
  end

  it 'finds a genuine foreign high port twice as anonymous' do
    2.times { verify_bounce('8080', open_ports: [8080]) }
  end

  it 'finds a genuine foreign high port twice with local credentials' do
    2.times { verify_bounce('8080', open_ports: [8080], 'FTPUSER' => 'module_target', 'FTPPASS' => 'module-target-password') }
  end

  it 'keeps an open-then-closed port list accurate on repeat' do
    2.times { verify_bounce('8080,8081', open_ports: [8080]) }
  end

  it 'keeps a closed-then-open port list accurate on repeat' do
    2.times { verify_bounce('8081,8080', open_ports: [8080]) }
  end

  it 'finds both real open ports in a range with a closed middle port twice' do
    2.times { verify_bounce('8080-8082', open_ports: [8080, 8082]) }
  end

  it 'finds both real open ports in a reversed explicit list twice' do
    2.times { verify_bounce('8082,8080', open_ports: [8080, 8082]) }
  end

  it 'does not report a foreign port through the protected relay twice' do
    2.times { verify_bounce('8080', open_ports: [], relay: 'protected') }
  end

  it 'does not report a foreign port after rejected authentication twice' do
    2.times { verify_bounce('8080', open_ports: [], 'FTPUSER' => 'module_target', 'FTPPASS' => 'wrong-password') }
  end

  it 'does not report an actually open low port refused by relay policy twice' do
    2.times { verify_bounce('80', open_ports: []) }
  end

  it 'still finds a genuine port with a small configured delay twice' do
    2.times { verify_bounce('8080', open_ports: [8080], 'DELAY' => 20) }
  end
end
