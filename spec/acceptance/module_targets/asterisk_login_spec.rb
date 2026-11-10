require 'acceptance_spec_helper'
require_relative '../../../test/module_targets/sip/acceptance'

RSpec.describe 'Genuine Asterisk Manager authentication' do
  include_context 'real SIP targets'

  cases = [
    ['module_manager', 'module-target-manager-password', true],
    ['module_manager', 'module-target-wrong-password', false],
    ['missing_manager', 'module-target-manager-password', false]
  ]
  cases.each do |username, password, success|
    it "tests the actual #{username} #{success ? 'accepted' : 'rejected'} login twice with exact credential reporting" do
      snapshots = 2.times.map do
        output = scan('auxiliary/voip/asterisk_login', 'exposed', {
          'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => '', 'PASS_FILE' => '', 'USERPASS_FILE' => '',
          'BLANK_PASSWORDS' => false, 'USER_AS_PASS' => false, 'STOP_ON_SUCCESS' => true, 'BRUTEFORCE_SPEED' => 5
        }, port: 5038)
        rows = credentials
        if success
          expect(output).to include("User: \"#{username}\" using pass: \"#{password}\" - can login")
          expect(rows.length).to eq(1)
          row = rows.first
          expect(row.slice('username', 'private_data', 'private_type', 'status', 'address', 'port', 'proto', 'name', 'module_fullname')).to eq({
            'username' => username, 'private_data' => password, 'private_type' => 'Metasploit::Credential::Password', 'status' => 'Successful',
            'address' => endpoint('exposed').fetch('host'), 'port' => 5038, 'proto' => 'tcp', 'name' => 'asterisk_manager', 'module_fullname' => 'auxiliary/voip/asterisk_login'
          })
        else
          expect(output).not_to include('can login')
          expect(rows).to eq([])
          expect(services).to eq([])
        end
        expect(notes).to eq([])
        inactive('exposed')
        rows
      end
      expect(snapshots.last).to eq(snapshots.first)
      manager_wire_proof(username, password)
    end
  end
end
