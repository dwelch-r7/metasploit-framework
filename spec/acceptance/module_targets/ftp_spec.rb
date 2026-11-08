require 'acceptance_spec_helper'

RSpec.describe 'FTP module targets' do
  include_context 'module target'

  before(:all) do
    %w[read_write read_only denied].each do |service|
      expect(target_exec(service, 'proftpd', '-v')).to match(/ProFTPD Version \d+\.\d+\./)
      expect(target_exec(service, 'python3', '/opt/native_probe.py')).to include("permissions verified: #{service}")
    end
  end

  it 'identifies the normalized FTP product from the real banner' do
    output = run_target_module('auxiliary/scanner/ftp/ftp_version', 'read_write')
    expect(output).to match(/FTP Banner: ProFTPD\r?\n/)
  end

  it 'exposes the login scanner check through the public entry point' do
    output = run_target_module('auxiliary/scanner/ftp/ftp_login', 'read_write', {}, action: 'check')
    expect(output).to match(/FTP service detected: ProFTPD\r?\n/)
  end

  %w[read_write read_only denied].each do |service|
    it "authenticates a local user twice with listing, access and extended checks on #{service}" do
      2.times do
        output = run_target_module('auxiliary/scanner/ftp/ftp_login', service, login_options.merge(
          'CHECK_ACCESS' => true, 'DIRECTORY_LISTING' => true, 'EXTENDED_CHECKS' => true
        ))
        expect(output).to include('Login Successful: module_target:module-target-password (Read/Write)')
        expect(output).to include('FTP FEAT: 211-Features:', "FTP STAT: 211-Status of 'Module target FTP'", 'FTP SYST: 215 UNIX Type: L8')
        expect(listing_loot(output)).to include('module-target.txt')
        expect(target_files(service)).to eq(['module-target.txt'])
      end
    end
  end

  it 'rejects an invalid local password' do
    output = run_target_module('auxiliary/scanner/ftp/ftp_login', 'read_write', login_options.merge('PASSWORD' => 'wrong-password'), allow_errors: true)
    expect(output).to include('Failed: module_target:wrong-password')
    expect(output).not_to include('Login Successful')
  end

  { 'read_write' => 'Read/Write', 'read_only' => 'Read-only', 'denied' => nil }.each do |service, access|
    (access ? [false, true] : [false]).each do |extended|
      it "detects anonymous #{service} access twice with #{extended ? 'EPSV' : 'PASV'} and preserves files" do
        2.times do
          output = run_target_module('auxiliary/scanner/ftp/ftp_anonymous', service, { 'STORE_LOOT' => true, 'PassiveMode' => extended })
          if access
            expect(output).to include("Anonymous #{access} access")
            expect(listing_loot(output)).to include('module-target.txt')
          else
            expect(output).to include('FTP service, but no anonymous access')
            expect(output).not_to include('Directory listing stored to:')
          end
          expect(target_files(service)).to eq(['module-target.txt'])
        end
      end
    end
  end

  it 'supports the login scanner anonymous credential collection' do
    output = run_target_module('auxiliary/scanner/ftp/ftp_login', 'read_write', login_options.merge(
      'USERNAME' => nil, 'PASSWORD' => nil, 'ANONYMOUS_LOGIN' => true
    ))
    expect(output).to include('Login Successful: anonymous:mozilla@example.com')
  end

  it 'does not accept anonymous credentials when anonymous access is disabled' do
    output = run_target_module('auxiliary/scanner/ftp/ftp_login', 'denied', login_options.merge(
      'USERNAME' => nil, 'PASSWORD' => nil, 'ANONYMOUS_LOGIN' => true
    ), allow_errors: true)
    expect(output).to include('Failed: anonymous:mozilla@example.com')
    expect(output).not_to include('Login Successful')
  end

  def target_files(service)
    target_exec(service, 'find', '/srv/ftp', '-mindepth', '1', '-maxdepth', '1', '-printf', '%f\n').lines.map(&:strip).sort
  end

  def listing_loot(output)
    path = output[/Directory listing stored to: (.+)$/, 1]&.strip
    expect(path).not_to be_nil, output
    expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
    File.read(path)
  end

  def login_options
    {
      'USERNAME' => 'module_target', 'PASSWORD' => 'module-target-password',
      'USER_FILE' => nil, 'PASS_FILE' => nil, 'USERPASS_FILE' => nil,
      'BLANK_PASSWORDS' => false, 'USER_AS_PASS' => false, 'ANONYMOUS_LOGIN' => false,
      'STOP_ON_SUCCESS' => true
    }
  end
end
