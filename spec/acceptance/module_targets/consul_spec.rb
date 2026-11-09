require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Native Consul version targets' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/consul/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-consul.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-consul-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native = JSON.parse(stdout)
  end

  it 'discovers the exact public UI version when the genuine agent blocks both APIs' do
    output = scan('ui_only')
    expect(output).to include('HashiCorp Consul 1.20.6 identified from the UI version leak (Consul UI at /ui/)')
    expect(output).to include('the agent info API returned HTTP 403')
  end

  %w[open_old open_current].each do |service|
    it "discovers the exact native version twice on #{service}" do
      2.times do
        output = scan(service)
        expect(output).to include("HashiCorp Consul #{@native.fetch('profiles').fetch(service).fetch('version')} found")
        expect(output).to include('No authentication required to read the agent info API')
      end
    end
  end

  %w[acl_old acl_current].each do |service|
    it "uses an actual management token on #{service}" do
      output = scan(service, 'Token' => @native.fetch('management_token'))
      expect(output).to include("HashiCorp Consul #{@native.fetch('profiles').fetch(service).fetch('version')} found")
      expect(output).to include('Version retrieved with the supplied ACL token')
    end

    it "discovers the native public version without a token on #{service}" do
      expect_fallback(service, scan(service))
    end

    it "falls back after the native agent rejects an incorrect token on #{service}" do
      output = scan(service, 'Token' => @native.fetch('wrong_token'))
      expect_fallback(service, output)
      expect(output).not_to include('Version retrieved with the supplied ACL token')
    end
  end

  it 'discovers Consul behind a genuine reverse-proxy subpath' do
    expect(scan('prefix', 'TARGETURI' => '/consul/')).to include('HashiCorp Consul 2.0.4 found')
  end

  it 'does not identify unrelated actual Apache content as Consul' do
    output = scan('unrelated')
    expect(output).to include('Target does not appear to be a Consul agent')
    expect(output).not_to include('HashiCorp Consul', 'Consul UI detected')
  end

  def scan(service, options = {})
    run_target_module('auxiliary/scanner/http/hashicorp_consul_version', service, { 'SSL' => false, 'THREADS' => 1 }.merge(options))
  end

  def expect_fallback(service, output)
    profile = @native.fetch('profiles').fetch(service)
    expect(output).to include("HashiCorp Consul #{profile.fetch('version')} identified from")
    expect(output).to include('identified from the version endpoint')
    expect(output).to include('the agent info API returned HTTP 403')
  end
end
