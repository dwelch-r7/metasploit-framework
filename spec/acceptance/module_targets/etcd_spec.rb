require 'acceptance_spec_helper'
require 'rbconfig'
require_relative '../../../test/module_targets/etcd/tree'

RSpec.describe 'Native etcd targets' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/etcd/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-etcd.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-etcd-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native = JSON.parse(stdout)
  end

  %w[old modern secured empty v2_disabled].each do |service|
    it "discovers the actual native version twice on #{service}" do
      2.times do
        output = scan('version', service)
        @native.fetch('profiles').fetch(service).fetch('version').each do |key, value|
          expect(output).to include("\"#{key}\"=>\"#{value}\"")
        end
      end
    end
  end

  it 'discovers the actual version through a reverse proxy base path' do
    expect(scan('version', 'prefix', { 'TARGETURI' => '/etcd/' })).to include('"etcdserver"=>"3.5.18"')
  end

  it 'does not fingerprint an unrelated actual Apache JSON resource as etcd' do
    output = scan('version', 'unrelated')
    expect(output).not_to include('"name"=>', '"etcdserver"=>', '[+]')
  end

  %w[old modern empty secured prefix].each do |service|
    it "collects exact recursive JSON twice without changing #{service} keys" do
      options = service == 'secured' ? { 'HttpUsername' => @native.fetch('username'), 'HttpPassword' => @native.fetch('password') } : {}
      options['TARGETURI'] = '/etcd/' if service == 'prefix'
      profile = @native.fetch('profiles').fetch(service == 'prefix' ? 'modern' : service)
      2.times do
        previous = loot_files
        output = scan('open_key_scanner', service, options)
        expect(output).to include('Version:', 'Data:')
        created = loot_files - previous
        expect(created.length).to eq(1), output
        expect(EtcdTarget.canonical_document(JSON.parse(File.binread(created.first)))).to eq(EtcdTarget.canonical_document(profile.fetch('tree')))
        endpoint = target_endpoint(service)
        path = service == 'prefix' ? '/etcd/v2/keys/?recursive=true' : '/v2/keys/?recursive=true'
        message = Net::HTTP::Get.new(path)
        message.basic_auth(@native.fetch('username'), @native.fetch('password')) if service == 'secured'
        response = Net::HTTP.start(endpoint.fetch('host'), endpoint.fetch('port'), nil) { |http| http.request(message) }
        expect(response.code).to eq('200')
        expect(EtcdTarget.canonical_document(JSON.parse(response.body))).to eq(EtcdTarget.canonical_document(profile.fetch('tree')))
      end
    end
  end

  [
    ['secured', {}, 'anonymous credentials'],
    ['secured', { 'HttpUsername' => 'root', 'HttpPassword' => 'incorrect-module-target-password' }, 'wrong credentials'],
    ['v2_disabled', {}, 'disabled v2 API'],
    ['unrelated', {}, 'unrelated Apache']
  ].each do |service, options, label|
    it "refuses #{label} without key loot or a runtime error" do
      previous = loot_files
      output = scan('open_key_scanner', service, options, allow_errors: true)
      expect(output).not_to match(/NoMethodError|undefined (?:local variable|method)|Error running|Exception|\nData:/)
      expect(loot_files).to eq(previous)
    end
  end

  def scan(name, service, options = {}, allow_errors: false)
    run_target_module("auxiliary/scanner/etcd/#{name}", service, { 'SSL' => false, 'VERBOSE' => true, 'THREADS' => 1 }.merge(options), allow_errors: allow_errors)
  end

  def loot_files
    Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')]
  end
end
