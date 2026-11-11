require 'rspec'
require 'msfenv'
require 'msf/core'

RSpec.describe 'Java JMX endpoint discovery' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    scope.const_set(:Opt, Msf::Opt)
    source = File.expand_path('../../../../../modules/auxiliary/scanner/misc/java_jmx_server.rb', __dir__)
    scope.module_eval(File.read(source), source)
    scope.const_get(:MetasploitModule)
  end
  # An empty Temurin 17.0.21+9 registry returned this exact exception class.
  # send_registry_lookup exposes the class name as the Ruby exception message.
  let(:missing_binding) { Rex::Proto::Rmi::Exception.new('java.rmi.NotBoundException') }

  describe '#discover_endpoint' do
    it 'returns no endpoint when jmxrmi is not bound' do
      allow(mod).to receive(:send_registry_lookup).with(name: 'jmxrmi').and_raise(missing_binding)

      expect(mod.discover_endpoint).to be_nil
    end

    it 'propagates other remote exceptions' do
      exception = Rex::Proto::Rmi::Exception.new('java.rmi.AccessException')
      allow(mod).to receive(:send_registry_lookup).with(name: 'jmxrmi').and_raise(exception)

      expect { mod.discover_endpoint }.to raise_error(Rex::Proto::Rmi::Exception, 'java.rmi.AccessException')
    end

    it 'propagates local failures' do
      allow(mod).to receive(:send_registry_lookup).with(name: 'jmxrmi').and_raise(ArgumentError, 'Invalid lookup')

      expect { mod.discover_endpoint }.to raise_error(ArgumentError, 'Invalid lookup')
    end

    it 'preserves a valid JMX endpoint' do
      endpoint = { object: 'javax.management.remote.rmi.RMIServerImpl_Stub', address: '192.0.2.1', port: 1100 }
      allow(mod).to receive(:send_registry_lookup).with(name: 'jmxrmi').and_return(endpoint)

      expect(mod.discover_endpoint).to equal(endpoint)
    end
  end

  describe '#run_host' do
    before do
      allow(mod).to receive_messages(rhost: '192.0.2.1', rport: 1099, is_rmi?: true)
      allow(mod).to receive(:send_registry_lookup).with(name: 'jmxrmi').and_raise(missing_binding)
      allow(mod).to receive(:print_status)
    end

    it 'disconnects and reports no MBean without service or vulnerability reports' do
      expect(mod).to receive(:connect).with(no_args).once
      expect(mod).to receive(:disconnect).with(no_args).once
      expect(mod).to receive(:print_status).with('192.0.2.1:1099 Java JMX MBean not detected')
      expect(mod).not_to receive(:report_service)
      expect(mod).not_to receive(:report_vuln)
      expect(mod).not_to receive(:handshake)

      mod.run_host('192.0.2.1')
    end
  end
end
