require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/java_rmi/acceptance'

RSpec.describe 'Genuine JVM registry and JMX owners', acceptance: true do
  include_context 'module target'
  include Acceptance::JavaRmi

  before(:all) do
    @native = java_native_phase('before')
    owners = Acceptance::JavaRmi::OWNERS.values_at('registry', 'jmx')
    code = "load \"test/module_targets/java_rmi/report_observer.rb\"; #{owners.inspect}.each { |name| framework.modules.create(name).class.prepend(ModuleTargetRmiObservations) }"
    expect(console_command("irb -e '#{code}'")).not_to match(/Error|Exception/)
  end

  after(:all) do
    java_native_phase('after') if @native
  end

  %w[open guarded].each do |role|
    it "enumerates the genuine #{role} JMX registry and reference twice" do
      2.times { verify_java_registry(role) }
    end
  end

  it 'enumerates both actual dynamic-proxy registry aliases twice' do
    2.times { verify_java_registry('empty', multi: true) }
  end

  it 'handles an actual empty registry without inventing services twice' do
    2.times do
      output, reports, = java_scan('registry', 'empty', {}, allow_errors: true)
      expect(output).to include('Names not found in the Registry')
      expect(reports).to be_empty
    end
  end

  %w[open guarded].each do |role|
    it "classifies the actual #{role} JMX endpoint twice" do
      2.times { verify_java_jmx(role) }
    end
  end

  it 'does not report a JMX MBean in the genuine empty registry twice' do
    2.times do
      output, reports, = java_scan('jmx', 'empty')
      expect(output).to include('Java JMX MBean not detected')
      expect(reports).to be_empty
    end
  end

  %w[registry jmx].each do |kind|
    it "does not report genuine HTTP content as a #{kind} endpoint twice" do
      2.times do
        output, reports, = java_scan(kind, 'empty', { 'RPORT' => 8180, 'RmiReadLoopTimeout' => 1 }, allow_errors: true)
        expect(output).not_to include('names found in the Registry', 'Handshake with', 'Class Loader Enabled')
        expect(reports).to be_empty
      end
    end
  end
end
