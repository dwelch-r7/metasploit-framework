require 'spec_helper'
require 'rex/text'
require_relative '../../../test/module_targets/flowise/acceptance_helpers'

RSpec.describe FlowiseAcceptance do
  let(:harness_class) do
    Class.new do
      include RSpec::Matchers
      include FlowiseAcceptance

      attr_reader :forwarded
      attr_accessor :response

      def initialize
        @profile = 'flowise_300'
        @observations = []
        @forwarded = []
        @response = 'Unit boundary return'
      end

      def rows
        @observations
      end

      def listener_host
        '192.0.2.30'
      end

      def run_target_module(*arguments, **keywords)
        @forwarded << [arguments, keywords]
        @observations << { 'kind' => 'UNIT-BOUNDARY' }
        @response
      end
    end
  end
  let(:harness) { harness_class.new }

  it 'supplies the generic command default when the effective payload is generic' do
    harness.invoke(FlowiseInputs::CUSTOM)
    expect(harness.forwarded.fetch(0).fetch(0).fetch(2)).to include('PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'true')
  end

  it 'preserves explicit generic command bytes without mutating caller options' do
    command = +'printf${IFS}%s${IFS}ExactProof'
    options = { 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command }
    harness.invoke(FlowiseInputs::CUSTOM, options)
    expect(harness.forwarded.fetch(0).fetch(0).fetch(2).fetch('CMD')).to equal(command)
    expect(options).to eq('PAYLOAD' => 'cmd/unix/generic', 'CMD' => command)
  end

  it 'does not forward generic CMD to the selected fetch payload' do
    payload = 'cmd/linux/http/x64/meterpreter_reverse_tcp'
    harness.invoke(FlowiseInputs::JS, { 'PAYLOAD' => payload, 'LPORT' => 4444 }, action: 'run -z')
    forwarded = harness.forwarded.fetch(0).fetch(0).fetch(2)
    expect(forwarded).not_to have_key('CMD')
    expect(forwarded).to include('PAYLOAD' => payload, 'LPORT' => 4444)
  end

  it 'preserves Python options without generic CMD or passive WfsDelay' do
    harness.instance_variable_set(:@profile, 'flowise_311')
    harness.invoke(FlowiseInputs::MCP, { 'PAYLOAD' => 'cmd/unix/reverse_python', 'PythonPath' => '/usr/bin/python3' }, action: 'run -z')
    forwarded = harness.forwarded.fetch(0).fetch(0).fetch(2)
    expect(forwarded).not_to have_key('CMD')
    expect(forwarded).not_to have_key('WfsDelay')
    expect(forwarded).to include('PAYLOAD' => 'cmd/unix/reverse_python', 'PythonPath' => '/usr/bin/python3')
  end

  it 'rejects invalid explicit CMD for a fetch family before invoking Framework' do
    options = { 'PAYLOAD' => 'cmd/linux/http/x64/meterpreter_reverse_tcp', 'CMD' => 'Explicit invalid command' }
    expect { harness.invoke(FlowiseInputs::JS, options) }.to raise_error(ArgumentError, 'CMD is only valid with cmd/unix/generic in this fixture')
    expect(harness.forwarded).to eq([])
  end

  it 'does not inject payload generation options into checks' do
    harness.invoke(FlowiseInputs::JS, action: 'check')
    forwarded = harness.forwarded.fetch(0).fetch(0).fetch(2)
    expect(forwarded).not_to have_key('CMD')
    expect(forwarded).not_to have_key('PAYLOAD')
  end

  it 'still rejects an actual unknown-option response from Framework' do
    harness.response = 'Unknown datastore option: FORBIDDEN'
    expect { harness.invoke(FlowiseInputs::JS) }.to raise_error(RSpec::Expectations::ExpectationNotMetError, /Unknown datastore option/)
  end
end
