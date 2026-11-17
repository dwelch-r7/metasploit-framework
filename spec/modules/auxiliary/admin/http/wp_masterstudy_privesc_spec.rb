require 'msfenv'
require 'msf/base'

RSpec.describe 'MasterStudy generated passwords' do
  subject(:password) { mod.get_password }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('MASTERSTUDY_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/admin/http/wp_masterstudy_privesc.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:mod) { owner_class.new }
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:configured_password) { '' }

  before do
    allow(mod).to receive(:framework).and_return(framework)
    mod.datastore['PASSWORD'] = configured_password
  end

  describe '#get_password' do
    context 'when PASSWORD is blank' do
      # Captured from the original getter using rex-text 0.2.64. The genuine
      # MasterStudy 2.7.5 registration endpoint rejected it for lacking a number.
      let(:generated_prefix) { 'lrMIJLFPAQ' }

      before do
        allow(Rex::Text).to receive(:rand_password).and_return(generated_prefix)
        allow(Rex::Text).to receive(:rand_text_alpha_lower).with(1).and_return('a')
        allow(Rex::Text).to receive(:rand_text_alpha_upper).with(1).and_return('A')
        allow(Rex::Text).to receive(:rand_text_numeric).with(1).and_return('1')
      end

      # Framework and the Rex generators are doubled with their real output
      # lengths (10 bytes and one byte). The owner getter and datastore execute;
      # this unit contract does not exercise registration or HTTP behavior.
      shared_examples 'a compliant generated password' do
        it 'meets the native password length and character requirements' do
          aggregate_failures do
            expect(password.bytesize).to be_between(8, 20).inclusive
            expect(password).to match(/[a-z]/)
            expect(password).to match(/[A-Z]/)
            expect(password).to match(/[0-9]/)
          end
        end

        it 'preserves the configured PASSWORD value' do
          password

          expect(mod.datastore['PASSWORD']).to eq(configured_password)
        end
      end

      include_examples 'a compliant generated password'

      context 'when PASSWORD is nil' do
        let(:configured_password) { nil }

        include_examples 'a compliant generated password'
      end

      context 'when PASSWORD contains only whitespace' do
        let(:configured_password) { " \t\n" }

        include_examples 'a compliant generated password'
      end

      # Explicit synthetic outputs covering the other missing categories.
      context 'when the 10-byte generator output lacks lowercase letters' do
        let(:generated_prefix) { 'ABCDEFG123' }

        include_examples 'a compliant generated password'
      end

      context 'when the 10-byte generator output lacks uppercase letters' do
        let(:generated_prefix) { 'abcdefg123' }

        include_examples 'a compliant generated password'
      end
    end

    shared_examples 'an unchanged explicit password' do
      it 'returns PASSWORD exactly without generating characters' do
        expect(Rex::Text).not_to receive(:rand_password)
        expect(Rex::Text).not_to receive(:rand_text_alpha_lower)
        expect(Rex::Text).not_to receive(:rand_text_alpha_upper)
        expect(Rex::Text).not_to receive(:rand_text_numeric)

        expect(password).to eq(configured_password)
      end
    end

    context 'when an explicit PASSWORD meets the native policy' do
      let(:configured_password) { 'CustomPassword7!' }

      include_examples 'an unchanged explicit password'
    end

    context 'when an explicit PASSWORD has surrounding whitespace' do
      let(:configured_password) { "  Custom7!\t" }

      include_examples 'an unchanged explicit password'
    end

    context 'when an explicit PASSWORD is shorter than the native minimum' do
      let(:configured_password) { 'short' }

      include_examples 'an unchanged explicit password'
    end

    context 'when an explicit PASSWORD exceeds the native maximum' do
      let(:configured_password) { 'CustomPasswordIsTooLong7!' }

      include_examples 'an unchanged explicit password'
    end
  end
end
