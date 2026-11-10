require 'spec_helper'
require 'tmpdir'

RSpec.describe 'Apache Flink application path options' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:modules_path) { ENV.fetch('FLINK_OPTIONS_MODULE_ROOT', File.expand_path('../../modules', __dir__)) }
  let(:dummy_pathname) { Pathname.new(Dir.mktmpdir('flink-options-')) }
  let(:framework) do
    Msf::Simple::Framework.create(
      'ConfigDirectory' => framework_config_pathname.to_s,
      'DeferModuleLoads' => true,
      'DisableDatabase' => true
    )
  end
  let(:validator) do
    validator_class = Class.new do
      include Msf::Ui::Console::ModuleOptionValidation

      attr_accessor :framework
    end
    validator_class.new.tap { |instance| instance.framework = framework }
  end

  {
    'file traversal' => ['auxiliary', 'scanner/http/apache_flink_jobmanager_traversal'],
    'JAR execution' => ['exploit', 'multi/http/apache_flink_jar_upload_exec']
  }.each do |label, (type, reference)|
    context "with #{label}" do
      subject(:mod) { load_and_create_module(module_type: type, reference_name: reference) }

      it 'accepts the application path as a known console run option' do
        # Both modules already honor this value for real root/subpath requests.
        # Their console must not warn that the operator setting is unknown.
        expect(validator.unknown_datastore_option_message(mod, 'TARGETURI')).to be_nil
      end

      it 'preserves the root application default' do
        expect(mod.target_uri.path).to eq('/')
      end

      it 'preserves the selected subpath when normalizing the API route' do
        mod.datastore['TARGETURI'] = '/flink/'

        expect(mod.normalize_uri(mod.target_uri.path, 'config')).to eq('/flink/config')
      end
    end
  end
end
