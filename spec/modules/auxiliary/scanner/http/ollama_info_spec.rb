require 'msfenv'
require 'msf/base'

RSpec.describe 'Ollama model details' do
  subject(:mod) do
    namespace = Module.new
    path = File.expand_path('../../../../../modules/auxiliary/scanner/http/ollama_info.rb', __dir__)
    namespace.module_eval(File.binread(path), path)
    namespace.const_get(:MetasploitModule).allocate
  end

  let(:capture) do
    path = File.expand_path('../../../../file_fixtures/modules/auxiliary/scanner/http/ollama_info/models.json', __dir__)
    JSON.parse(File.binread(path))
  end
  let(:tables) { [] }
  let(:model_details) { capture.fetch('details').fetch(model.fetch('name')) }
  let(:running_models) { [] }
  let(:local_models) { [model] }
  let(:parameter_size) { '134.52M' }

  before do
    allow(mod).to receive(:ollama?).and_return(true)
    allow(mod).to receive(:list_running_models).and_return('models' => running_models)
    allow(mod).to receive(:list_local_models).and_return('models' => local_models)
    allow(mod).to receive(:get_model_info).and_return(model_details)
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:print_status)
    allow(Rex::Text::Table).to receive(:new).and_wrap_original do |original, options|
      original.call(options).tap { |table| tables << table }
    end
  end

  shared_examples 'model metadata' do |name, release, status, size, temperature, prompt|
    it 'preserves captured metadata when details are available' do
      mod.run_host('192.0.2.10')

      expect(tables.fetch(0).rows).to eq([[name, release, status, size, parameter_size, temperature, prompt]])
    end

    context 'when the details request returns nil, including HTTP 401' do
      let(:model_details) { nil }

      it 'prints the discovered model with unavailable fields marked N/A' do
        mod.run_host('192.0.2.10')

        expect(mod).to have_received(:print_status).with(tables.fetch(0).to_s)
        expect(tables.fetch(0).rows).to eq([[name, release, status, size, 'N/A', 'N/A', 'N/A']])
      end
    end

    context 'when the nested details field is absent' do
      let(:model_details) { super().except('details') }
      let(:parameter_size) { 'N/A' }

      it_behaves_like 'model metadata with incomplete parameter size', name, release, status, size, temperature, prompt
    end

    context 'when the nested details field is null' do
      let(:model_details) { super().merge('details' => nil) }
      let(:parameter_size) { 'N/A' }

      it_behaves_like 'model metadata with incomplete parameter size', name, release, status, size, temperature, prompt
    end

    context 'when the parameter size field is absent' do
      let(:model_details) { super().merge('details' => {}) }
      let(:parameter_size) { 'N/A' }

      it_behaves_like 'model metadata with incomplete parameter size', name, release, status, size, temperature, prompt
    end
  end

  shared_examples 'model metadata with incomplete parameter size' do |name, release, status, size, temperature, prompt|
    it 'marks only parameter size unavailable and preserves the other metadata' do
      mod.run_host('192.0.2.10')

      expect(tables.fetch(0).rows).to eq([[name, release, status, size, parameter_size, temperature, prompt]])
    end
  end

  context 'with a running model also present in the local catalog' do
    let(:model) { capture.fetch('running').fetch(0) }
    let(:running_models) { [model] }

    it_behaves_like 'model metadata', 'lab-running', 'cpu', 'Running', '90.80 MB', '0.42', 'Module target single-line system prompt'
  end

  context 'with an installed model' do
    let(:model) { capture.fetch('models').fetch(1) }

    it_behaves_like 'model metadata', 'lab-installed', 'bare', 'Installed', '87.48 MB', 'N/A', 'N/A'
  end
end
