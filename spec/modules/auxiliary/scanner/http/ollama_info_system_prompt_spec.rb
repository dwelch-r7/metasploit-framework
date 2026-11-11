require 'msfenv'
require 'msf/base'

RSpec.describe 'Ollama system prompts' do
  subject(:mod) do
    namespace = Module.new
    path = File.expand_path('../../../../../modules/auxiliary/scanner/http/ollama_info.rb', __dir__)
    namespace.module_eval(File.binread(path), path)
    namespace.const_get(:MetasploitModule).allocate
  end

  # The fixture retains the system and modelfile fields returned by Ollama 0.1.48
  # for an imported SmolLM-135M model created with a two-line SYSTEM directive.
  let(:capture) do
    path = File.expand_path('../../../../file_fixtures/modules/auxiliary/scanner/http/ollama_info/multiline_system.json', __dir__)
    JSON.parse(File.binread(path))
  end

  describe '#get_system_prompt' do
    it 'preserves both lines of the captured structured prompt without Modelfile quotes' do
      expect(mod.get_system_prompt(capture)).to eq("Module target first system line\nModule target second system line")
    end

    it 'uses a structured single-line prompt without requiring a Modelfile' do
      expect(mod.get_system_prompt('system' => 'Single-line system prompt')).to eq('Single-line system prompt')
    end

    it 'prefers the structured prompt to a different Modelfile prompt' do
      details = capture.merge('modelfile' => "SYSTEM Legacy system prompt\n")

      expect(mod.get_system_prompt(details)).to eq(capture.fetch('system'))
    end

    it 'preserves whitespace in the structured prompt' do
      expect(mod.get_system_prompt('system' => "  System prompt\n")).to eq("  System prompt\n")
    end

    it 'marks an explicitly empty structured prompt unavailable without using the Modelfile' do
      expect(mod.get_system_prompt(capture.merge('system' => ''))).to eq('N/A')
    end

    it 'marks an explicitly null structured prompt unavailable without using the Modelfile' do
      expect(mod.get_system_prompt(capture.merge('system' => nil))).to eq('N/A')
    end

    it 'preserves the legacy Modelfile-only prompt when the structured field is absent' do
      expect(mod.get_system_prompt('modelfile' => "FROM model\nSYSTEM Legacy system prompt\n")).to eq("Legacy system prompt\n")
    end

    it 'marks missing details unavailable' do
      expect(mod.get_system_prompt(nil)).to eq('N/A')
    end

    it 'marks an absent structured prompt and Modelfile unavailable' do
      expect(mod.get_system_prompt({})).to eq('N/A')
    end

    it 'marks a null Modelfile unavailable' do
      expect(mod.get_system_prompt('modelfile' => nil)).to eq('N/A')
    end

    it 'marks an empty Modelfile unavailable' do
      expect(mod.get_system_prompt('modelfile' => '')).to eq('N/A')
    end

    it 'marks a Modelfile without a SYSTEM directive unavailable' do
      expect(mod.get_system_prompt('modelfile' => "FROM model\n")).to eq('N/A')
    end
  end
end
