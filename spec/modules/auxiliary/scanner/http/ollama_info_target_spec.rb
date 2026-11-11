require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/ollama/acceptance'

RSpec.describe 'Genuine Ollama model enumeration', acceptance: true do
  include_context 'module target'
  include Acceptance::Ollama

  before(:all) do
    @native = ollama_native('before')
    code = "load \"test/module_targets/ollama/observer.rb\"; framework.modules.create(#{Acceptance::Ollama::OWNER.inspect}).class.prepend(ModuleTargetOllamaHttp)"
    expect(console_command("irb -e '#{code}'")).not_to match(/Error|Exception/)
  end

  after do
    ollama_native('prepare') if @ollama_changed
  end

  after(:all) do
    ollama_native('after') if @native
  end

  it 'enumerates real running and installed models without duplicates twice' do
    snapshot = ollama_native('inspect')
    2.times { verify_ollama_table(snapshot) }
  end

  it 'enumerates both genuinely unloaded models as installed twice' do
    @ollama_changed = true
    snapshot = ollama_native('prepare', 'installed')
    2.times { verify_ollama_table(snapshot) }
  end

  it 'prints no invented models for a genuinely empty catalog twice' do
    @ollama_changed = true
    snapshot = ollama_native('prepare', 'empty')
    2.times { verify_ollama_table(snapshot) }
  end

  it 'retains discovery when model details require authentication twice' do
    snapshot = ollama_native('inspect')
    2.times { verify_ollama_table(snapshot, 'proxy', { 'RPORT' => 11801 }, details_denied: true) }
  end

  it 'reads protected model details with valid HTTP credentials twice' do
    snapshot = ollama_native('inspect')
    2.times { verify_ollama_table(snapshot, 'proxy', { 'RPORT' => 11801, 'HttpUsername' => 'laboperator', 'HttpPassword' => 'module-target-password' }) }
  end

  it 'does not report an Ollama table when HTTP authentication is required twice' do
    2.times do
      output, = ollama_scan('proxy', { 'RPORT' => 11802 }, allow_errors: true)
      expect(output).not_to include('Ollama Models', 'lab-running', 'lab-installed')
    end
  end

  it 'enumerates the fully authenticated Ollama endpoint twice' do
    snapshot = ollama_native('inspect')
    2.times { verify_ollama_table(snapshot, 'proxy', { 'RPORT' => 11802, 'HttpUsername' => 'laboperator', 'HttpPassword' => 'module-target-password' }) }
  end

  it 'rejects a genuine unrelated Apache HTTP response twice' do
    2.times do
      output, = ollama_scan('proxy', { 'RPORT' => 80 }, allow_errors: true)
      expect(output).not_to include('Ollama Models', 'lab-running', 'lab-installed')
    end
  end

  it 'enumerates real models under a reverse-proxy URL prefix twice' do
    snapshot = ollama_native('inspect')
    2.times { verify_ollama_table(snapshot, 'proxy', { 'TARGETURI' => '/nested/' }) }
  end

  it 'rejects a nonexistent target base path twice' do
    2.times do
      output, = ollama_scan('proxy', { 'TARGETURI' => '/absent-base/' }, allow_errors: true)
      expect(output).not_to include('Ollama Models', 'lab-running', 'lab-installed')
    end
  end

  it 'does not invent a table on a genuinely closed port twice' do
    2.times do
      output, = ollama_scan('ollama', { 'RPORT' => 11999 }, allow_errors: true)
      expect(output).not_to include('Ollama Models', 'lab-running', 'lab-installed')
    end
  end

  it 'retains both lines of an actual multiline model system prompt twice' do
    @ollama_changed = true
    snapshot = ollama_native('prepare', 'multiline')
    2.times { verify_ollama_table(snapshot) }
  end
end
