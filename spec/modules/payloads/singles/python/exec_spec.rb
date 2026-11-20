require 'rspec'
require 'msfenv'
require 'msf/base'
require 'json'
require 'open3'

RSpec.describe 'singles/python/exec' do
  subject(:payload) { payload_class.new }

  let(:payload_class) do
    scope = Module.new
    scope.const_set(:OptString, Msf::OptString)
    source = File.expand_path('../../../../../modules/payloads/singles/python/exec.rb', __dir__)
    scope.module_eval(File.binread(source), source)
    component = scope.const_get(:MetasploitModule)
    Class.new(Msf::Payload) { include component }
  end

  let(:python) { ENV.fetch('PYTHON', 'python3') }
  let(:executor) { File.expand_path('../../../../file_fixtures/python_exec/arguments.py', __dir__) }

  # The interpreter parses and executes the unmodified generated payload and
  # compressed stub. Only subprocess.Popen is replaced, so these examples inspect
  # the exact public API argument without running their command strings.
  def interpreted_command(command)
    payload.datastore['CMD'] = command
    output, error, status = Open3.capture3(python, executor, stdin_data: { payload: payload.generate }.to_json)
    raise "Generated payload failed in Python: #{error}" unless status.success?

    JSON.parse(output).fetch(0).fetch('arguments')
  end

  {
    'ordinary text' => 'printf ordinary',
    'a single quote' => "printf 'single'",
    'both quote kinds' => %q{printf 'single' "double"},
    'a triple single quote' => %q{printf 'single' "double" '''},
    'both triple quote kinds' => %q{printf ''' """},
    'a single quote beside the triple delimiter' => %q{printf "double" 'single'},
    'two single quotes beside the triple delimiter' => %q{printf "double" ''},
    'a double quote beside the triple delimiter' => %q{printf "'''"},
    'two double quotes beside the triple delimiter' => %q{printf "'''" ""},
    'Unicode and shell metacharacters' => %q{printf '雪😀' "$HOME" \ $(printf nested)},
    'an LF with no quotes' => "printf first\nprintf second",
    'an LF with a single quote' => "printf 'first'\nprintf second",
    'an LF with both quote kinds' => "printf 'first' \"second\"\nprintf third",
    'a CR with no quotes' => "printf first\rprintf second",
    'a CR with both quote kinds' => "printf 'first' \"second\"\rprintf third",
    'CRLF with both quote kinds' => "printf 'first' \"second\"\r\nprintf third",
    'a trailing backslash with no quotes' => 'printf trailing\\',
    'a trailing backslash with a single quote' => "printf 'trailing'\\",
    'a trailing backslash with both quote kinds' => "printf 'trailing' \"slash\"\\",
    'an even trailing backslash pair' => 'printf trailing\\\\'
  }.each do |description, command|
    it "preserves #{description} in the real interpreter" do
      expect(interpreted_command(command)).to eq([command])
    end
  end

  it 'preserves the operator command option during generation' do
    command = "printf 'first' \"second\"\r\n"
    payload.datastore['CMD'] = command
    payload.generate

    expect(payload.datastore['CMD']).to eq(command)
  end
end
