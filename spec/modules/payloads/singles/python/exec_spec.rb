require 'rspec'
require 'msfenv'
require 'msf/base'
require 'json'
require 'open3'
require 'shellwords'

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
  def interpreted_invocation(command)
    payload.datastore['CMD'] = command
    output, error, status = Open3.capture3(python, executor, stdin_data: { payload: payload.generate }.to_json)
    raise "Generated payload failed in Python: #{error}" unless status.success?

    JSON.parse(output).fetch(0)
  end

  def interpreted_command(command)
    interpreted_invocation(command).fetch('arguments')
  end

  def lifecycle_result(mode, count: 1)
    skip 'The process-reaping fixture requires POSIX waitpid' if Gem.win_platform?

    fixture = File.expand_path('../../../../file_fixtures/python_exec/lifecycle.py', __dir__)
    programs = count.times.map do |index|
      payload.datastore['CMD'] = 'exec ' + Shellwords.join([python, fixture, 'child', mode, index.to_s])
      payload.generate
    end
    output, error, status = Open3.capture3(python, fixture, stdin_data: { payloads: programs }.to_json)
    raise "Generated payload lifecycle failed: #{error}" unless status.success?

    result = JSON.parse(output)
    if ENV['PYTHON_EXEC_ARTIFACTS']
      File.write(File.join(ENV.fetch('PYTHON_EXEC_ARTIFACTS'), "#{mode}-#{count}.json"), JSON.pretty_generate(result))
    end
    result
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

  it 'preserves shell dispatch and all three PIPE arguments' do
    expect(interpreted_invocation('printf ordinary').fetch('options')).to eq('shell' => true, 'stdin' => -1, 'stdout' => -1, 'stderr' => -1)
  end

  it 'returns before completion and automatically reaps a real completed child and its pipes' do
    result = lifecycle_result('quick')

    expect(result).to include('errors' => [], 'waiters_daemon' => true, 'waiters_finished' => true, 'invokers_finished' => true, 'descriptors_preserved' => true, 'cleanup_descriptors_preserved' => true, 'no_children_after_cleanup' => true)
    expect(result.fetch('records')).to match([include('returned_before_release' => true, 'completion' => include('complete' => true), 'reaping' => include('automatic' => true), 'proof_base64' => Base64.strict_encode64("python-exec-\x00\xe2\x98\x83\r\n".b))])
  end

  it 'closes stdin and drains real stdout and stderr beyond pipe capacity before reaping' do
    result = lifecycle_result('pipes')

    expect(result).to include('errors' => [], 'descriptors_preserved' => true, 'cleanup_descriptors_preserved' => true, 'no_children_after_cleanup' => true)
    expect(result.fetch('records')).to match([include('returned_before_release' => true, 'completion' => include('complete' => true, 'stdin_eof' => true), 'reaping' => include('automatic' => true))])
  end

  it 'reaps two overlapping real commands independently in one persistent namespace' do
    result = lifecycle_result('quick', count: 2)

    expect(result).to include('errors' => [], 'waiters_daemon' => true, 'waiters_finished' => true, 'invokers_finished' => true, 'descriptors_preserved' => true, 'cleanup_descriptors_preserved' => true, 'no_children_after_cleanup' => true)
    expect(result.fetch('records')).to all(include('returned_before_release' => true, 'completion' => include('complete' => true), 'reaping' => include('automatic' => true)))
    expect(result.fetch('records').map { |row| row.fetch('process').fetch('pid') }.uniq.length).to eq(2)
  end
end
