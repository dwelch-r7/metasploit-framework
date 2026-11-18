require 'msfenv'
require 'msf/base'
require 'msf/util/python_deserialization'
require 'rex/text'
require 'open3'

if ENV['PYTHON_DESERIALIZATION_SOURCE']
  Msf::Util.send(:remove_const, :PythonDeserialization)
  load ENV.fetch('PYTHON_DESERIALIZATION_SOURCE')
end

RSpec.describe Msf::Util::PythonDeserialization do
  let(:python) { ENV.fetch('PYTHON', 'python3') }
  let(:executor) { File.expand_path('../../../file_fixtures/python_deserialization/execute.py', __dir__) }
  let(:export_code) do
    # Minimal form of the real Meterpreter EXPORTED_SYMBOLS/export decorator
    # that raised NameError from Thread.run in pgAdmin's Python 3.11 runtime.
    <<~PYTHON
      EXPORTED_SYMBOLS = {}
      def export(symbol):
          EXPORTED_SYMBOLS[symbol.__name__] = symbol
          return symbol
      @export
      def marker():
          return 'registered'
      print(EXPORTED_SYMBOLS['marker']())
    PYTHON
  end

  # Pickle loading, builtin exec, standard threads and Python are real. No
  # transport/session doubles or callbacks run. Child threads have bounded joins
  # and the parent bounds/reaps the interpreter. Python 3 must be available.
  def python_result(request)
    Open3.popen3(python, executor) do |input, output, error, process|
      input.write(request.to_json)
      input.close
      unless process.join(8)
        Process.kill('KILL', process.pid)
        process.join
        raise 'Python deserialization contract exceeded eight seconds'
      end
      stdout = output.read
      stderr = error.read
      raise "Python deserialization contract failed: #{stderr}" unless process.value.success?

      JSON.parse(stdout)
    end
  end

  def execute(code, name: :py3_exec_threaded, repeat: 1, release: false)
    serialized = Array.new(repeat) { Base64.strict_encode64(described_class.payload(name, code)) }
    python_result('payloads' => serialized, 'release' => release)
  end

  it 'retains the public payload names' do
    expect(described_class.payload_names).to eq(%i[py3_exec py3_exec_threaded])
  end

  it 'rejects an unknown payload name' do
    expect { described_class.payload(:unknown, 'pass') }.to raise_error(ArgumentError, 'unknown payload not found in payloads')
  end

  it 'keeps the in-place protocol-zero payload bytes unchanged' do
    expect(described_class.payload(:py3_exec, "print('canary')")).to eq("c__builtin__\nexec\np0\n(Vprint('canary')\np1\ntp2\nRp3\n.")
  end

  it 'accepts the threaded payload name as a string' do
    expect(described_class.payload('py3_exec_threaded', 'pass')).to eq(described_class.payload(:py3_exec_threaded, 'pass'))
  end

  it 'matches the reference generator behavior for a top-level registry' do
    source = ENV.fetch('PYTHON_DESERIALIZATION_GENERATOR', File.expand_path('../../../../external/source/python_deserialization/py3_exec_threaded.py', __dir__))
    reference = python_result('generator' => source, 'code' => export_code)
    generated_result = python_result('payloads' => [reference.fetch('payload')])

    expect([execute(export_code), generated_result].map { |result| result.values_at('stdout', 'errors', 'alive') }).to eq([
      ["registered\n", [], []], ["registered\n", [], []]
    ])
  end

  %i[py3_exec py3_exec_threaded].each do |name|
    it "executes a simple command with #{name}" do
      result = execute("print('simple-canary')", name: name)

      expect(result.values_at('stdout', 'errors', 'returns', 'alive')).to eq(["simple-canary\n", [], [nil], []])
    end
  end

  it 'lets the actual export decorator resolve the top-level registry' do
    result = execute(export_code)

    expect(result.values_at('stdout', 'errors', 'alive')).to eq(["registered\n", [], []])
  end

  it 'preserves the registry through the actual compressed Python exec stub' do
    result = execute(Msf::Payload::Python.create_exec_stub(export_code))

    expect(result.values_at('stdout', 'errors', 'alive')).to eq(["registered\n", [], []])
  end

  it 'lets a function resolve a module imported at top level' do
    result = execute("import math\ndef answer():\n    return math.isqrt(1764)\nprint(answer())")

    expect(result.values_at('stdout', 'errors')).to eq(["42\n", []])
  end

  it 'lets a class method resolve top-level data' do
    result = execute("VALUE = 'class-canary'\nclass Example:\n    def value(self):\n        return VALUE\nprint(Example().value())")

    expect(result.values_at('stdout', 'errors')).to eq(["class-canary\n", []])
  end

  it 'uses the same dictionary for globals and locals' do
    expect(execute('print(globals() is locals())').fetch('stdout')).to eq("True\n")
  end

  it 'isolates repeated invocations in fresh namespaces' do
    result = execute("global _msf_deser_counter\n_msf_deser_counter = globals().get('_msf_deser_counter', 0) + 1\nprint(_msf_deser_counter)", repeat: 2)

    expect(result.values_at('stdout', 'errors')).to eq(["1\n1\n", []])
  end

  it 'does not add payload globals to the threading module' do
    result = execute("global _msf_namespace_canary\n_msf_namespace_canary = 'canary'")

    expect(result.fetch('threading_keys_added')).to be_empty
  end

  it 'retains builtin access in the explicit namespace' do
    expect(execute('print(len([1, 2, 3]))').fetch('stdout')).to eq("3\n")
  end

  it 'preserves backslashes and line breaks in command code' do
    result = execute("text = 'line\\nnext'\r\nprint(text)")

    expect(result.values_at('stdout', 'errors')).to eq(["line\nnext\n", []])
  end

  it 'returns from unpickling while the worker is still waiting' do
    code = <<~PYTHON
      import builtins
      builtins._msf_deserialization_started.set()
      if not builtins._msf_deserialization_release.wait(2):
          raise RuntimeError('Unpickling blocked on the worker')
      print('released')
    PYTHON
    result = execute(code, release: true)

    expect(result.values_at('stdout', 'errors', 'returns', 'alive')).to eq(["released\n", [], [nil], []])
  end

  it 'keeps a worker exception in the normal thread exception path' do
    result = execute("raise ValueError('unit-error')")

    expect(result.values_at('errors', 'returns', 'alive')).to eq([[{ 'type' => 'ValueError', 'message' => 'unit-error' }], [nil], []])
  end
end
