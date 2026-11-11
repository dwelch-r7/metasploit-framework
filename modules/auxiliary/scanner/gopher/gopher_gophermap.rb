##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/stopwatch'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Gopher gophermap Scanner',
      'Description' => %q(
        This module identifies Gopher servers, and processes the gophermap
        file which lists all the files on the server.
      ),
      'References' => [
        ['URL', 'https://sdfeu.org/w/tutorials:gopher']
      ],
      'Author' => 'h00die',
      'License' => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(70),
        OptString.new('PATH', [false, 'Path to enumerate', ''])
      ]
    )

    register_advanced_options([
      OptInt.new('GopherReadTimeout', [true, 'Maximum seconds to read a complete Gopher menu', 10]),
      OptInt.new('GopherMaxBytes', [true, 'Maximum bytes in a complete Gopher menu', 1024 * 1024])
    ])
  end

  TYPE_MAP = {
    '0' => 'Text file',
    '1' => 'Directory',
    '2' => 'CSO name server',
    '3' => 'Error',
    '4' => 'Mac HQX filer',
    '5' => 'PC binary',
    '6' => 'UNIX uuencoded file',
    '7' => 'Search server',
    '8' => 'Telnet Session',
    '9' => 'Binary File',
    'c' => 'Calendar',
    'e' => 'Event',
    'g' => 'GIF image',
    'h' => 'HTML',
    'i' => 'inline text',
    's' => 'Sound',
    'I' => 'Image',
    'M' => 'MIME multipart/mixed message',
    'T' => 'TN3270 Session'
  }.freeze

  def get_type(char)
    TYPE_MAP.fetch(char.chomp, nil)
  end

  def run_host(ip)
    unless datastore['GopherReadTimeout'].positive? && datastore['GopherMaxBytes'].positive?
      fail_with(Failure::BadConfig, 'GopherReadTimeout and GopherMaxBytes must be positive')
    end

    connect
    sock.put("#{datastore['PATH']}\r\n")
    gophermap = read_gophermap
    unless gophermap
      vprint_error('Failed to read a complete Gopher menu within the configured limits')
      return
    end

    rows = gopher_rows(gophermap)
    unless rows
      vprint_error('Target did not return a valid Gopher menu')
      return
    end

    rows.each { |row| print_gopher_row(row) }
    report_service(host: ip, port: rport, name: 'gopher', info: gophermap)
  rescue Rex::ConnectionError, Rex::TimeoutError, ::Timeout::Error, ::IOError, ::Errno::ECONNRESET => e
    vprint_error("Failed to read Gopher menu: #{e.message}")
    elog('Gopher menu request failed', error: e)
  ensure
    disconnect
  end

  private

  def read_gophermap
    remaining = datastore['GopherReadTimeout']
    maximum = datastore['GopherMaxBytes']
    response = String.new.b

    # RFC 1436 ends menus with a dot line; TCP receive blocks are not messages.
    # https://www.rfc-editor.org/rfc/rfc1436.html
    loop do
      return nil if remaining <= 0

      data, elapsed = Rex::Stopwatch.elapsed_time do
        sock.get_once([sock.def_block_size, maximum - response.bytesize + 1].min, remaining)
      end
      remaining -= elapsed
      return nil if remaining.negative? || data.nil? || data.empty?

      response << data
      return nil if response.bytesize > maximum
      return response if response == ".\r\n" || response.end_with?("\r\n.\r\n")
      return nil if response.bytesize == maximum
    end
  rescue EOFError
    nil
  end

  def gopher_rows(gophermap)
    payload = gophermap.delete_suffix(".\r\n")
    return [] if payload.empty?

    rows = payload.delete_suffix("\r\n").split("\r\n", -1).map do |line|
      fields = line.split("\t", -1)
      return nil if fields.length < 2 || fields.first.empty? || line.match?(/[\x00\r\n]/)
      return nil unless fields.first.getbyte(0).between?(33, 126)

      port = fields[3]
      return nil if port.present? && (!port.match?(/\A\d{1,5}\z/) || port.to_i > 65_535)

      fields
    end
    rows
  end

  def print_gopher_row(fields)
    type_char = fields.first[0]
    desc = fields.first[1..]
    file_type = get_type(type_char)
    if file_type == 'inline text'
      print_good(desc)
      return
    end

    print_good(file_type ? "  #{file_type}: #{desc}" : "  Invalid File Type (#{type_char}): #{desc}")
    if fields.length >= 3
      authority = fields[3].present? ? Rex::Socket.to_authority(fields[2], fields[3]) : "#{fields[2]}:"
      print_good("    Path: #{authority}#{fields[1]}")
    else
      print_good("    Path: #{fields[1]}")
    end
  end
end
