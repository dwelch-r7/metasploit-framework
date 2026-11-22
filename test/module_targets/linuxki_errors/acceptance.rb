# frozen_string_literal: true

require_relative '../linuxki/acceptance'

# Real Apache statuses and a refused target socket exercise check error paths.
module LinuxkiErrorTarget
  include LinuxkiTarget

  def lk_error_check(label, options, status: nil)
    call = lk_call(label, options)
    events = call.fetch(:events)
    if status
      expect(events.filter_map { |row| row['response']&.fetch('code') }).to eq([status])
    end
    checks = events.filter_map { |row| row['check'] }
    expect(checks.length).to eq(1)
    expect(checks.first).to include('code' => 'unknown', 'reason' => a_string_matching(/\S/))
    expect(events.select { |row| row['error']&.fetch('type') == 'Msf::Exploit::Failed' }).to eq([])
    expect(events.select { |row| row['owner_exploit_body'] }).to eq([])
  end

  def lk_status_control(prefix, expected)
    endpoint = target_endpoint('target')
    uri = URI::HTTP.build(host: endpoint.fetch('host'), port: endpoint.fetch('port'), path: prefix + LinuxkiTarget::PAGE)
    response = Net::HTTP.start(uri.hostname, uri.port, nil, open_timeout: 5, read_timeout: 5) { |http| http.get(uri.request_uri) }
    @rc[:native_http] << { label: 'native-status', uri: uri.to_s, code: response.code.to_i, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    rc_save
    expect(response.code.to_i).to eq(expected)
  end

  def lk_missing
    prefix = '/module-target-missing'
    lk_status_control(prefix, 404)
    lk_error_check('missing-page', { 'TARGETURI' => prefix }, status: 404)
  end

  def lk_forbidden
    prefix = '/module-target-denied-' + Process.pid.to_s
    path = '/var/www/html' + prefix
    rc_command('create-denied-directory', 'target', 'mkdir', path)
    rc_command('link-genuine-page', 'target', 'ln', '-s', '/opt/linuxki', path + '/linuxki')
    rc_command('deny-traversal', 'target', 'chmod', '000', path)
    lk_status_control(prefix, 403)
    lk_error_check('forbidden-page', { 'TARGETURI' => prefix }, status: 403)
  ensure
    if path
      rc_command('restore-traversal', 'target', 'chmod', '755', path)
      rc_command('remove-genuine-link', 'target', 'rm', '-f', path + '/linuxki')
      rc_command('remove-denied-directory', 'target', 'rmdir', path)
    end
  end

  def lk_refused_socket
    endpoint = target_runtime.fetch('module_endpoints').fetch('target')
    control = rc_json("begin;socket=TCPSocket.new(#{endpoint.fetch('host').inspect},1);socket.close;{refused:false};rescue Errno::ECONNREFUSED;{refused:true};end")
    @rc[:refused_socket_control] = control
    rc_save
    expect(control).to eq('refused' => true)
    lk_error_check('refused-socket', { 'RPORT' => 1, 'TARGETURI' => '/', 'HttpClientTimeout' => 2 })
  end
end
