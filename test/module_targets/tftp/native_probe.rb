# frozen_string_literal: true

require 'base64'
require 'json'
require 'open3'
require 'resolv'
require 'socket'

runtime = ENV['MODULE_TARGET_RUNTIME'] && JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
compose = runtime ? runtime.fetch('compose') : ['docker', 'compose', '-p', ARGV.fetch(0), '-f', File.join(__dir__, 'compose.yaml')]
commands = []
files = {}
run = lambda do |service, *arguments|
  stdout, stderr, status = Open3.capture3(*compose, 'exec', '-T', service, 'timeout', '8', *arguments)
  stdout.force_encoding(Encoding::UTF_8)
  stderr.force_encoding(Encoding::UTF_8)
  raise "Native text output is not UTF-8: #{service}" unless stdout.valid_encoding? && stderr.valid_encoding?

  commands << { service: service, argv: arguments, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
  raise "Native command timed out: #{service} #{arguments.inspect}" if status.exitstatus == 124

  [stdout, stderr, status.exitstatus]
end
begin
  version, error, code = run.call('tftp', '/usr/sbin/in.tftpd', '-V')
  raise "Unexpected TFTP implementation: #{version} #{error}" unless code.zero? && (version + error).include?('tftp-hpa 5.2')

  run.call('tftp', 'dpkg-query', '-W', 'tftpd-hpa', 'tftp-hpa')
  permissions, error, code = run.call('tftp', 'stat', '-c', '%a %U', '/srv/tftp/denied.txt')
  raise "Denied fixture permissions differ: #{permissions} #{error}" unless code.zero? && permissions.strip == '600 root'

  identity, error, code = run.call('tftp', 'su', '-s', '/bin/sh', '-c', 'id -un; test -r /srv/tftp/denied.txt', 'tftp')
  raise "Native server user can read denied fixture: #{identity} #{error}" unless code == 1 && identity.strip == 'tftp' && error.empty?

  %w[public.txt empty.txt large.bin nested/inside.txt café.txt].each do |name|
    %w[octet netascii].each do |mode|
      # NUL-only large data and LF-only text are byte-stable after netascii's
      # round-trip conversion, so a native comparison covers both modes.
      destination = '/tmp/module-target-native-copy'
      run.call('tftp', 'rm', '-f', destination)
      stdout, stderr, code = run.call('tftp', 'tftp', '-m', mode, '127.0.0.1', '-c', 'get', name, destination)
      raise "Native #{mode} TFTP failed: #{name}: #{stdout} #{stderr}" unless code.zero? && stdout.empty? && stderr.empty?

      _, _, compared = run.call('tftp', 'cmp', '-s', destination, "/srv/tftp/#{name}")
      raise "Native #{mode} transfer bytes differ: #{name}" unless compared.zero?

      sha, stderr, code = run.call('tftp', 'sha256sum', destination)
      raise "Native transfer hash unavailable: #{stderr}" unless code.zero?

      files[name] ||= {}
      files.fetch(name)[mode] = sha.split.first
      run.call('tftp', 'rm', '-f', destination)
    end
  end
  %w[missing.txt denied.txt].each do |name|
    destination = '/tmp/module-target-native-denied'
    run.call('tftp', 'rm', '-f', destination)
    stdout, stderr, code = run.call('tftp', 'tftp', '-m', 'octet', '127.0.0.1', '-c', 'get', name, destination)
    response = stdout + stderr
    expected = name == 'missing.txt' ? /File not found/i : /(?:Access violation|Permission denied)/i
    raise "Native TFTP did not enforce #{name}: #{code}: #{response}" unless response.match?(expected)

    files[name] = { response: response, exitstatus: code }
    run.call('tftp', 'rm', '-f', destination)
  end
  # A real DNS answer also verifies UDP publication/discovery on the host.
  # TFTP's subsequent transfer ID uses another port, so its complete native
  # transfers above intentionally stay in the owned container namespace.
  endpoint = runtime && runtime.fetch('endpoints').fetch('unrelated')
  unless endpoint
    binding, status = Open3.capture2(*compose, 'port', '--protocol', 'udp', 'unrelated', '53')
    raise 'Cannot find the published DNS UDP port' unless status.success?

    host, port = binding.strip.split(':')
    endpoint = { 'host' => host, 'port' => port.to_i }
  end
  query = Resolv::DNS::Message.new(0x1234)
  query.add_question('module-target.test', Resolv::DNS::Resource::IN::A)
  socket = UDPSocket.new
  begin
    socket.send(query.encode, 0, endpoint.fetch('host'), endpoint.fetch('port'))
    raise 'Published UDP DNS did not respond' unless IO.select([socket], nil, nil, 3)

    bytes, = socket.recvfrom(65_535)
    answer = Resolv::DNS::Message.decode(bytes)
    addresses = []
    answer.each_answer { |_name, _ttl, resource| addresses << resource.address.to_s if resource.is_a?(Resolv::DNS::Resource::IN::A) }
    raise "Wrong native UDP DNS data: #{addresses.inspect}" unless answer.id == query.id && addresses == ['192.0.2.10']

    files['unrelated_dns'] = { endpoint: endpoint, request_hex: query.encode.unpack1('H*'), response_hex: bytes.unpack1('H*'), addresses: addresses }
  ensure
    socket.close
  end
ensure
  puts JSON.pretty_generate(files: files, commands: commands)
end
