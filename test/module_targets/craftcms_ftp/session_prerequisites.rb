# frozen_string_literal: true

# The acceptance process runs on the host, while the listener lives on the
# isolated Compose network. Run the small native HTTP receiver in that listener.
module CraftFtpSessionPrerequisites
  def cf_port
    rc_json("begin;socket=TCPServer.new('0.0.0.0',0);port=socket.local_address.ip_port;socket.close;port;end")
  end

  def cf_native_fetch(arch, tool)
    executable = File.join(target_runtime.fetch('artifacts'), "ftp-native-exit#{arch}")
    command = ['nasm', '-f', 'bin', "-DARCH=#{arch}", 'test/module_targets/druid_sessions/native_exit.asm', '-o', executable]
    output, error, status = Open3.capture3(*command)
    @rc.fetch(:commands) << { label: 'assemble-native-ftp-elf', argv: command, exit: status.exitstatus, stdout_base64: Base64.strict_encode64(output.b), stderr: error }
    expect(status.success?).to be(true), output + error
    bytes = File.binread(executable)
    expect(bytes.byteslice(0, 5)).to eq("\x7fELF".b + (arch == 32 ? 1 : 2).chr)
    setup = <<~RUBY
      begin
        bytes=File.binread(#{executable.inspect});server=TCPServer.new('0.0.0.0',0)
        state={server:server,port:server.local_address.ip_port}
        state[:thread]=Thread.new do
          peer=nil
          begin
            Timeout.timeout(12) do
              peer=server.accept;request=String.new
              request << peer.readpartial(4096) until request.include?("\\r\\n\\r\\n")
              peer.write("HTTP/1.1 200 OK\\r\\nContent-Length: " + bytes.bytesize.to_s + "\\r\\nConnection: close\\r\\n\\r\\n" + bytes)
              state[:request]=request
            end
          rescue StandardError => error
            state[:error]={type:error.class.name,message:error.message}
          ensure
            peer.close if peer;server.close
          end
        end
        framework.instance_variable_set(:@craft_ftp_native_http,state)
        {port:state[:port],sha256:Digest::SHA256.hexdigest(bytes)}
      end
    RUBY
    File.binwrite(File.join(target_runtime.fetch('artifacts'), "native-http-receiver#{arch}.rb"), setup)
    server = rc_json("eval(Base64.strict_decode64(#{Base64.strict_encode64(setup).inspect}))")
    expect(server.fetch('sha256')).to eq(Digest::SHA256.hexdigest(bytes))
    destination = "/tmp/module-target-ftp-native-fetch-#{Process.pid}-#{arch}"
    absent = !it_file(destination).fetch('exists')
    expect(absent).to be(true)
    url = "http://#{listener_host}:#{server.fetch('port')}/native-exit#{arch}"
    if tool == 'curl'
      rc_command('native-ftp-fetch-curl', 'app', 'curl', '--fail', '--silent', '--show-error', '--max-time', '8', url, '-o', destination)
    else
      rc_command('native-ftp-fetch-wget', 'app', 'wget', '-q', '-T', '8', '-O', destination, url)
    end
    rc_command('native-ftp-fetch-chmod', 'app', 'chmod', '755', destination)
    code = 'import hashlib,json,os,subprocess,sys;from pathlib import Path;p=Path(sys.argv[1]);r=subprocess.run([str(p)],timeout=3);print(json.dumps({"uid":os.geteuid(),"exit":r.returncode,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}))'
    output, = rc_command('native-ftp-fetch-execute', 'app', 'python3', '-c', code, destination)
    result = JSON.parse(output)
    expect(result).to eq('uid' => it_expected_uid, 'exit' => 42, 'sha256' => Digest::SHA256.hexdigest(bytes))
    response = rc_json('begin;state=framework.instance_variable_get(:@craft_ftp_native_http);state[:thread].join(2);{request:state[:request],error:state[:error],alive:state[:thread].alive?};end')
    expect(response).to include('error' => nil, 'alive' => false)
    expect(response.fetch('request')).to start_with("GET /native-exit#{arch} HTTP/1.1\r\n")
    @rc[:ftp_native_fetch] ||= []
    @rc[:ftp_native_fetch] << { arch: arch, tool: tool, result: result, receiver: response }
  ensure
    if absent
      rc_command('native-ftp-fetch-remove', 'app', 'rm', '-f', destination)
      expect(it_file(destination).fetch('exists')).to be(false)
    end
    if server
      rc_json('begin;state=framework.instance_variable_get(:@craft_ftp_native_http);state[:server].close unless state[:server].closed?;state[:thread].kill if state[:thread].alive?;state[:thread].join;{alive:state[:thread].alive?};end')
    end
    rc_save
  end
end
