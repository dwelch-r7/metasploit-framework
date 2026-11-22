# frozen_string_literal: true

require 'base64'
require 'json'
require 'open3'
require 'shellwords'
require 'socket'
require 'timeout'

# Vendor Erlang and real EPMD controls; no Framework protocol implementation.
class NativeCouchdbErlangProbe
  def initialize(node: ENV.fetch('MODULE_TARGET_COUCHDB_NODE', 'couchdb@127.0.0.1'))
    raise ArgumentError, 'Unexpected native CouchDB node name' unless node.match?(/\Acouchdb@[a-z0-9.-]+\z/)

    @node = "'#{node}'"
    @runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
    @records = { commands: [], proofs: [] }
  end

  def run
    @records[:http] = JSON.parse(command('curl', '--fail', '--silent', 'http://127.0.0.1:5984/'))
    raise 'Native CouchDB identity mismatch' unless @records[:http].fetch('version') == '3.2.1'

    @erl = command('sh', '-c', 'find /opt/couchdb -type f -path "*/bin/erl" -print -quit').strip
    @boot = '/opt/couchdb/releases/3.2.1/start_clean'
    command('test', '-f', @boot + '.boot')
    command('sh', '-c', 'test "$(cat /opt/couchdb/.erlang.cookie)" = monster')
    @records[:vm_args] = command('cat', '/opt/couchdb/etc/vm.args')
    @records[:node] = node = @node.delete("'")
    raise 'Native CouchDB configured node mismatch' unless @records[:vm_args].lines.any? { |line| line.strip == "-name #{node}" }

    @records[:runtime] = remote("io:format(\"IDENTITY=~p~n\", [rpc:call(#{@node},erlang,system_info,[system_version])])")
    raise 'Native Erlang identity mismatch' unless @records[:runtime].include?('Erlang/OTP 23')

    @records[:wrong_cookie] = remote("io:format(\"PING=~p~n\", [net_adm:ping(#{@node})])", cookie: 'wrong-module-target-cookie')
    raise 'Native wrong cookie was accepted' unless @records[:wrong_cookie].include?('PING=pang')

    endpoint = @runtime.fetch('endpoints').fetch('target')
    Socket.tcp(endpoint.fetch('host'), endpoint.fetch('port'), connect_timeout: 5) do |socket|
      socket.write("\x00\x01n")
      @records[:epmd] = Timeout.timeout(5) { socket.read }
    end
    raise 'Native EPMD identity/port mismatch' unless @records[:epmd].include?('name couchdb at port 9100')

    2.times do |index|
      path = "/tmp/module-target-couchdb-native-#{index}"
      value = "Native 'quote' \"double\" é λ 💥\r\nsecond line\n"
      command('test', '!', '-e', path)
      begin
        rpc('printf %s ' + Shellwords.escape(value) + ' > ' + path)
        actual = command('cat', path)
        owner = command('stat', '-c', '%u', path).strip
        raise 'Native command bytes/UID mismatch' unless actual.b == value.b && owner == '5984'

        @records[:proofs] << { path: path, bytes: Base64.strict_encode64(actual), uid: owner }
      ensure
        command('rm', '-f', path)
      end
    end
    @records[:tools] = command('sh', '-c', 'for tool in sh bash openssl wget curl chmod base64; do printf "%s=" "$tool"; command -v "$tool" || :; done')
    @records[:passed] = true
    @records
  ensure
    File.write(File.join(@runtime.fetch('artifacts'), 'native-couchdb-erlang-partial.json'), JSON.pretty_generate(@records))
  end

  def command(*arguments)
    stdout, stderr, status = Open3.capture3(*@runtime.fetch('compose'), 'exec', '-T', 'target', *arguments)
    @records[:commands] << { argv: arguments, stdout: stdout, stderr: stderr, exit: status.exitstatus }
    raise "Native operation failed: #{arguments.inspect}: #{stderr}" unless status.success?

    stdout
  end

  def remote(expression, cookie: 'monster')
    command(@erl, '-boot', @boot, '+S', '1:1', '+A', '1', '-noshell', '-name', 'native@127.0.0.1', '-setcookie', cookie, '-eval', expression + ',halt().')
  end

  def rpc(value)
    encoded = Base64.strict_encode64(value.b)
    remote("[] = rpc:call(#{@node},os,cmd,[unicode:characters_to_list(base64:decode(#{encoded.inspect}))])")
  end
end

puts JSON.pretty_generate(NativeCouchdbErlangProbe.new.run) if $PROGRAM_NAME == __FILE__
