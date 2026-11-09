# frozen_string_literal: true

require 'json'
require 'open3'

# Vendor CLI, Erlang RPC and Pika controls, independent of Framework.
class NativeRabbitProbe
  def initialize
    @runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
    @records = { profiles: {}, commands: [] }
  end

  def run
    { 'old' => ['3.8.16', '24'], 'new' => ['3.12.14', '25'] }.each do |service, (version, otp)|
      actual = command(service, 'rabbitmq-diagnostics', '-q', 'server_version').strip
      raise "RabbitMQ version mismatch: #{actual}" unless actual == version

      runtime = erl(service, 'io:format("OTP=~s ERTS=~s~n", [erlang:system_info(otp_release), erlang:system_info(version)])')
      raise 'OTP version mismatch' unless runtime.include?("OTP=#{otp} ")

      users = command(service, 'rabbitmqctl', '-q', 'list_users', '--formatter=json')
      permissions = command(service, 'rabbitmqctl', '-q', 'list_permissions', '-p', '/', '--formatter=json')
      raise 'Native users mismatch' unless JSON.parse(users).map { |row| row.fetch('user') }.sort == %w[guest lab-amqp-limited lab-amqp-user]
      raise 'Limited user unexpectedly has root vhost access' if JSON.parse(permissions).any? { |row| row.fetch('user') == 'lab-amqp-limited' }

      ca = command(service, 'cat', '/opt/module-target-certificates/server.crt')
      amqp = [false, true].to_h do |tls|
        cases = {
          'valid' => ['lab-amqp-user', 'module-target-amqp-password', '/', true],
          'wrong' => ['lab-amqp-user', 'wrong-password', '/', false],
          'limited_root' => ['lab-amqp-limited', 'module-target-limited-password', '/', false],
          'limited_allowed' => ['lab-amqp-limited', 'module-target-limited-password', 'module-target', true],
          'guest_remote' => ['guest', 'guest', '/', false]
        }.to_h do |kind, (username, password, vhost, success)|
          input = { host: service, tls: tls, ca: ca, username: username, password: password, vhost: vhost }
          result = JSON.parse(command('client', 'python', '/opt/module-target-client.py', input: input))
          raise "Native #{service} #{kind} TLS=#{tls} policy mismatch" unless result.fetch('connected') == success

          raise 'Native TLS negotiation mismatch' if tls && result.fetch('start').fetch('tls') != 'TLSv1.2'

          if success && !(result.fetch('properties').fetch('product') == 'RabbitMQ' && result.fetch('properties').fetch('version') == version)
            raise 'Native AMQP identity mismatch'
          end

          [kind, result]
        end
        [tls ? 'tls' : 'plain', cases]
      end
      distribution = [true, false].to_h do |legacy|
        result = JSON.parse(command('client', 'python', '/opt/module-target-distribution.py', input: { host: service, legacy: legacy, cookie: 'MODULE_TARGET_ERLANG_COOKIE' }))
        raise 'Native distribution handshake mismatch' unless result.fetch('authenticated') == (!legacy || service == 'old')

        [legacy ? 'legacy' : 'v6', result]
      end
      wrong = JSON.parse(command('client', 'python', '/opt/module-target-distribution.py', input: { host: service, legacy: false, cookie: 'WRONG_MODULE_TARGET_COOKIE' }))
      raise 'Native broker accepted wrong distribution cookie' if wrong.fetch('authenticated')

      rpc = 2.times.map do |index|
        path = "/tmp/module-target-native-rpc-#{index}"
        command(service, 'test', '!', '-e', path)
        value = remote(service, "rpc:call('rabbit@#{service}', os, cmd, [\"touch #{path}; id -un\"])")
        raise 'Native remote command identity mismatch' unless value.include?('rabbitmq')

        owner = command(service, 'stat', '-c', '%U', path).strip
        raise 'Native command file owner mismatch' unless owner == 'rabbitmq'

        command(service, 'rm', path)
        { output: value, owner: owner }
      end
      rejected = remote(service, "net_adm:ping('rabbit@#{service}')", cookie: 'WRONG_MODULE_TARGET_COOKIE')
      raise 'Native Erlang accepted wrong cookie' unless rejected.include?('pang')

      queues = command(service, 'rabbitmqctl', '-q', 'list_queues', '-p', '/', 'name', '--formatter=json')
      raise 'Native AMQP queue leaked' unless JSON.parse(queues).empty?

      @records[:profiles][service] = { version: actual, runtime: runtime, users: JSON.parse(users), permissions: JSON.parse(permissions), amqp: amqp, distribution: distribution, rejected_cookie: wrong, rpc: rpc, rejected_rpc: rejected, queues: JSON.parse(queues) }
    end
    @records
  ensure
    File.write(File.join(@runtime.fetch('artifacts'), 'native-rabbitmq-partial.json'), JSON.pretty_generate(@records))
  end

  private

  def command(service, *arguments, input: nil)
    stdout, stderr, status = Open3.capture3(*@runtime.fetch('compose'), 'exec', '-T', service, *arguments, stdin_data: input ? JSON.generate(input) : '')
    @records[:commands] << { service: service, argv: arguments, input: input, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
    raise "Native command failed: #{service} #{arguments.inspect}: #{stderr}#{stdout}" unless status.success?

    stdout
  end

  def erl(service, expression, *options)
    command(service, 'erl', '+S', '1:1', '+A', '1', '-noshell', *options, '-eval', "#{expression}, halt().")
  end

  def remote(service, expression, cookie: 'MODULE_TARGET_ERLANG_COOKIE')
    result = "io:format(\"RPC=~p~n\", [#{expression}])"
    erl(service, result, '-sname', 'module_native', '-setcookie', cookie)
  end
end

puts JSON.pretty_generate(NativeRabbitProbe.new.run) if $PROGRAM_NAME == __FILE__
