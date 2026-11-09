# frozen_string_literal: true

require 'json'
require 'base64'
require 'open3'

# Vendor Erlang performs legacy rex RPCs and receives each real completion.
# The benign executable is a visible shell script, not a simulated service.
runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
records = []
begin
  %w[old new].each do |service|
    2.times do |index|
      path = "/tmp/module-target-native-launch-#{index}"
      active = "#{path}-active"
      script = "#!/bin/sh\necho $$ > #{active}\nsleep 5\n"
      create = "printf '%s' '#{Base64.strict_encode64(script)}' | base64 -d > #{path}; chmod 700 #{path}"
      program = <<~ERLANG
        Node = 'rabbit@#{service}',
        pong = net_adm:ping(Node),
        {ok, Initial} = rpc:call(Node, file, list_dir, ["/tmp"]),
        Before = lists:sort(Initial),
        Send = fun(Command) ->
          {rex, Node} ! {self(), {call, os, cmd, [Command], user}},
          receive {rex, Reply} -> Reply after 5000 -> erlang:error(completion_timeout) end
        end,
        [] = Send(#{JSON.generate(create)}),
        "rabbitmq\\n" = Send("stat -c %U #{path}"),
        {Elapsed, "\\n"} = timer:tc(Send, ["#{path} & echo"]),
        true = Elapsed < 1000000,
        Wait = fun Again(0) -> erlang:error(active_timeout);
                   Again(Attempts) ->
                     case rpc:call(Node, file, read_file, ["#{active}"]) of
                       {ok, PidBytes} -> PidBytes;
                       _ -> timer:sleep(10), Again(Attempts - 1)
                     end
               end,
        Pid = string:trim(binary_to_list(Wait(100))),
        "alive" = Send("test -d /proc/" ++ Pid ++ " && printf alive"),
        [] = Send("rm -f #{path} #{active}"),
        {ok, Final} = rpc:call(Node, file, list_dir, ["/tmp"]),
        Before = lists:sort(Final),
        io:format("NATIVE_BACKGROUND=~p~n", [{Elapsed, Pid, Before}]),
        halt().
      ERLANG
      argv = runtime.fetch('compose') + ['exec', '-T', service, 'erl', '+S', '1:1', '+A', '1', '-noshell', '-sname', 'native_completion', '-setcookie', 'MODULE_TARGET_ERLANG_COOKIE', '-eval', program]
      stdout, stderr, status = Open3.capture3(*argv)
      records << { service: service, repeat: index, source: script, argv: argv, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
      raise "Native background/cleanup failed on #{service}: #{stderr}#{stdout}" unless status.success? && stdout.include?('NATIVE_BACKGROUND=')
    end
  end
  puts JSON.pretty_generate(records)
ensure
  File.write(File.join(runtime.fetch('artifacts'), 'native-completion-partial.json'), JSON.pretty_generate(records))
end
