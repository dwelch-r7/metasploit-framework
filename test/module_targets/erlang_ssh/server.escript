#!/usr/bin/env escript
%%! +S 1:1 +A 1 +SDcpu 1:1 +SDio 1 -noshell
main(_) ->
    {ok, _} = application:ensure_all_started(ssh),
    Dir = "/tmp/module-target-erlang/keys",
    ok = filelib:ensure_dir(Dir ++ "/placeholder"),
    Key = public_key:generate_key({rsa, 2048, 65537}),
    Pem = public_key:pem_encode([public_key:pem_entry_encode('RSAPrivateKey', Key)]),
    ok = file:write_file(Dir ++ "/ssh_host_rsa_key", Pem),
    ok = file:change_mode(Dir ++ "/ssh_host_rsa_key", 8#600),
    Banner = case os:getenv("LAB_SSH_ID") of false -> []; Value -> [{id_string, Value}] end,
    {ok, Daemon} = ssh:daemon(2222, Banner ++ [
        {system_dir, Dir},
        {user_dir, Dir},
        {auth_methods, "password"},
        {user_passwords, [{"module_user", "module-target-erlang-password"}]}
    ]),
    io:format("SSH_DAEMON_READY=~p~n", [Daemon]),
    ok = file:write_file("/tmp/module-target-erlang/ready", <<"ready">>),
    receive stop -> ok end.
