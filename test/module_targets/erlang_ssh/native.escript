#!/usr/bin/env escript
%%! +S 1:1 +A 1 +SDcpu 1:1 +SDio 1 -noshell
main(["inspect"]) ->
    {ok, _} = application:ensure_all_started(crypto),
    ok = application:load(ssh),
    {ok, Ssh} = application:get_key(ssh, vsn),
    Release = erlang:system_info(otp_release),
    {ok, Version} = file:read_file(code:root_dir() ++ "/releases/" ++ Release ++ "/OTP_VERSION"),
    Uid = string:trim(os:cmd("id -u")),
    Arch = erlang:system_info(system_architecture),
    Beam = code:which(ssh_connection),
    {ok, Bytes} = file:read_file(Beam),
    Digest = binary:encode_hex(crypto:hash(sha256, Bytes), lowercase),
    io:format("{\"otp\":\"~s\",\"release\":\"~s\",\"ssh\":\"~s\",\"uid\":~s,\"architecture\":\"~s\",\"beam_sha256\":\"~s\"}~n", [string:trim(binary_to_list(Version)), Release, Ssh, Uid, Arch, Digest]);
main(["auth", Password]) ->
    {ok, _} = application:ensure_all_started(ssh),
    Options = [{user, "module_user"}, {password, Password}, {user_interaction, false}, {silently_accept_hosts, true}, {save_accepted_host, false}, {user_dir, "/tmp/module-target-erlang/keys"}, {auth_methods, "password"}],
    case ssh:connect("127.0.0.1", 2222, Options, 5000) of
        {ok, Connection} ->
            {ok, Channel} = ssh_connection:session_channel(Connection, 5000),
            success = ssh_connection:exec(Connection, Channel, "os:cmd(\"printf module_target_authenticated\").", 5000),
            Output = collect(Connection, Channel, <<>>),
            ssh:close(Connection),
            io:format("AUTHENTICATED=true~nOUTPUT=~p~n", [Output]);
        {error, Reason} ->
            io:format("AUTHENTICATED=false~nERROR=~p~n", [Reason])
    end.
collect(Connection, Channel, Output) ->
    receive
        {ssh_cm, Connection, {data, Channel, _, Data}} -> collect(Connection, Channel, <<Output/binary, Data/binary>>);
        {ssh_cm, Connection, {closed, Channel}} -> Output;
        {ssh_cm, Connection, _} -> collect(Connection, Channel, Output)
    after 5000 -> erlang:error(authenticated_exec_timeout)
    end.
