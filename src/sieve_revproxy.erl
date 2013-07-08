-module(sieve_revproxy).

-export([init/3]).

-record(stproxy, {transport,
                   socket,
                   handler,
                   timeout,
                   buffer = <<>>,
                   remote,
                   remote_socket,
                   remote_transport}).

init(Transport, Socket, Opts) ->
    Handler = proplists:get_value(proxy, Opts),
    Timeout = proplists:get_value(timeout, Opts, 5000),
    wait_request(#stproxy{transport=Transport,
                           socket=Socket,
                           handler=Handler,
                           timeout=Timeout}).

-spec wait_request(#stproxy{}) -> ok | none().
wait_request(State=#stproxy{socket=Socket, transport=Transport, timeout=T,
        handler=Handler, buffer=Buffer}) ->
    case Transport:recv(Socket, 0, T) of
        {ok, Data} ->
            Buffer1 = << Buffer/binary, Data/binary >>,
            case call_handler(Handler, Buffer1) of
                stop ->
                    terminate(State);
                {stop, Reply} ->
                    Transport:send(Reply),
                    terminate(State);
                {remote, Remote} ->
                    start_proxy_loop(State#stproxy{buffer=Buffer1,
                                                   remote=Remote});
                [{remote, Remote}, {data, NewData}] ->
                    start_proxy_loop(State#stproxy{buffer=NewData,
                                                   remote=Remote});
                [{remote, Remote}, {data, NewData}, {reply, Reply}] ->
                    Transport:send(Socket, Reply),
                    start_proxy_loop(State#stproxy{buffer=NewData,
                                                   remote=Remote});
                _ ->
                    wait_request(State#stproxy{buffer=Buffer1})
            end;
        {error, _Reason} ->
            terminate(State)
    end.


start_proxy_loop(State=#stproxy{remote=Remote, buffer=Buffer}) ->
    case remote_connect(Remote) of
        {Transport, {ok, Socket}} ->
            Transport:send(Socket, Buffer),
            proxy_loop(State#stproxy{remote_socket=Socket,
                    remote_transport=Transport, buffer= <<>> });
        {error, _Error} ->
            terminate(State)
    end.

proxy_loop(State=#stproxy{socket=From, transport=TFrom,
        remote_socket=To, remote_transport=TTo}) ->
    TFrom:setopts(From, [{packet, 0}, {active, once}]),
    TTo:setopts(To, [{packet, 0}, {active, once}]),

    receive
        {_, From, Data} ->
            TTo:send(To, Data),
            proxy_loop(State);
        {_, To, Data} ->
            TFrom:send(From, Data),
            proxy_loop(State);
        {tcp_closed, To} ->
            terminate(State);
        {tcp_closed, From} ->
            remote_terminate(State);
        {ssl_closed, To} ->
            terminate(State);
        {ssl_closed, From} ->
            remote_terminate(State);
        _ ->
            terminate_all(State)
    end.


call_handler({M, F}, Data) ->
    M:F(Data);
call_handler({M, F, A}, Data) ->
    erlang:apply(M, F, [Data | A]).

-spec terminate(#stproxy{}) -> ok.
terminate(#stproxy{socket=Socket, transport=Transport}) ->
    Transport:close(Socket),
    ok.

remote_connect({Ip, Port}) ->
    {barrel_tcp, gen_tcp:connect(Ip, Port, [binary, {packet, 0},
                                            {delay_send, true}])};
remote_connect({ssl, Ip, Port, Opts}) ->
    Opts1 = parse_ssl_options(Opts),
    {barrel_ssl:connect(Ip, Port, [binary, {packet, 0},
                                   {delay_send, true} | Opts1])}.

remote_terminate(#stproxy{remote_socket=Socket,
        remote_transport=Transport}) ->
    Transport:close(Socket),
    ok.

terminate_all(State) ->
    remote_terminate(State),
    terminate(State).

-spec parse_ssl_options([ssl:ssloption()]) -> any().
parse_ssl_options(Opts) ->
    parse_ssl_options(Opts, []).

%%% cowboy ssupport only certfile, keyfile & password
parse_ssl_options([{certfile, _}=KV|Rest], Acc) ->
    parse_ssl_options(Rest, [KV|Acc]);
parse_ssl_options([{keyfile, _}=KV|Rest], Acc) ->
    parse_ssl_options(Rest, [KV|Acc]);
parse_ssl_options([{password, _}=KV|Rest], Acc) ->
    parse_ssl_options(Rest, [KV|Acc]);
parse_ssl_options([_KV|Rest], Acc) ->
    parse_ssl_options(Rest, Acc).
