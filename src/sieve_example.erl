-module(sieve_example).
-export([start/0, proxy/1]).

proxy(_Data) ->
    {remote, {"openbsd.org", 80}}.

start() ->
    barrel:start(),

    barrel:start_listener(http, 100, barrel_tcp,
                          [{port, 8080}], sieve_revproxy, [{proxy, {?MODULE, proxy}}]).
