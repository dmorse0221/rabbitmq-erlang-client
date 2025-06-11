%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2007-2020 VMware, Inc. or its affiliates.  All rights reserved.
%%

%% @private
-module(amqp_auth_mechanisms).

-include("amqp_client.hrl").

-export([plain/3, amqplain/3, external/3, crdemo/3]).

%%---------------------------------------------------------------------------

%% @spec (none, any(), init) -> {binary(), list()} |
%%       (none, amqp_params_network(), any()) -> {binary(), any()}
%% @doc Implements PLAIN SASL authentication mechanism for AMQP connections.
%% 
%% This function handles the PLAIN authentication mechanism as defined in RFC 4616.
%% In the init phase, it returns the mechanism name. In the authentication phase,
%% it constructs the authentication response by concatenating the username and
%% decrypted password with null byte separators in the format:
%% [authzid] UTF8NUL authcid UTF8NUL passwd
%% 
%% The authzid (authorization identity) is left empty, so the format becomes:
%% 0x00 + username + 0x00 + password
%% @end
plain(none, _, init) ->
    {<<"PLAIN">>, []};
plain(none, #amqp_params_network{username = Username,
                                 password = Password}, _State) ->
    DecryptedPassword = credentials_obfuscation:decrypt(Password),
    {<<0, Username/binary, 0, DecryptedPassword/binary>>, _State}.

%% @spec (none, any(), init) -> {binary(), list()} |
%%       (none, amqp_params_network(), any()) -> {binary(), any()}
%% @doc Implements AMQPLAIN SASL authentication mechanism for AMQP connections.
%% 
%% This function handles the AMQPLAIN authentication mechanism, which is RabbitMQ's
%% proprietary variant of PLAIN authentication. In the init phase, it returns the
%% mechanism name. In the authentication phase, it constructs the authentication
%% response as an AMQP table containing LOGIN and PASSWORD fields.
%% 
%% Unlike PLAIN which uses null-separated strings, AMQPLAIN uses AMQP's native
%% table format to encode credentials in a structured way with typed fields.
%% @end
amqplain(none, _, init) ->
    {<<"AMQPLAIN">>, []};
amqplain(none, #amqp_params_network{username = Username,
                                    password = Password}, _State) ->
    LoginTable = [{<<"LOGIN">>,    longstr, Username},
                  {<<"PASSWORD">>, longstr, credentials_obfuscation:decrypt(Password)}],
    {rabbit_binary_generator:generate_table(LoginTable), _State}.

%% @spec (none, any(), init) -> {binary(), list()} |
%%       (none, any(), any()) -> {binary(), any()}
%% @doc Implements EXTERNAL SASL authentication mechanism for AMQP connections.
%% 
%% This function handles the EXTERNAL authentication mechanism, which is used when
%% authentication is performed outside of the SASL framework. In the init phase,
%% it returns the mechanism name. In the authentication phase, it returns an empty
%% binary since no credentials need to be transmitted.
%% 
%% EXTERNAL authentication is typically used with SSL/TLS client certificates or
%% other external authentication methods where client identity is already established.
%% @end
external(none, _, init) ->
    {<<"EXTERNAL">>, []};
external(none, _, _State) ->
    {<<"">>, _State}.

%% @spec (none, any(), init) -> {binary(), integer()} |
%%       (none, amqp_params_network(), integer()) -> {binary(), integer()} |
%%       (binary(), amqp_params_network(), integer()) -> {binary(), integer()}
%% @doc Implements RABBIT-CR-DEMO challenge-response authentication mechanism.
%% 
%% This function demonstrates a multi-step challenge-response authentication process.
%% It progresses through three states: init -> username exchange -> password challenge.
%% In the init phase, it returns the mechanism name and initial state 0.
%% In state 0, it sends the username and advances to state 1.
%% In state 1, it responds to the server's password challenge and advances to state 2.
%% 
%% This mechanism is primarily for educational purposes to demonstrate how
%% challenge-response SASL authentication works with state tracking.
%% @end
crdemo(none, _, init) ->
    {<<"RABBIT-CR-DEMO">>, 0};
crdemo(none, #amqp_params_network{username = Username}, 0) ->
    {Username, 1};
crdemo(<<"Please tell me your password">>,
       #amqp_params_network{password = Password}, 1) ->
    DecryptedPassword = credentials_obfuscation:decrypt(Password),
    {<<"My password is ", DecryptedPassword/binary>>, 2}.
