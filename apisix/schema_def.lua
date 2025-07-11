--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local schema    = require('apisix.core.schema')
local table_insert = table.insert
local table_concat = table.concat
local setmetatable = setmetatable
local error     = error

local _M = {version = 0.5}


local plugins_schema = {
    type = "object"
}

_M.anonymous_consumer_schema = {
    type = "string",
    minLength = "1"
}

local id_schema = {
    anyOf = {
        {
            type = "string", minLength = 1, maxLength = 64,
            pattern = [[^[a-zA-Z0-9-_.]+$]]
        },
        {type = "integer", minimum = 1}
    }
}

local host_def_pat = "^\\*?[0-9a-zA-Z-._\\[\\]:]+$"
local host_def = {
    type = "string",
    pattern = host_def_pat,
}
_M.host_def = host_def


local ipv4_seg = "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
local ipv4_def_buf = {}
for i = 1, 4 do
    table_insert(ipv4_def_buf, ipv4_seg)
end
local ipv4_def = table_concat(ipv4_def_buf, [[\.]])
-- There is false negative for ipv6/cidr. For instance, `:/8` will be valid.
-- It is fine as the correct regex will be too complex.
local ipv6_def = "([a-fA-F0-9]{0,4}:){1,8}(:[a-fA-F0-9]{0,4}){0,8}"
                 .. "([a-fA-F0-9]{0,4})?"
local ip_def = {
    {title = "IPv4", type = "string", format = "ipv4"},
    {title = "IPv4/CIDR", type = "string", pattern = "^" .. ipv4_def .. "/([12]?[0-9]|3[0-2])$"},
    {title = "IPv6", type = "string", format = "ipv6"},
    {title = "IPv6/CIDR", type = "string", pattern = "^" .. ipv6_def .. "/[0-9]{1,3}$"},
}
_M.ip_def = ip_def


_M.uri_def = {type = "string", pattern = [=[^[^\/]+:\/\/([\da-zA-Z.-]+|\[[\da-fA-F:]+\])(:\d+)?]=]}


local timestamp_def = {
    type = "integer",
}

local remote_addr_def = {
    description = "client IP",
    type = "string",
    anyOf = ip_def,
}


local label_value_def = {
    description = "value of label",
    type = "string",
    pattern = [[^\S+$]],
    maxLength = 256,
    minLength = 1
}
_M.label_value_def = label_value_def


local labels_def = {
    description = "key/value pairs to specify attributes",
    type = "object",
    patternProperties = {
        [".*"] = label_value_def
    },
}


local rule_name_def = {
    type = "string",
    maxLength = 100,
    minLength = 1,
}


local desc_def = {
    type = "string",
    maxLength = 256,
}


local timeout_def = {
    type = "object",
    properties = {
        connect = {type = "number", exclusiveMinimum = 0},
        send = {type = "number", exclusiveMinimum = 0},
        read = {type = "number", exclusiveMinimum = 0},
    },
    required = {"connect", "send", "read"},
}


local health_checker = {
    type = "object",
    properties = {
        active = {
            type = "object",
            properties = {
                type = {
                    type = "string",
                    enum = {"http", "https", "tcp"},
                    default = "http"
                },
                timeout = {type = "number", default = 1},
                concurrency = {type = "integer", default = 10},
                host = host_def,
                port = {
                    type = "integer",
                    minimum = 1,
                    maximum = 65535
                },
                http_path = {type = "string", default = "/"},
                https_verify_certificate = {type = "boolean", default = true},
                healthy = {
                    type = "object",
                    properties = {
                        interval = {type = "integer", minimum = 1, default = 1},
                        http_statuses = {
                            type = "array",
                            minItems = 1,
                            items = {
                                type = "integer",
                                minimum = 200,
                                maximum = 599
                            },
                            uniqueItems = true,
                            default = {200, 302}
                        },
                        successes = {
                            type = "integer",
                            minimum = 1,
                            maximum = 254,
                            default = 2
                        }
                    }
                },
                unhealthy = {
                    type = "object",
                    properties = {
                        interval = {type = "integer", minimum = 1, default = 1},
                        http_statuses = {
                            type = "array",
                            minItems = 1,
                            items = {
                                type = "integer",
                                minimum = 200,
                                maximum = 599
                            },
                            uniqueItems = true,
                            default = {429, 404, 500, 501, 502, 503, 504, 505}
                        },
                        http_failures = {
                            type = "integer",
                            minimum = 1,
                            maximum = 254,
                            default = 5
                        },
                        tcp_failures = {
                            type = "integer",
                            minimum = 1,
                            maximum = 254,
                            default = 2
                        },
                        timeouts = {
                            type = "integer",
                            minimum = 1,
                            maximum = 254,
                            default = 3
                        }
                    }
                },
                req_headers = {
                  type = "array",
                  minItems = 1,
                  items = {
                      type = "string",
                      uniqueItems = true,
                  },
                }
            }
        },
        passive = {
            type = "object",
            properties = {
                type = {
                    type = "string",
                    enum = {"http", "https", "tcp"},
                    default = "http"
                },
                healthy = {
                    type = "object",
                    properties = {
                        http_statuses = {
                            type = "array",
                            minItems = 1,
                            items = {
                                type = "integer",
                                minimum = 200,
                                maximum = 599,
                            },
                            uniqueItems = true,
                            default = {200, 201, 202, 203, 204, 205, 206, 207,
                                       208, 226, 300, 301, 302, 303, 304, 305,
                                       306, 307, 308}
                        },
                        successes = {
                            type = "integer",
                            minimum = 0,
                            maximum = 254,
                            default = 5
                        }
                    }
                },
                unhealthy = {
                    type = "object",
                    properties = {
                        http_statuses = {
                            type = "array",
                            minItems = 1,
                            items = {
                                type = "integer",
                                minimum = 200,
                                maximum = 599,
                            },
                            uniqueItems = true,
                            default = {429, 500, 503}
                        },
                        tcp_failures = {
                            type = "integer",
                            minimum = 0,
                            maximum = 254,
                            default = 2
                        },
                        timeouts = {
                            type = "integer",
                            minimum = 0,
                            maximum = 254,
                            default = 7
                        },
                        http_failures = {
                            type = "integer",
                            minimum = 0,
                            maximum = 254,
                            default = 5
                        },
                    }
                }
            },
        }
    },
    anyOf = {
        {required = {"active"}},
        {required = {"active", "passive"}},
    },
    additionalProperties = false,
}


local nodes_schema = {
    anyOf = {
        {
            type = "object",
            patternProperties = {
                [".*"] = {
                    description = "weight of node",
                    type = "integer",
                    minimum = 0,
                }
            },
        },
        {
            type = "array",
            items = {
                type = "object",
                properties = {
                    host = host_def,
                    port = {
                        description = "port of node",
                        type = "integer",
                        minimum = 1,
                        maximum = 65535
                    },
                    weight = {
                        description = "weight of node",
                        type = "integer",
                        minimum = 0,
                    },
                    priority = {
                        description = "priority of node",
                        type = "integer",
                        default = 0,
                    },
                    metadata = {
                        description = "metadata of node",
                        type = "object",
                    }
                },
                required = {"host", "weight"},
            },
        }
    }
}
_M.discovery_nodes = {
    type = "array",
    items = {
        type = "object",
        properties = {
            host = {
                description = "domain or ip",
            },
            port = {
                description = "port of node",
                type = "integer",
                minimum = 1,
                maximum = 65535
            },
            weight = {
                description = "weight of node",
                type = "integer",
                minimum = 0,
            },
            priority = {
                description = "priority of node",
                type = "integer",
            },
            metadata = {
                description = "metadata of node",
                type = "object",
            }
        },
        -- nodes from DNS discovery may not contain port
        required = {"host", "weight"},
    },
}


local certificate_scheme = {
    type = "string", minLength = 128, maxLength = 64*1024
}


local private_key_schema = {
    type = "string", minLength = 128, maxLength = 64*1024
}


local upstream_schema = {
    type = "object",
    properties = {
        -- metadata
        id = id_schema,
        name = rule_name_def,
        desc = desc_def,
        labels = labels_def,
        create_time = timestamp_def,
        update_time = timestamp_def,

        -- properties
        nodes = nodes_schema,
        retries = {
            type = "integer",
            minimum = 0,
        },
        retry_timeout = {
            type = "number",
            minimum = 0,
        },
        timeout = timeout_def,
        tls = {
            type = "object",
            properties = {
                client_cert_id = id_schema,
                client_cert = certificate_scheme,
                client_key = private_key_schema,
                verify = {
                    type = "boolean",
                    description = "Turn on server certificate verification, "..
                        "currently only kafka upstream is supported",
                    default = false,
                },
            },
            dependencies = {
                client_cert = {required = {"client_key"}},
                client_key = {required = {"client_cert"}},
                client_cert_id = {
                    ["not"] = {required = {"client_cert", "client_key"}}
                }
            }
        },
        keepalive_pool = {
            type = "object",
            properties = {
                size = {
                    type = "integer",
                    default = 320,
                    minimum = 1,
                },
                idle_timeout = {
                    type = "number",
                    default = 60,
                    minimum = 0,
                },
                requests = {
                    type = "integer",
                    default = 1000,
                    minimum = 1,
                },
            },
        },
        type = {
            description = "algorithms of load balancing",
            type = "string",
            default = "roundrobin",
        },
        checks = health_checker,
        hash_on = {
            type = "string",
            default = "vars",
            enum = {
              "vars",
              "header",
              "cookie",
              "consumer",
              "vars_combinations",
            },
        },
        key = {
            description = "the key of chash for dynamic load balancing",
            type = "string",
        },
        scheme = {
            default = "http",
            enum = {"grpc", "grpcs", "http", "https", "tcp", "tls", "udp",
                "kafka"},
            description = "The scheme of the upstream." ..
                " For L7 proxy, it can be one of grpc/grpcs/http/https." ..
                " For L4 proxy, it can be one of tcp/tls/udp." ..
                " For specific protocols, it can be kafka."
        },
        discovery_type = {
            description = "discovery type",
            type = "string",
        },
        discovery_args = {
            type = "object",
            properties = {
                namespace_id = {
                    description = "namespace id",
                    type = "string",
                },
                group_name = {
                    description = "group name",
                    type = "string",
                },
            }
        },
        pass_host = {
            description = "mod of host passing",
            type = "string",
            enum = {"pass", "node", "rewrite"},
            default = "pass"
        },
        upstream_host = host_def,
        service_name = {
            type = "string",
            maxLength = 256,
            minLength = 1
        },
    },
    oneOf = {
        {required = {"nodes"}},
        {required = {"service_name", "discovery_type"}},
    },
    additionalProperties = false
}

-- TODO: add more nginx variable support
_M.upstream_hash_vars_schema = {
    type = "string",
    pattern = [[^((uri|server_name|server_addr|request_uri|remote_port]]
               .. [[|remote_addr|query_string|host|hostname|mqtt_client_id)]]
               .. [[|arg_[0-9a-zA-z_-]+)$]],
}

-- validates header name, cookie name.
-- a-z, A-Z, 0-9, '_' and '-' are allowed.
-- when "underscores_in_headers on", header name allow '_'.
-- http://nginx.org/en/docs/http/ngx_http_core_module.html#underscores_in_headers
_M.upstream_hash_header_schema = {
    type = "string",
    pattern = [[^[a-zA-Z0-9-_]+$]]
}

-- validates string only
_M.upstream_hash_vars_combinations_schema = {
    type = "string"
}


local method_schema = {
    description = "HTTP method",
    type = "string",
    enum = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
        "OPTIONS", "CONNECT", "TRACE", "PURGE"},
}
_M.method_schema = method_schema


_M.route = {
    type = "object",
    properties = {
        -- metadata
        id = id_schema,
        name = rule_name_def,
        desc = desc_def,
        labels = labels_def,
        create_time = timestamp_def,
        update_time = timestamp_def,

        -- properties
        uri = {type = "string", minLength = 1, maxLength = 4096},
        uris = {
            type = "array",
            items = {
                description = "HTTP uri",
                type = "string",
            },
            minItems = 1,
            uniqueItems = true,
        },
        priority = {type = "integer", default = 0},

        methods = {
            type = "array",
            items = method_schema,
            uniqueItems = true,
        },
        host = host_def,
        hosts = {
            type = "array",
            items = host_def,
            minItems = 1,
            uniqueItems = true,
        },
        remote_addr = remote_addr_def,
        remote_addrs = {
            type = "array",
            items = remote_addr_def,
            minItems = 1,
            uniqueItems = true,
        },
        timeout = timeout_def,
        vars = {
            type = "array",
        },
        filter_func = {
            type = "string",
            minLength = 10,
            pattern = [[^function]],
        },

        -- The 'script' fields below are used by dashboard for plugin orchestration
        script = {type = "string", minLength = 10, maxLength = 102400},
        script_id = id_schema,

        plugins = plugins_schema,
        plugin_config_id = id_schema,

        upstream = upstream_schema,

        service_id = id_schema,
        upstream_id = id_schema,

        enable_websocket = {
            description = "enable websocket for request",
            type        = "boolean",
        },

        status = {
            description = "route status, 1 to enable, 0 to disable",
            type = "integer",
            enum = {1, 0},
            default = 1
        },
    },
    allOf = {
        {
            oneOf = {
                {required = {"uri"}},
                {required = {"uris"}},
            },
        },
        {
            oneOf = {
                {["not"] = {
                    anyOf = {
                        {required = {"host"}},
                        {required = {"hosts"}},
                    }
                }},
                {required = {"host"}},
                {required = {"hosts"}}
            },
        },
        {
            oneOf = {
                {["not"] = {
                    anyOf = {
                        {required = {"remote_addr"}},
                        {required = {"remote_addrs"}},
                    }
                }},
                {required = {"remote_addr"}},
                {required = {"remote_addrs"}}
            },
        },
    },
    anyOf = {
        {required = {"plugins", "uri"}},
        {required = {"upstream", "uri"}},
        {required = {"upstream_id", "uri"}},
        {required = {"service_id", "uri"}},
        {required = {"plugins", "uris"}},
        {required = {"upstream", "uris"}},
        {required = {"upstream_id", "uris"}},
        {required = {"service_id", "uris"}},
        {required = {"script", "uri"}},
        {required = {"script", "uris"}},
    },
    ["not"] = {
        anyOf = {
            {required = {"script", "plugins"}},
            {required = {"script", "plugin_config_id"}},
        }
    },
    additionalProperties = false,
}


_M.service = {
    type = "object",
    properties = {
        -- metadata
        id = id_schema,
        name = rule_name_def,
        desc = desc_def,
        labels = labels_def,
        create_time = timestamp_def,
        update_time = timestamp_def,

        -- properties
        plugins = plugins_schema,
        upstream = upstream_schema,
        upstream_id = id_schema,
        script = {type = "string", minLength = 10, maxLength = 102400},
        enable_websocket = {
            description = "enable websocket for request",
            type        = "boolean",
        },
        hosts = {
            type = "array",
            items = host_def,
            minItems = 1,
            uniqueItems = true,
        },
    },
    additionalProperties = false,
}


_M.consumer = {
    type = "object",
    properties = {
        -- metadata
        username = {
            type = "string", minLength = 1, maxLength = rule_name_def.maxLength,
            pattern = [[^[a-zA-Z0-9_\-]+$]]
        },
        desc = desc_def,
        labels = labels_def,
        create_time = timestamp_def,
        update_time = timestamp_def,

        -- properties
        group_id = id_schema,
        plugins = plugins_schema,
    },
    required = {"username"},
    additionalProperties = false,
}

_M.credential = {
    type = "object",
    properties = {
        -- metadata
        id = id_schema,
        name = rule_name_def,
        desc = desc_def,
        labels = labels_def,
        create_time = timestamp_def,
        update_time = timestamp_def,

        -- properties
        plugins = {
            type = "object",
            maxProperties = 1,
        },
    },
    additionalProperties = false,
}

_M.upstream = upstream_schema


local secret_uri_schema = {
    type = "string",
    pattern = "^\\$(secret|env|ENV)://"
}


_M.ssl = {
    type = "object",
    properties = {
        -- metadata
        id = id_schema,
        desc = desc_def,
        labels = labels_def,
        create_time = timestamp_def,
        update_time = timestamp_def,

        -- properties
        type = {
            description = "ssl certificate type, " ..
                            "server to server certificate, " ..
                            "client to client certificate for upstream",
            type = "string",
            default = "server",
            enum = {"server", "client"}
        },
        cert = {
            oneOf = {
                certificate_scheme,
                secret_uri_schema
            }
        },
        key = {
            oneOf = {
                private_key_schema,
                secret_uri_schema
            }
        },
        sni = {
            type = "string",
            pattern = host_def_pat,
        },
        snis = {
            type = "array",
            items = {
                type = "string",
                pattern = host_def_pat,
            },
            minItems = 1,
        },
        certs = {
            type = "array",
            items = {
                oneOf = {
                    certificate_scheme,
                    secret_uri_schema
                }
            }
        },
        keys = {
            type = "array",
            items = {
                oneOf = {
                    private_key_schema,
                    secret_uri_schema
                }
            }
        },
        client = {
            type = "object",
            properties = {
                ca = certificate_scheme,
                depth = {
                    type = "integer",
                    minimum = 0,
                    default = 1,
                },
                skip_mtls_uri_regex = {
                    type = "array",
                    minItems = 1,
                    uniqueItems = true,
                    items = {
                        description = "uri regular expression to skip mtls",
                        type = "string",
                    }
                },
            },
            required = {"ca"},
        },
        status = {
            description = "ssl status, 1 to enable, 0 to disable",
            type = "integer",
            enum = {1, 0},
            default = 1
        },
        ssl_protocols = {
            description = "set ssl protocols",
            type = "array",
            maxItems = 3,
            uniqueItems = true,
            items = {
                enum = {"TLSv1.1", "TLSv1.2", "TLSv1.3"}
            },
        },
    },
    ["if"] = {
        properties = {
            type = {
                enum = {"server"},
            },
        },
    },
    ["then"] = {
        oneOf = {
            {required = {"sni", "key", "cert"}},
            {required = {"snis", "key", "cert"}}
        }
    },
    ["else"] = {required = {"key", "cert"}},
    additionalProperties = false,
}



-- TODO: Design a plugin resource registration framework used by plugins and move the proto
--       resource to grpc-transcode plugin, which should not be an APISIX core resource
_M.proto = {
    type = "object",
    properties = {
        -- metadata
        id = id_schema,
        name = rule_name_def,
        desc = desc_def,
        labels = labels_def,
        create_time = timestamp_def,
        update_time = timestamp_def,

        -- properties
        content = {
            type = "string", minLength = 1, maxLength = 1024*1024
        }
    },
    required = {"content"},
    additionalProperties = false,
}


_M.global_rule = {
    type = "object",
    properties = {
        -- metadata
        id = id_schema,
        create_time = timestamp_def,
        update_time = timestamp_def,

        -- properties
        plugins = plugins_schema,
    },
    required = {"id", "plugins"},
    additionalProperties = false,
}


local xrpc_protocol_schema = {
    type = "object",
    properties = {
        name = {
            type = "string",
        },
        superior_id = id_schema,
        conf = {
            description = "protocol-specific configuration",
            type = "object",
        },
        logger = {
            type = "array",
            items = {
                properties = {
                    name = {
                        type = "string",
                    },
                    filter = {
                        description = "logger filter rules",
                        type = "array",
                    },
                    conf = {
                        description = "logger plugin configuration",
                        type = "object",
                    },
                },
                dependencies = {
                    name = {"conf"},
                },
                additionalProperties = false,
            },
        },

    },
    required = {"name"}
}


_M.stream_route = {
    type = "object",
    properties = {
        -- metadata
        id = id_schema,
        name = rule_name_def,
        desc = desc_def,
        labels = labels_def,
        create_time = timestamp_def,
        update_time = timestamp_def,

        -- properties
        remote_addr = remote_addr_def,
        server_addr = {
            description = "server IP",
            type = "string",
            anyOf = ip_def,
        },
        server_port = {
            description = "server port",
            type = "integer",
            minimum = 1,
            maximum = 65535
        },
        sni = {
            description = "server name indication",
            type = "string",
            pattern = host_def_pat,
        },
        upstream = upstream_schema,
        upstream_id = id_schema,
        service_id = id_schema,
        plugins = plugins_schema,
        protocol = xrpc_protocol_schema,
    },
    additionalProperties = false,
}


_M.plugins = {
    type = "array",
    items = {
        type = "object",
        properties = {
            name = {
                type = "string",
                minLength = 1,
            },
            stream = {
                type = "boolean"
            },
            additionalProperties = false,
        },
        required = {"name"}
    }
}


_M.plugin_config = {
    type = "object",
    properties = {
        -- metadata
        id = id_schema,
        name = {
            type = "string",
        },
        desc = desc_def,
        labels = labels_def,
        create_time = timestamp_def,
        update_time = timestamp_def,

        -- properties
        plugins = plugins_schema,
    },
    required = {"id", "plugins"},
    additionalProperties = false,
}


_M.consumer_group = {
    type = "object",
    properties = {
        -- metadata
        id = id_schema,
        name = rule_name_def,
        desc = desc_def,
        labels = labels_def,
        create_time = timestamp_def,
        update_time = timestamp_def,

        -- properties
        plugins = plugins_schema,
    },
    required = {"id", "plugins"},
    additionalProperties = false,
}


_M.id_schema = id_schema


_M.plugin_injected_schema = {
    ["$comment"] = "this is a mark for our injected plugin schema",
    _meta = {
        type = "object",
        properties = {
            disable = {
                type = "boolean",
            },
            error_response = {
                oneOf = {
                    { type = "string" },
                    { type = "object" },
                }
            },
            priority = {
                description = "priority of plugins by customized order",
                type = "integer",
            },
            filter = {
                description = "filter determines whether the plugin "..
                                "needs to be executed at runtime",
                type  = "array",
            },
            pre_function = {
                description = "function to be executed in each phase " ..
                              "before execution of plugins. The pre_function will have access " ..
                              "to two arguments: `conf` and `ctx`.",
                type = "string",
            },
        },
        additionalProperties = false,
    }
}


setmetatable(_M, {
    __index = schema,
    __newindex = function() error("no modification allowed") end,
})


return _M
