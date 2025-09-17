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
local ngx = ngx
local events = require("apisix.events")
local get_routes = require("apisix.router").http_routes
local core       = require("apisix.core")
local upstream   = require("apisix.upstream")
local apisix_ssl = require("apisix.ssl")
local schema_def = require("apisix.schema_def")
local roundrobin = require("resty.roundrobin")
local ipmatcher  = require("resty.ipmatcher")
local expr       = require("resty.expr.v1")
local pairs      = pairs
local ipairs     = ipairs
local type       = type
local table_insert = table.insert
local tostring   = tostring
local healthcheck
local healthcheck_shdict_name = "upstream-split-healthcheck"
local we =  require("apisix.events")

local checker
local tls ={
     client_cert= "-----BEGIN CERTIFICATE-----\nMIIDjTCCAxOgAwIBAgISBVEAmygHnpQp4unJTM7z0ZXIMAoGCCqGSM49BAMDMDIx\nCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF\nNTAeFw0yNTA2MjYwMTMyNDhaFw0yNTA5MjQwMTMyNDdaMBUxEzARBgNVBAMTCjk3\nOTg2My54eXowWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATxJIpOzk5XYf77Bd1z\n7UVKNb3zvLgzJdKMHjutcAg8zKWZhoQth5WoLSUWCWbpVJbtPs2g2BmbOx/HAv87\n0Gd+o4ICJDCCAiAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMB\nBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQl3XMrbCTjj76Sa2sm\n3hXZVGJ4NTAfBgNVHSMEGDAWgBSfK1/PPCFPnQS37SssxMZwi9LXDTAyBggrBgEF\nBQcBAQQmMCQwIgYIKwYBBQUHMAKGFmh0dHA6Ly9lNS5pLmxlbmNyLm9yZy8wIwYD\nVR0RBBwwGoIMKi45Nzk4NjMueHl6ggo5Nzk4NjMueHl6MBMGA1UdIAQMMAowCAYG\nZ4EMAQIBMC0GA1UdHwQmMCQwIqAgoB6GHGh0dHA6Ly9lNS5jLmxlbmNyLm9yZy83\nMy5jcmwwggECBgorBgEEAdZ5AgQCBIHzBIHwAO4AdQAaBP9J0FQdQK/2oMO/8djE\nZy9O7O4jQGiYaxdALtyJfQAAAZeqE0LVAAAEAwBGMEQCIGtbJn/8OBakcqmsoitK\n8UO00d2GfQp4VEzekrrwOmfcAiAk+XUV7Ja0GhH1c0BrDC8cQadBb20iN2VWWi9V\nrjL1iQB1AMz7D2qFcQll/pWbU87psnwi6YVcDZeNtql+VMD+TA2wAAABl6oTSmoA\nAAQDAEYwRAIgYFA80Ty4R7J3beAXznEP9y859Q+TUPvN9Z13utgOGQ4CIAt+yhCE\nJjJk6+U545Iz+u1q/w9nDaPCMTmj4/onVgYbMAoGCCqGSM49BAMDA2gAMGUCMQDC\nqLOcSW0hBdaJKOMGIoVIsUZ51wuzwwj7FkODfLrFZVkMXMSIvFQ9BXrht3mHoRcC\nMAoXo098hLZZs9ipyyJV1HAJoBRjg8xAyAZ1iz9XSrB+iqkI8qEfjzShm9obhEJv\nZw==\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIEVzCCAj+gAwIBAgIRAIOPbGPOsTmMYgZigxXJ/d4wDQYJKoZIhvcNAQELBQAw\nTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\ncmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjQwMzEzMDAwMDAw\nWhcNMjcwMzEyMjM1OTU5WjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\nRW5jcnlwdDELMAkGA1UEAxMCRTUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQNCzqK\na2GOtu/cX1jnxkJFVKtj9mZhSAouWXW0gQI3ULc/FnncmOyhKJdyIBwsz9V8UiBO\nVHhbhBRrwJCuhezAUUE8Wod/Bk3U/mDR+mwt4X2VEIiiCFQPmRpM5uoKrNijgfgw\ngfUwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD\nATASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSfK1/PPCFPnQS37SssxMZw\ni9LXDTAfBgNVHSMEGDAWgBR5tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcB\nAQQmMCQwIgYIKwYBBQUHMAKGFmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wEwYDVR0g\nBAwwCjAIBgZngQwBAgEwJwYDVR0fBCAwHjAcoBqgGIYWaHR0cDovL3gxLmMubGVu\nY3Iub3JnLzANBgkqhkiG9w0BAQsFAAOCAgEAH3KdNEVCQdqk0LKyuNImTKdRJY1C\n2uw2SJajuhqkyGPY8C+zzsufZ+mgnhnq1A2KVQOSykOEnUbx1cy637rBAihx97r+\nbcwbZM6sTDIaEriR/PLk6LKs9Be0uoVxgOKDcpG9svD33J+G9Lcfv1K9luDmSTgG\n6XNFIN5vfI5gs/lMPyojEMdIzK9blcl2/1vKxO8WGCcjvsQ1nJ/Pwt8LQZBfOFyV\nXP8ubAp/au3dc4EKWG9MO5zcx1qT9+NXRGdVWxGvmBFRAajciMfXME1ZuGmk3/GO\nkoAM7ZkjZmleyokP1LGzmfJcUd9s7eeu1/9/eg5XlXd/55GtYjAM+C4DG5i7eaNq\ncm2F+yxYIPt6cbbtYVNJCGfHWqHEQ4FYStUyFnv8sjyqU8ypgZaNJ9aVcWSICLOI\nE1/Qv/7oKsnZCWJ926wU6RqG1OYPGOi1zuABhLw61cuPVDT28nQS/e6z95cJXq0e\nK1BcaJ6fJZsmbjRgD5p3mvEf5vdQM7MCEvU0tHbsx2I5mHHJoABHb8KVBgWp/lcX\nGWiWaeOyB7RP+OfDtvi2OsapxXiV7vNVs7fMlrRjY1joKaqmmycnBvAq14AEbtyL\nsVfOS66B8apkeFX2NY4XPEYV4ZSCe8VHPrdrERk2wILG3T/EGmSIkCYVUMSnjmJd\nVQD9F6Na/+zmXCc=\n-----END CERTIFICATE-----",
     client_key= "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEILrpjX2iZKC5K/zqixTNafh6k4ijGI9EreIcfPPJ1fb5oAoGCCqGSM49\nAwEHoUQDQgAE8SSKTs5OV2H++wXdc+1FSjW987y4MyXSjB47rXAIPMylmYaELYeV\nqC0lFglm6VSW7T7NoNgZmzsfxwL/O9Bnfg==\n-----END EC PRIVATE KEY-----"
}



local set_upstream_tls_client_param
local ok, apisix_ngx_upstream = pcall(require, "resty.apisix.upstream")
if ok then
    set_upstream_tls_client_param = apisix_ngx_upstream.set_cert_and_key
else
    set_upstream_tls_client_param = function ()
        return nil, "need to build APISIX-Runtime to support upstream mTLS"
    end
end

local lrucache = core.lrucache.new({
    ttl = 0, count = 512
})

local schema = {
    type = "object",
    properties = {
        healthcheck = {
            type = "boolean",
            default = true
        }
    },
}

local plugin_name = "upstream-split"

local _M = {
    version = 0.1,
    priority = 959,
    name = plugin_name,
    schema = schema
}

function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)

    if not ok then
        return false, err
    end
    return true
end

local function get_healthchecker_name(value)
    return "upstream#" .. value.key
end
_M.get_healthchecker_name = get_healthchecker_name

local function release_checker(healthcheck_parent)
    if not healthcheck_parent or not healthcheck_parent.checker then
        return
    end
    local checker = healthcheck_parent.checker
    core.log.info("try to release checker: ", tostring(checker))
    checker:delayed_clear(3)
    checker:stop()
end


local function create_checker()
    local pl_file = require "pl.file"
    local ssl = require "ngx.ssl"
    local cert = (pl_file.read("logs/cert.pem", true))
    local key = (pl_file.read("logs/key.pem", true))
    core.log.error("ssl: ", cert)

    healthcheck = require("resty.healthcheck")
    checker = healthcheck.new({
        name = "testing",
        events_module = we:get_healthcheck_events_modele(),
        shm_name = healthcheck_shdict_name,
        ssl_cert = cert,
        ssl_key = key,
        checks = {
                active = {  -- 主动健康检查
                type = "https",
                timeout = 5,
                concurrency = 1,
                http_path = "/headers",
                https_verify_certificate = false,
                healthy = {
                    interval = 3, -- 0 = disabled by default
                    http_statuses = { 200, 302 },
                    successes = 2,
                },
                unhealthy = {
                    interval = 3, -- 0 = disabled by default
                    http_statuses = { 429, 404,
                                    500, 501, 502, 503, 504, 505 },
                    tcp_failures = 2,
                    timeouts = 3,
                    http_failures = 5,
                },
                
            }
        }
    })
    core.log.error("creating new checker")

    -- local ok, err = checker:add_target("192.168.56.103", 443, "1.979863.xyz", false)

    local handler = function(target, eventname, sourcename, pid)
        ngx.log(ngx.error,"Event from: ", sourcename)
        if eventname == checker.events.remove then
            -- a target was removed
            ngx.log(ngx.error,"Target removed: ",
                target.ip, ":", target.port, " ", target.hostname)
        elseif eventname == checker.events.healthy then
            -- target changed state, or was added
            ngx.log(ngx.error,"Target switched to healthy: ",
                target.ip, ":", target.port, " ", target.hostname)
             
        elseif eventname ==  checker.events.unhealthy then
            -- target changed state, or was added
            ngx.log(ngx.error,"Target switched to unhealthy: ",
                target.ip, ":", target.port, " ", target.hostname)
        else
            -- unknown event
        end
    end
    return checker
    
end


local function add_checker(upstream_node,ctx)
    if healthcheck == nil then
        healthcheck = require("resty.healthcheck")
    end
    local upstream = ctx.matched_route.value.upstream
    if not upstream.clean_handlers then
        upstream.clean_handlers = {}
    end
    -- local healthcheck_parent = upstream.parent
    -- if healthcheck_parent.upstreamchecker and healthcheck_parent.upstreamchecker_nodes_ver == upstream._nodes_ver then

    --         core.log.warn("checker is existing")

    --     return healthcheck_parent.upstreamchecker
    -- end

    if upstream.is_creating_upstreamchecker then
        core.log.info("another request is creating new checker")
        return nil
    end
    upstream.is_creating_upstreamchecker = true

    core.log.error("events module used by the healthcheck: ", events.events_module,
                    ", module name: ",events:get_healthcheck_events_modele())

    -- local checker, err = healthcheck.new({
    --     name = get_healthchecker_name(upstream_node),
    --     shm_name = healthcheck_shdict_name,
    --     checks = upstream.checks,
    --     -- the events.init_worker will be executed in the init_worker phase,
    --     -- events.healthcheck_events_module is set
    --     -- while the healthcheck object is executed in the http access phase,
    --     -- so it can be used here
    --     events_module = events:get_healthcheck_events_modele(),
    -- })

    if not checker then
        core.log.error("fail to create healthcheck instance: ")
        upstream.is_creating_upstreamchecker = nil
        return nil
    end

    -- if healthcheck_parent.upstreamchecker then
    --     local ok, err = pcall(core.config_util.cancel_clean_handler, healthcheck_parent,
    --                                           healthcheck_parent.upstreamchecker_idx, true)
    --     if not ok then
    --         core.log.error("cancel clean handler error: ", err)
    --     end
    --     core.log.error("cancel clean handler")

    -- end

    -- core.log.warn("create new checker: ", tostring(checker))

    local host = upstream.checks and upstream.checks.active and upstream.checks.active.host
    local port = upstream.checks and upstream.checks.active and upstream.checks.active.port
    local up_hdr = upstream.pass_host == "rewrite" and upstream.upstream_host
    local use_node_hdr = upstream.pass_host == "node" or nil
    for _, node in ipairs(upstream_node.nodes) do
        local host_hdr = up_hdr or (use_node_hdr and node.domain)
        local ok, err = checker:add_target(node.host, port or node.port, host,
                                           false, host_hdr)
        if not ok then
            core.log.error("failed to add new health check target: ", node.host, ":",
                    port or node.port, " err: ", err)
        end
    end

    local check_idx, err = core.config_util.add_clean_handler(upstream, release_checker)
    if not check_idx then
        upstream.is_creating_upstreamchecker = nil
        checker:clear()
        checker:stop()
        core.log.error("failed to add clean handler, err:",
            err, " healthcheck parent:", core.json.delay_encode(upstream_node, true))

        return nil
    end

    -- healthcheck_parent.upstreamchecker = checker
    -- healthcheck_parent.upstreamchecker_upstream = upstream
    -- healthcheck_parent.upstreamchecker_nodes_ver = upstream._nodes_ver
    -- healthcheck_parent.upstreamchecker_idx = check_idx

    upstream.is_creating_upstreamchecker = nil

    return checker
end

local function fetch_healthchecker(upstream, ctx)
    if not upstream.checks then
        return nil
    end
    local name = get_healthchecker_name(upstream)
    checker = lrucache(name, nil, create_checker)
    if not checker then
        return nil
    end
    return add_checker(upstream,ctx)
end


local function parse_domain_for_node(node)
    local host = node.domain or node.host
    if not ipmatcher.parse_ipv4(host)
       and not ipmatcher.parse_ipv6(host)
    then
        node.domain = host

        local ip, err = core.resolver.parse_domain(host)
        if ip then
            node.host = ip
        end

        if err then
            core.log.error("dns resolver domain: ", host, " error: ", err)
        end
    end
end


local function set_upstream(url, ctx)
    local upstream_info = ctx.matched_route.value.upstream
    core.log.warn("parse route which contain domain: ",core.json.delay_encode(upstream_info, true))
    local new_nodes = {}
    local nodes_dot = {"1","2","3"}
    -- if core.table.isarray(nodes) then
    --     for _, node in ipairs(nodes) do
    --         parse_domain_for_node(node)
    --         table_insert(new_nodes, node)
    --     end
    -- else
        for _, dot in pairs(nodes_dot) do
            local node = {}
            local port, host
            host, port = core.utils.parse_addr(dot .."." .. url)
            node.domain = host
            parse_domain_for_node(node)
            if  port then
                node.port = port
            else
                node.port =  upstream_info.scheme == "https" and 443 or 80
            end

            node.weight = 1
            table_insert(new_nodes, node)
        end
    -- end
    
    local up_conf = {
        name = upstream_info.name,
        type = upstream_info.type,
        hash_on = upstream_info.hash_on,
        pass_host = upstream_info.pass_host,
        upstream_host = upstream_info.upstream_host,
        key = ctx.matched_route.key,
        nodes = new_nodes,
        timeout = upstream_info.timeout,
        scheme = upstream_info.scheme,
        tls = tls,
        checks= {
            active = {  -- 主动健康检查
            type = "https",
            timeout = 1,
            concurrency = 10,
            http_path = "/headers",
            https_verify_certificate = false,
            healthy = {
                interval = 1, -- 0 = disabled by default
                http_statuses = { 200, 302 },
                successes = 2,
            },
            unhealthy = {
                interval = 1, -- 0 = disabled by default
                http_statuses = { 429, 404,
                                500, 501, 502, 503, 504, 505 },
                tcp_failures = 2,
                timeouts = 3,
                http_failures = 5,
            },
            ssl_cert =tls.client_cert,
            ssl_key =tls.client_key
        }
        }
    }

    local ok, err = upstream.check_schema(up_conf)
    if not ok then
        core.log.error("failed to validate generated upstream: ", err)
        return 500, err
    end

    --up_conf.id  = core.request.headers()["x-request-id"] or ngx.var.request_id
    -- core.log.warn("parse route which contain domain: ",core.json.delay_encode(up_conf, true))

    fetch_healthchecker(up_conf,ctx)
    local name = get_healthchecker_name(up_conf)
    local nodes, err = healthcheck.get_target_list(name, healthcheck_shdict_name)
    core.log.warn("healthcheck http_statuses: ",core.json.delay_encode(nodes, true))
    local matched_route = ctx.matched_route
    up_conf.parent = matched_route
    local upstream_key = up_conf.type .. "#route_" ..
                         matched_route.value.id .. "_" 
    if upstream_info.node_tid then
        upstream_key = upstream_key .. "_" .. upstream_info.node_tid
    end
    --core.log.warn("upstream_key: ", upstream_key)
    up_conf.checks = ""  --不要把健康检查配置写回上游配置
    upstream.set(ctx, upstream_key, ctx.conf_version, up_conf)
    local scheme = upstream_info.scheme
    core.log.warn("healthcheck set cert: ",core.json.delay_encode(upstream_info, true))

    if scheme == "https" then
        upstream.set_scheme(ctx, up_conf)
        if (scheme == "https" or scheme == "grpcs") and up_conf.tls then

            local client_cert, client_key
            if up_conf.tls.client_cert_id then
                client_cert = ctx.upstream_ssl.cert
                client_key = ctx.upstream_ssl.key
            else
                client_cert = up_conf.tls.client_cert
                client_key = up_conf.tls.client_key
            end

            -- the sni here is just for logging
            local sni = ctx.var.upstream_host
            local cert, err = apisix_ssl.fetch_cert(sni, client_cert)
            if not ok then
                return 503, err
            end

            local key, err = apisix_ssl.fetch_pkey(sni, client_key)
            if not ok then
                return 503, err
            end
            local ok, err = set_upstream_tls_client_param(cert, key)
            if not ok then
                return 503, err
            end
            core.log.warn("healthcheck set cert: ")

        end
    end


    return
end


local function new_rr_obj(weighted_upstreams)
    local server_list = {}
    for i, upstream_obj in ipairs(weighted_upstreams) do
        if upstream_obj.upstream_id then
            server_list[upstream_obj.upstream_id] = upstream_obj.weight
        elseif upstream_obj.upstream then
            -- Add a virtual id field to uniquely identify the upstream key.
            upstream_obj.upstream.vid = i
            -- Get the table id of the nodes as part of the upstream_key,
            -- avoid upstream_key duplicate because vid is the same in the loop
            -- when multiple rules with multiple weighted_upstreams under each rule.
            -- see https://github.com/apache/apisix/issues/5276
            local node_tid = tostring(upstream_obj.upstream.nodes):sub(#"table: " + 1)
            upstream_obj.upstream.node_tid = node_tid
            server_list[upstream_obj.upstream] = upstream_obj.weight
        else
            -- If the upstream object has only the weight value, it means
            -- that the upstream weight value on the default route has been reached.
            -- Mark empty upstream services in the plugin.
            server_list["plugin#upstream#is#empty"] = upstream_obj.weight

        end
    end

    return roundrobin:new(server_list)
end


function _M.access(conf, ctx)
    core.log.warn("upstream_key: ")
   
    local headers = ngx.req.get_headers()
    if not headers["upstream"] or headers["upstream"] == "" then
        return 400
    end
    set_upstream(headers["upstream"],ctx)
    -- local weighted_upstreams
    -- local match_passed = true

    -- for _, rule in ipairs(conf.rules) do
    --     -- check if all upstream_ids are valid
    --     if rule.weighted_upstreams then
    --         for _, wupstream in ipairs(rule.weighted_upstreams) do
    --             local ups_id = wupstream.upstream_id
    --             if ups_id then
    --                 local ups = upstream.get_by_id(ups_id)
    --                 if not ups then
    --                     return 500, "failed to fetch upstream info by "
    --                                 .. "upstream id: " .. ups_id
    --                 end
    --             end
    --         end
    --     end

    --     if not rule.match then
    --         match_passed = true
    --         weighted_upstreams = rule.weighted_upstreams
    --         break
    --     end

    --     for _, single_match in ipairs(rule.match) do
    --         local expr, err = expr.new(single_match.vars)
    --         if err then
    --             core.log.error("vars expression does not match: ", err)
    --             return 500, err
    --         end

    --         match_passed = expr:eval(ctx.var)
    --         if match_passed then
    --             break
    --         end
    --     end

    --     if match_passed then
    --         weighted_upstreams = rule.weighted_upstreams
    --         break
    --     end
    -- end

    -- core.log.info("match_passed: ", match_passed)

    -- if not match_passed then
    --     return
    -- end

    -- local rr_up, err = lrucache(weighted_upstreams, nil, new_rr_obj, weighted_upstreams)
    -- if not rr_up then
    --     core.log.error("lrucache roundrobin failed: ", err)
    --     return 500
    -- end

    -- local upstream = rr_up:find()
    -- if upstream and type(upstream) == "table" then
    --     core.log.info("upstream: ", core.json.encode(upstream))
    --     return set_upstream(upstream, ctx)
    -- elseif upstream and upstream ~= "plugin#upstream#is#empty" then
    --     ctx.upstream_id = upstream
    --     core.log.info("upstream_id: ", upstream)
    --     return
    -- end

    -- ctx.upstream_id = nil
    -- core.log.warn("route_up: ", upstream)
    return
end

local healthcheck
local function checker_info(value)
    if not healthcheck then
        healthcheck = require("resty.healthcheck")
    end
    local routes = get_routes()
    if not routes then
        return 404, {err="node routes"}
    end
    local infos = {}
    for _, value in core.config_util.iterate_values(routes) do
        local plugin = value.value.plugins and value.value.plugins["upstream-split"]
        if plugin then
            local name = get_healthchecker_name(value)
            local nodes, err = healthcheck.get_target_list(name, healthcheck_shdict_name)
            if err then
                core.log.error("healthcheck.get_target_list failed: ", err)
            end
            core.table.insert(infos, {
                name = value.key,
                nodes = nodes,
            })
        end
    end
    return 200, infos
end

function _M.control_api()
    return {
        {
            methods = {"GET"},
            uris = {"/v1/plugin/upstream-split/status"},
            handler = checker_info,
        }
    }
end

function _M.init()
    local we =  require("apisix.events")
    core.log.error("healthcheck  init ",we:get_healthcheck_events_modele())

    -- local ok, err = we:configure({
    --     shm = "upstream-split-event",
    --     interval = 0.1
    -- })

    -- if not ok then
    --     core.log.error("healthcheck inited failed: ", err)

    -- end
    -- we:configured()
    core.log.error("healthcheck  inited")

end

return _M
