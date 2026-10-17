#include <napi/native_api.h>
#include "clahsos_tun.h"

namespace {
struct Operation {
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    bool start = false;
    bool success = false;
    int fd = -1;
    int port = 0;
};

napi_value schedule(napi_env env, bool start, int fd = -1, int port = 0)
{
    auto* operation = new Operation();
    operation->start = start;
    operation->fd = fd;
    operation->port = port;
    napi_value promise, name;
    napi_create_promise(env, &operation->deferred, &promise);
    napi_create_string_utf8(env, "ClashOS VPN tunnel", NAPI_AUTO_LENGTH, &name);
    napi_create_async_work(env, nullptr, name,
        [](napi_env, void* data) {
            auto* op = static_cast<Operation*>(data);
            if (op->start) op->success = clahsos::startTunnel(op->fd, op->port);
            else { clahsos::stopTunnel(); op->success = true; }
        },
        [](napi_env env, napi_status status, void* data) {
            auto* op = static_cast<Operation*>(data);
            napi_value result;
            napi_get_boolean(env, status == napi_ok && op->success, &result);
            napi_resolve_deferred(env, op->deferred, result);
            napi_delete_async_work(env, op->work);
            delete op;
        }, operation, &operation->work);
    napi_queue_async_work(env, operation->work);
    return promise;
}

napi_value start(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value args[2];
    int32_t fd = -1, port = 0;
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc != 2 || napi_get_value_int32(env, args[0], &fd) != napi_ok ||
        napi_get_value_int32(env, args[1], &port) != napi_ok) {
        napi_throw_type_error(env, nullptr, "Expected TUN fd and local SOCKS port");
        return nullptr;
    }
    return schedule(env, true, fd, port);
}
napi_value stop(napi_env env, napi_callback_info) { return schedule(env, false); }
napi_value stopSync(napi_env env, napi_callback_info)
{
    clahsos::stopTunnel();
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}
napi_value status(napi_env env, napi_callback_info)
{
    const std::string text = clahsos::tunnelStatus();
    napi_value result;
    napi_create_string_utf8(env, text.c_str(), text.size(), &result);
    return result;
}
napi_value init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        {"start", nullptr, start, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"stop", nullptr, stop, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"stopSync", nullptr, stopSync, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"status", nullptr, status, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties);
    napi_add_env_cleanup_hook(env, [](void*) { clahsos::stopTunnel(); }, nullptr);
    return exports;
}
napi_module module = {1, 0, nullptr, init, "clahsos_tun", nullptr, {0}};
}
extern "C" __attribute__((constructor)) void registerClahsosTun() { napi_module_register(&module); }
