# kiwi-catalog 扩展钩子（extensions）

kiwi-catalog 支持通过环境变量挂载包外路由扩展（例如部署私有的运营后台
`kiwi-catalog-admin`）。开源包本身不内置任何扩展；未设置环境变量时行为
与无此机制完全一致。

## 声明扩展

```sh
export KIWI_CATALOG_EXTENSIONS=kiwi_catalog_admin   # 逗号分隔多个 import path
```

服务装配时（`create_catalog_app` / `register_fastapi_routes` / 路由解析）
逐个 `import` 每个扩展模块，并调用其顶层函数：

```python
# 你的扩展包顶层 __init__.py
def register_kiwi_extension(reg) -> None:
    # 1) fallback 栈：RouteEntry 约定 handler
    #    handler(db_path, payload, query, **path_params) -> dict | {"__html__": ...}
    reg.add_route({"GET"}, "/portal/dashboard", my_dashboard_handler)

    # 2) FastAPI 栈：自行装饰注册（双栈都要注册，两边各自验证）
    def _fastapi(app, db_path):
        @app.get("/portal/dashboard")
        def page() -> str: ...

    reg.add_fastapi_hook(_fastapi)
```

商家后台 HTML（`/portal/*`）与运营后台同属私有运营界面，由
`kiwi-catalog-admin` 扩展注册。核心仓只保留其调用的账号、商家资料和 Listings
API；未安装扩展时页面路由不存在。

### 核心 API 返回的 `/portal/*` 链接

有三处**核心响应会给出手工操作入口的 `/portal/*` 链接**，它们只有在扩展已挂载
时才可访问（基址取自 `KIWI_CATALOG_PUBLIC_BASE_URL`，未配置时回退本地开发地址）：

| 位置 | 字段 | 形式 |
| --- | --- | --- |
| `services/enrollments.py` | `verification_uri` | `/portal/connect/{enrollment_id}`（相对路径） |
| `api/handlers/connector_identity.py` | `login_url` | `<基址>/portal/connect?request_id=…` |
| `api/handlers/service_status.py` | `authorization_url` | `<基址>/portal/connect/{enrollment_id}` |

未安装扩展时这些链接 404：`/v1` API（含 device 轮询）本身不受影响，但**连接确认/
授权必须由用户在浏览器里完成的那一步做不了**。因此「只跑核心、不装扩展」的部署
必须自行提供等价页面，或把这几步排除在流程之外。

## 规则与保证

- **fail-soft**：扩展缺失、没有 `register_kiwi_extension`、注册或挂钩抛
  异常，都只记一条 `warning` 日志并跳过——服务照常启动，对应路由表现
  为普通 404，与从未注册不可区分。扩展永远不能拖垮 catalog 本身。
- **基路由优先**：扩展路由追加在基表之后，路径模板冲突时基表路由先被
  匹配（fallback 栈顺序匹配先到先得；FastAPI 栈基路由先注册同理）。
- **缓存**：装载结果进程级缓存，坏扩展不会每请求重试；测试用
  `kiwi_catalog.api.extensions.reset_extension_cache()` 重置。
- **双栈**：kiwi-catalog 是 fallback ASGI + FastAPI 双栈，扩展若只注册
  一边，另一栈上对应路由 404。FastAPI 栈的 parity 中间件经
  `resolve_route` 默认表自动感知扩展路由（404/405 判定、访问日志、
  413 上限一致生效）。

## 参考实现

`harrylabsj/kiwi-catalog-admin`（私有仓）：运营后台即以此钩子挂载，
gate 在 `KIWI_CATALOG_PORTAL_ADMIN_ENABLED`。
