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
    # 1) 双栈共享：handler(db_path, payload, query, **path_params) -> dict
    reg.add_route({"GET"}, "/portal/dashboard", my_dashboard_handler)

    # 2) 可选：FastAPI 专用实现。同方法同路径时优先于共享实现。
    def _fastapi(app, db_path):
        @app.get("/portal/dashboard")
        def page() -> str: ...

    reg.add_fastapi_hook(_fastapi)
```

商家后台 HTML（`/portal/*`）与运营后台同属私有运营界面，由
`kiwi-catalog-admin` 扩展注册。核心仓只保留其调用的账号、商家资料和 Listings
API；未安装扩展时这些后台页面路由不存在。匿名只读的公开商家主页
`/m/{merchant_id}` 不属于后台，由核心直接提供（只展示公开投影）。

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
- **HTTP 路由冲突**：同方法的匹配范围重叠时，优先保留基路由和先注册的共享路由。
  后一条路由的冲突方法会被跳过，日志同时列出两个模板。其他方法可继续挂载。
  例如，`GET /portal/{page}` 与 `GET /portal/history` 应使用互不重叠的路径。
  FastAPI hook 只能替换同一扩展中匹配范围和方法相同的共享路由。
  通过 `include_router` 挂载的子路由组会按实际前缀检查，组内有冲突时整组跳过。
  无法精确比较的自定义转换器按其固定前缀保守判断。
- **缓存**：装载结果进程级缓存，坏扩展不会每请求重试；测试用
  `kiwi_catalog.api.extensions.reset_extension_cache()` 重置。
- **双栈**：`add_route` 声明会自动挂在两栈。只用 FastAPI hook 的路由仅在
  FastAPI 上提供。共享 handler 可按需返回 `__html__`、`__redirect__`、
  `__status__`、`__no_store__` 和 `__cookies__` 元键。这些键在响应字典顶层保留给
  HTTP 传输控制，业务数据请使用其他键。共享模板使用 `{name}` 参数，
  `{id:int}` 等转换器须由 FastAPI hook 注册。

## 参考实现

`harrylabsj/kiwi-catalog-admin`（私有仓）：运营后台即以此钩子挂载，
gate 在 `KIWI_CATALOG_PORTAL_ADMIN_ENABLED`。
