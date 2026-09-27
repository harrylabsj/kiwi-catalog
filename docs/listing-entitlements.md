# Listings 商品名额（schema 40–41）

商家注册时获得免费方案，默认同时占用 20 个公开 Listings 名额。免费方案的额度保存在 `listing_plans`，可由本地管理员命令调整；单个商家的 `limit_override` 可覆盖方案额度。此处的 token 仅用于其他旧接口的身份认证，不再决定已连接 Runtime 的 Listings 权限。

发布流程：商家验证邮箱；Runtime 完成 enrollment、活动绑定和名片发布；Runtime 对每次 publish、自查和撤回请求签名。Catalog 校验当前绑定与 enrollment。Publish 在 `BEGIN IMMEDIATE` 事务中检查商家账号、方案状态、治理状态、已占用名额和稳定商品键，然后写入。`product` 与 `capability` 共用额度；`ACTIVE`（包含暂时 `STALE`）占名额，`WITHDRAWN` 与 `SUSPENDED` 不占名额。修改同一 `ACTIVE` 行不额外占名额；重新上架须重新检查。

商家主动撤回即释放名额。方案暂停后仍允许签名自查和撤回，但拒绝新增或重新发布。治理暂停会设置 `governance_hold`，普通重发布不得恢复；只有管理员解除治理后，且当前额度允许，才可恢复。Listings 的旧 `owner_token` 路径默认关闭；仅无 Catalog 账号的存量 merchant 可在迁移期显式设置 `KIWI_CATALOG_ENABLE_LEGACY_LISTINGS=on` 使用，正式切换前必须盘点并升级这些记录。已有 Catalog 账号的商家即使设置该开关也不能用 owner token 发布。

配置命令（本地管理员信任边界，修改写入审计表）：

```sh
kiwi-catalog --db catalog.sqlite catalog merchant listing-plan-limit free 20
kiwi-catalog --db catalog.sqlite catalog merchant listing-limit mkt_example --active-limit 20
kiwi-catalog --db catalog.sqlite catalog merchant listing-limit mkt_example --use-plan
kiwi-catalog --db catalog.sqlite catalog merchant listing-limit mkt_example --status suspended
```

Schema 40 为已有账号回填免费权益；若商家原有 `ACTIVE` 行超过默认 20 个，则记录等于现有占用的临时覆盖额度和审计事件。Schema 41 把尚未被管理员修改的旧免费默认值 10 提升到 20；已自定义的方案额度和商家覆盖额度保持不变。降额不会立即下架现有条目，但会阻止新增及重新上架。生产迁移前需备份数据库并单独审查迁移清单；本地实现不执行生产迁移或支付扣款。
