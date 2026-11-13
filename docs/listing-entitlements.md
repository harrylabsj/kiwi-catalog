# Listings 商品名额（schema 40–41）

商家注册时获得 lite 方案，默认同时占用 **5** 个公开 Listings 名额。运营可把商家调整为 plus / pro / max / ultra（分别 20 / 50 / 100 / 500）。方案额度保存在 `listing_plans`，单个商家的 `limit_override` 可覆盖方案额度（运营例外）。此处的 token 仅用于其他旧接口的身份认证，不再决定已连接 Runtime 的 Listings 权限。

发布流程：商家验证邮箱；Runtime 完成 enrollment、活动绑定和名片发布；Runtime 对每次 publish、自查和撤回请求签名。Catalog 校验当前绑定与 enrollment。Publish 在 `BEGIN IMMEDIATE` 事务中检查商家账号、方案状态、治理状态、已占用名额和稳定商品键，然后写入。`product` 与 `capability` 共用额度；`ACTIVE`（包含暂时 `STALE`）占名额，`WITHDRAWN` 与 `SUSPENDED` 不占名额。修改同一 `ACTIVE` 行不额外占名额；重新上架须重新检查。

商家主动撤回即释放名额。方案暂停后仍允许签名自查和撤回，但拒绝新增或重新发布。治理暂停会设置 `governance_hold`，普通重发布不得恢复；只有管理员解除治理后，且当前额度允许，才可恢复。历史 Listing 若被检测到分享码链接，**公开读纯读隐藏**（不修改 `publication_state`/`governance_hold`/`listing_digest`）；公开搜索/详情/主页不再返回，商家自查面提示 `quarantined`/`republish_required`，必须用同 key 重新发布干净内容（新 digest），不能用 reinstate 绕过。旧的 `governance_hold=2` 存量行仍按原隔离标记隐藏，并可在重新发布后清除。Listings 的旧 `owner_token` 路径默认关闭；仅无 Catalog 账号的存量 merchant 可在迁移期显式设置 `KIWI_CATALOG_ENABLE_LEGACY_LISTINGS=on` 使用，正式切换前必须盘点并升级这些记录。已有 Catalog 账号的商家即使设置该开关也不能用 owner token 发布。

配置命令（本地管理员信任边界，修改写入审计表）：

```sh
kiwi-catalog --db catalog.sqlite catalog merchant listing-plan-limit lite 5
kiwi-catalog --db catalog.sqlite catalog merchant listing-limit mkt_example --active-limit 20
kiwi-catalog --db catalog.sqlite catalog merchant listing-limit mkt_example --use-plan
kiwi-catalog --db catalog.sqlite catalog merchant listing-limit mkt_example --status suspended
```

Schema 40 为已有账号回填免费权益；Schema 41 曾把旧免费默认值 10 提升到 20。Schema 55 建立五档（lite 5 / plus 20 / pro 50 / max 100 / ultra 500，并把旧 free 改名为 lite），只在 lite 未被管理员自定义时把 20 降到 5；已有超过 5 个 ACTIVE 的 lite 商家保留存量、不能新增或重新上架，直到下架到 5 个以内。v40 为存量商家写入的临时 grandfather override 在 v55 中清除；运营后来手动设置的 override 保留。降额不会立即下架现有条目。生产迁移前需备份数据库并单独审查迁移清单；本地实现不执行生产迁移或支付扣款。
