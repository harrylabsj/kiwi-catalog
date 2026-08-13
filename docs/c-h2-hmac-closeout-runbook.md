# C-H2 收口操作手册（HMAC 遗留凭证 → 随机 token）

- **关联审查**：`kiwi-commerce-code-review-2026-08-13.md` 的 C-H2（无 `merchant_tokens`
  行的商户凭证 = 确定性 HMAC，且无法吊销）。
- **性质**：这是**一次人工运维流程**。代码侧的三个机制已实现并通过测试；本手册
  只描述需要你（运营）手动执行的部分。
- **目标**：把存量 legacy 商户从「确定性 HMAC owner_token」迁移到「随机 token」，
  最终设 `KIWI_CATALOG_LEGACY_HMAC_AUTH=off` 收口。

---

## 1. 背景：为什么必须收口

- 旧 kiwi CLI 客户端用 `owner_token = HMAC-SHA256(KIWI_CATALOG_OWNER_TOKEN_SECRET,
  "kiwi-catalog-owner:" + merchant_id)` 作为凭证。
- 该值**确定性**且**无法逐商户吊销**：一旦 secret 泄露/低熵，攻击者即可对任意
  无 token 行的商户派生凭证，而 `revoke` 依赖 `merchant_tokens` 行存在。
- 修复思路（代码已就绪，三招组合）：
  1. **新商户**：`register_account` 注册即种 `revoked` 占位行 → 永不进 HMAC 路径。
  2. **存量商户**：`backfill_legacy_merchant_tokens` 为无行商户签发随机 token。
  3. **总开关**：`KIWI_CATALOG_LEGACY_HMAC_AUTH=off` 彻底关闭 HMAC 回退。

---

## 2. 前置条件

- 已部署包含以上改动的 kiwi-catalog 代码（含 `catalog merchant token backfill`
  子命令与 `KIWI_CATALOG_LEGACY_HMAC_AUTH` 支持）。
- 服务运行环境已设 `KIWI_CATALOG_OWNER_TOKEN_SECRET`（backfill 签发时 Fernet 加密
  需要它，必须与生产服务**同一值**，否则 token 无法在「我的」页解密找回）。
- 拿到数据库路径。默认 `~/.local/share/kiwi-catalog/catalog.sqlite`（可用
  `KIWI_CATALOG_*` 或部署环境文件覆盖，见 `deploy/systemd/kiwi-catalog.service`）。

---

## 3. 收口步骤（按顺序执行）

### 步骤 0 —— 预览范围（只读，强烈建议先做）

先看有多少存量商户落在 HMAC 路径上（有 `merchants` 行但无 `merchant_tokens` 行）：

```sql
-- 只读预览：无 token 行的商户清单
select m.id as merchant_id, m.name, m.created_at
from merchants m
left join merchant_tokens t on t.merchant_id = m.id
where t.merchant_id is null
order by m.id;
```

记下这批 merchant_id，它们就是本次要迁移的对象。若结果为空，说明已无存量无行商户，
可跳过步骤 1/2，直接到步骤 4 设开关收口。

### 步骤 1 —— 回填 token（一次性，签发随机 token）

```bash
export KIWI_CATALOG_OWNER_TOKEN_SECRET='<与生产服务相同的值>'

# 文本输出（人工分发用）
kiwi-catalog --db /path/to/catalog.sqlite catalog merchant token backfill

# 或 JSON 输出（脚本/归档用）
kiwi-catalog --db /path/to/catalog.sqlite catalog merchant token backfill --format json
```

输出形如：

```
issued 2 token(s) — distribute each plaintext token to its merchant ONCE:
mkt_legacy_1    mkt_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
mkt_legacy_2    mkt_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
```

**⚠️ 关键点**：
- 明文 token **只在此命令输出一次**，库中只存 SHA-256 摘要与 Fernet 密文。请立即
  归档到受控位置（如密码管理器）。
- 命令**幂等**：重复运行只补「新出现的」无行商户，已回填的不重复签发（旧 token
  仍在库中有效）。
- **此步一执行，被回填商户的旧 HMAC owner_token 立即失效**（它们现在有 active 行，
  HMAC 回退被关闭）。所以步骤 2（分发）必须紧接着做，商户切换前会有短暂无法写。

### 步骤 2 —— 分发 token 给商户（脱机）

对每个 `(merchant_id, token)` 对，经安全渠道（邮件 / 微信 / 工单）把 token 发给对应
商家，并附说明：

> 你的 catalog owner token 已更换。请把 kiwi 配置里的
> `KIWI_CATALOG_OWNER_TOKEN_SECRET` 派生的 owner_token 替换为以下随机 token，
> 作为 `owner_token` 直接提交：
> `mkt_xxxxxxxx...`
> 旧 HMAC 派生值已失效。

商家侧（kiwi 仓）切换到新 token 后，`owner_token` 从「HMAC 派生」改为「随机 token」。

### 步骤 3 —— 核对迁移完成

确认所有步骤 0 列出的商户都已切换到新 token 且写接口恢复正常。可用服务端自查：

```bash
# 以某商户 token 身份自查（本地信任边界）
kiwi-catalog --db /path/to/catalog.sqlite catalog merchant status --token mkt_xxxxxxxx...
```

或让商户用新 token 走一次写接口（如 `/v1/agents/{id}/refresh`），确认不再 403。

### 步骤 4 —— 设总开关收口（最后一步）

所有存量商户迁移完成后，在服务环境设：

```bash
export KIWI_CATALOG_LEGACY_HMAC_AUTH=off
```

（systemd 部署则写入环境文件并重启 `kiwi-catalog` 服务。）

从此任何无 `merchant_tokens` 行的商户再提交 HMAC 派生 owner_token，都会被
`require_merchant_token` 直接 `403 AuthError("legacy HMAC owner-token auth is disabled")`。

---

## 4. 验证

1. **回填正确**：`catalog merchant token backfill` 再次运行输出 `(no legacy merchants
   without tokens)`（或 JSON `count: 0`）。
2. **开关生效**：对一个**无行**商户（可临时造一个不存在的 merchant_id 测试）提交其
   HMAC 派生 owner_token，期望 403：

   ```bash
   # 期望：invalid / legacy HMAC disabled
   curl -s -X POST http://127.0.0.1:8600/v1/agents/refresh \
     -H 'Content-Type: application/json' \
     -d '{"merchant_id":"<无行商户>","owner_token":"<其 HMAC 派生值>"}'
   ```

3. **旧商户仍可用**：已迁移商户用新随机 token 走写接口正常（200）。

---

## 5. 回滚

- **若步骤 1 回填后、分发前发现误操作**：回填本身可逆性有限——它已为商户签发 active
  token，旧 HMAC 凭证即刻失效。若要临时恢复某商户的 HMAC 访问，可删除该行（**仅
  在确认无其它影响、且你能补发新 token 的前提下**）：

  ```sql
  -- 慎用：删除某商户 token 行后，其 HMAC 回退恢复（若总开关仍为 on）
  delete from merchant_tokens where merchant_id = '<merchant_id>';
  ```

  更安全的做法是：**不要删行**，而是直接把步骤 2 的新 token 尽快交给商户。
- **开关回滚**：`KIWI_CATALOG_LEGACY_HMAC_AUTH` 设回 `on`（或删除该环境变量）并重启
  服务，即恢复 HMAC 回退。

---

## 6. 附：owner_token 派生方式（核对用）

```python
# 旧（HMAC，收口前）：
import hmac, hashlib
owner_token = hmac.new(
    SECRET.encode(), f"kiwi-catalog-owner:{merchant_id}".encode(), hashlib.sha256
).hexdigest()

# 新（收口后）：直接用 backfill 签发的随机 token
owner_token = "mkt_xxxxxxxx..."
```

服务端比较统一走 constant-time `token_matches`（`core/tokens.py`）。
