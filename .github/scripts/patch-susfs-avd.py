#!/usr/bin/env python3
"""给本内核树的 SUSFS v2.3.0 补上 SukiSU 需要的 4 个符号。

背景
----
树里 include/linux/susfs.h 标注的版本是 v2.3.0（作者为适配 5.15 + 配套 KernelSU 改过），
不含 SukiSU-Ultra builtin 的 kernel/selinux/{rules,sepolicy}.c 里引用的这些符号：

    susfs_add_sus_avd_allowed_by_type   (sepolicy.c:334 调用)
    susfs_add_sus_type                  (sepolicy.c:761 调用)
    susfs_spoof_avd_allowed_rcu         (上游 services.c 用；本树 services.c 未打 SUSFS，暂无人调用)
    susfs_is_sus_type_rcu               (同上)

所以 vmlinux 链接时报：
    ld.lld: error: undefined symbol: susfs_add_sus_avd_allowed_by_type

做法
----
从上游 susfs4ksu 分支 gki-android13-5.15 的 kernel_patches/fs/susfs.c 提取这 4 个函数
及其依赖（2 个哈希表 + 2 把锁 + 2 个结构体），追加到本树 fs/susfs.c 末尾，
并在 include/linux/susfs.h 里补外部声明。

差异处理
--------
上游用 SUSFS_LOGI_RL 宏，本树只定义了 SUSFS_LOGI / SUSFS_LOGE，替换为 SUSFS_LOGI。

幂等
----
脚本重复执行不会重复插入（先检查符号是否已存在）。

用法
----
    cd <内核树根目录>
    python3 patch-susfs-avd.py

退出码 0 = 已就位（含本来就有的情况），非 0 = 失败。
"""

import os
import sys

SUSFS_C = "fs/susfs.c"
SUSFS_H = "include/linux/susfs.h"

MARKER = "/* === SUSFS avd_allowed / sus_type 补齐（SukiSU 需要）=== */"

IMPL = r'''
/* === SUSFS avd_allowed / sus_type 补齐（SukiSU 需要）=== */
/*
 * 来源: susfs4ksu 分支 gki-android13-5.15 的 kernel_patches/fs/susfs.c
 *       （上游 simonpunk/susfs4ksu 已下线，用 midori01/susfs4ksu 镜像）
 *
 * 本树的 SUSFS v2.3.0 是适配过 5.15 的精简版，没有这两个哈希表。
 * SukiSU-Ultra builtin 的 sepolicy.c 在 add_rule_raw()/add_type() 里调用它们，
 * 缺符号会让 vmlinux 链接失败。
 *
 * 注意：本树的 security/selinux/ss/services.c 没有打 SUSFS 补丁，
 *       所以 susfs_spoof_avd_allowed_rcu / susfs_is_sus_type_rcu 目前没有调用者，
 *       保留定义是为了将来补 services.c 时可以直接用。
 */
#ifdef CONFIG_KSU_SUSFS

/* ---------- sus_type 哈希表 ---------- */
static DEFINE_MUTEX(susfs_mutex_lock_sus_type);
static DEFINE_HASHTABLE(SUS_TYPE_HLIST, 10);

struct st_susfs_sus_type_hlist {
	struct hlist_node node;
};

int susfs_add_sus_type(const char *secctx, u32 type_value) {
	struct st_susfs_sus_type_hlist *new_entry, *tmp_entry;
	struct hlist_node *tmp_hlist_node;
	int err = 0;

	mutex_lock(&susfs_mutex_lock_sus_type);
	hash_for_each_possible_safe(SUS_TYPE_HLIST, tmp_entry, tmp_hlist_node, node, type_value) {
		SUSFS_LOGE("secctx '%s', type_value '%u', was added before already\n",
			secctx, type_value);
		err = -EINVAL;
		goto unlock;
	}

	new_entry = kzalloc(sizeof(struct st_susfs_sus_type_hlist), GFP_KERNEL);
	if (!new_entry) {
		err = -ENOMEM;
		goto unlock;
	}

	hash_add_rcu(SUS_TYPE_HLIST, &new_entry->node, type_value);
	SUSFS_LOGI("secctx '%s', type '%u', has been added to SUS_TYPE_HLIST\n",
			secctx, type_value);
unlock:
	mutex_unlock(&susfs_mutex_lock_sus_type);
	return err;
}

bool susfs_is_sus_type_rcu(u32 type_value) {
	struct st_susfs_sus_type_hlist *entry = NULL;

	hash_for_each_possible_rcu(SUS_TYPE_HLIST, entry, node, type_value) {
		return true;
	}
	return false;
}

/* ---------- avd_allowed 哈希表 ---------- */
static DEFINE_MUTEX(susfs_mutex_lock_sus_avd_allowed_hlist);
static DEFINE_HASHTABLE(SUS_AVD_ALLOWED_HLIST, 18);

struct susfs_sus_av_rule {
	struct hlist_node node;
	u32 s_type;
	u32 t_type;
	u32 c_type;
	u32 orig_avd_allowed;
};

static inline u32 susfs_av_rule_hash(u32 ssid, u32 tsid, u16 tclass)
{
	u32 h;

	h = hash_32(ssid, 32);
	h ^= rol32(hash_32(tsid, 32), 13);
	h ^= rol32(hash_32((u32)tclass, 32), 19);

	h += h << 13;
	h ^= h >> 7;
	h += h << 17;
	h ^= h >> 5;

	return h;
}

int susfs_add_sus_avd_allowed_by_type(u32 s_type, u32 t_type, u32 c_type, u32 orig_avd_allowed)
{
	struct susfs_sus_av_rule *entry, *tmp_entry;
	struct hlist_node *tmp_hlist_node;
	int err = 0;
	u32 key;

	mutex_lock(&susfs_mutex_lock_sus_avd_allowed_hlist);

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		err = -ENOMEM;
		goto unlock;
	}

	key = susfs_av_rule_hash(s_type, t_type, c_type);
	hash_for_each_possible_safe(SUS_AVD_ALLOWED_HLIST, tmp_entry, tmp_hlist_node, node, key) {
		if (tmp_entry->s_type == s_type &&
		    tmp_entry->t_type == t_type &&
		    tmp_entry->c_type == c_type)
		{
			// Do not apply any new orig_avd_allowed for matched entry.
			kfree(entry);
			goto unlock;
		}
	}

	entry->s_type = s_type;
	entry->t_type = t_type;
	entry->c_type = c_type;
	entry->orig_avd_allowed = orig_avd_allowed;

	hash_add_rcu(SUS_AVD_ALLOWED_HLIST, &entry->node, key);
	SUSFS_LOGI("av_rule '%u %u %u %u' has been added to SUS_AVD_ALLOWED_HLIST\n",
			s_type, t_type, c_type, orig_avd_allowed);
unlock:
	mutex_unlock(&susfs_mutex_lock_sus_avd_allowed_hlist);
	return err;
}

void susfs_spoof_avd_allowed_rcu(u32 s_type, u32 t_type, u32 c_type, u32 *avd_allowed)
{
	struct susfs_sus_av_rule *entry;
	u32 key = susfs_av_rule_hash(s_type, t_type, c_type);

	hash_for_each_possible_rcu(SUS_AVD_ALLOWED_HLIST, entry, node, key) {
		if (entry->s_type == s_type &&
		    entry->t_type == t_type &&
		    entry->c_type == c_type)
		{
			*avd_allowed = entry->orig_avd_allowed;
			return;
		}
	}
}

#endif /* CONFIG_KSU_SUSFS */
/* === 补齐结束 === */
'''

DECLS = r'''
/* === SUSFS 补齐：SukiSU 用到的接口 === */
int susfs_add_sus_type(const char *secctx, u32 type_value);
bool susfs_is_sus_type_rcu(u32 type_value);
int susfs_add_sus_avd_allowed_by_type(u32 s_type, u32 t_type, u32 c_type, u32 orig_avd_allowed);
void susfs_spoof_avd_allowed_rcu(u32 s_type, u32 t_type, u32 c_type, u32 *avd_allowed);
'''

SYMS = [
    "susfs_add_sus_type",
    "susfs_add_sus_avd_allowed_by_type",
    "susfs_spoof_avd_allowed_rcu",
    "susfs_is_sus_type_rcu",
]


def fail(msg):
    print(f"::error::{msg}")
    sys.exit(1)


def main():
    if not os.path.isfile(SUSFS_C):
        fail(f"找不到 {SUSFS_C}（请在 include/linux/susfs.h 内核树根目录运行）")
    if not os.path.isfile(SUSFS_H):
        fail(f"找不到 {SUSFS_H}")

    src = open(SUSFS_C, encoding="utf-8", errors="replace").read()
    hdr = open(SUSFS_H, encoding="utf-8", errors="replace").read()

    print("=== 补前状态 ===")
    for s in SYMS:
        print(f"  {s:<38} susfs.c 出现 {src.count(s)} 次")

    already_c = all(s in src for s in SYMS)
    already_h = all(s in hdr for s in SYMS)

    # --- fs/susfs.c ---
    if already_c:
        print("\nfs/susfs.c 已含全部符号，跳过")
    else:
        if MARKER in src:
            fail("fs/susfs.c 里有标记但符号不全，请人工检查")
        with open(SUSFS_C, "a", encoding="utf-8") as f:
            f.write(IMPL)
        print(f"\n已追加实现到 {SUSFS_C}（+{IMPL.count(chr(10))} 行）")

    # --- include/linux/susfs.h ---
    if already_h:
        print("include/linux/susfs.h 已含全部声明，跳过")
    else:
        idx = hdr.rstrip().rfind("#endif")
        if idx < 0:
            fail("include/linux/susfs.h 里找不到结尾的 #endif")
        new_h = hdr[:idx] + DECLS.strip() + "\n\n" + hdr[idx:]
        with open(SUSFS_H, "w", encoding="utf-8") as f:
            f.write(new_h)
        print(f"已追加声明到 {SUSFS_H}")

    # --- 校验 ---
    src2 = open(SUSFS_C, encoding="utf-8", errors="replace").read()
    hdr2 = open(SUSFS_H, encoding="utf-8", errors="replace").read()
    print("\n=== 补后校验 ===")
    ok = True
    for s in SYMS:
        c = src2.count(s)
        h = hdr2.count(s)
        status = "OK" if (c > 0 and h > 0) else "FAIL"
        if c == 0 or h == 0:
            ok = False
        print(f"  [{status}] {s:<38} susfs.c={c}  susfs.h={h}")

    if not ok:
        fail("补齐不完整")

    # 检查依赖宏
    print("\n=== 依赖检查 ===")
    for dep in ["DEFINE_HASHTABLE", "hash_for_each_possible_safe", "hash_add_rcu",
                "hash_for_each_possible_rcu", "SUSFS_LOGI", "SUSFS_LOGE", "hash_32", "rol32"]:
        n = src2.count(dep)
        print(f"  {dep:<30} 出现 {n} 次" + ("" if n else "  ← 缺！"))

    print("\n补齐完成")


if __name__ == "__main__":
    main()
