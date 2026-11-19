import { api } from "./api.js";
import { el, clear, shortID, fmtTime, copyText, toast } from "./dom.js";

function drawerRoot() {
  return document.getElementById("drawer-root");
}

export function closeDrawer() {
  const root = drawerRoot();
  if (!root) return;
  root.hidden = true;
  clear(root);
}

export async function openModuleDrawer({ mod, projectName, currentUser, isAdmin, onChanged }) {
  const root = drawerRoot();
  clear(root);
  const panel = el("div", { className: "drawer-panel" });
  root.onclick = (ev) => {
    if (ev.target === root) closeDrawer();
  };
  root.appendChild(panel);
  root.hidden = false;

  const titleText = mod.display_name ? `${mod.display_name} (${mod.name})` : mod.name;
  panel.appendChild(
    el(
      "div",
      { className: "modal-header" },
      el("div", {}, el("h3", { className: "modal-title", text: titleText }), el("div", { className: "cell-sub mono", text: mod.repository_url })),
      el("button", { type: "button", className: "btn btn-sm", text: "关闭", onClick: closeDrawer })
    )
  );

  // 1. Metadata summary + admin inline edit
  const kvSection = el("div", {});
  const kv = el(
    "div",
    { className: "kv-grid" },
    el("span", { className: "kv-key", text: "模块名" }),
    el("span", { className: "mono", text: mod.name }),
    el("span", { className: "kv-key", text: "挂载路径" }),
    el("span", { className: "mono", text: mod.mount_path }),
    el("span", { className: "kv-key", text: "Repository ID" }),
    el(
      "span",
      { className: "action-row" },
      el("code", { text: mod.repository_id }),
      el("button", { type: "button", className: "btn btn-xs", text: "复制 ID", onClick: () => copyText(mod.repository_id, "Repository ID") })
    ),
    el("span", { className: "kv-key", text: "默认分支" }),
    el("span", { className: "mono", text: mod.default_branch || "main" }),
    el("span", { className: "kv-key", text: "当前账号权限" }),
    el("span", {}, mod.my_permission ? el("span", { className: "badge badge-success", text: mod.my_permission }) : el("span", { className: "badge badge-neutral", text: "未授权代码读取" }))
  );
  kvSection.appendChild(kv);

  if (isAdmin && !mod.archived_at) {
    const dispInp = el("input", { type: "text", className: "input input-full", value: mod.display_name || "", placeholder: "中文游戏名（如：潮汐假日）" });
    const descInp = el("input", { type: "text", className: "input input-full", value: mod.description || "", placeholder: "可选备注说明" });
    const saveMetaBtn = el("button", {
      type: "button",
      className: "btn btn-sm btn-primary",
      text: "保存名称与备注",
      onClick: async () => {
        saveMetaBtn.disabled = true;
        try {
          const updated = await api.patchModule(mod.module_id, {
            display_name: dispInp.value,
            description: descInp.value,
          });
          mod.display_name = updated.DisplayName || dispInp.value.trim();
          mod.description = updated.Description || descInp.value.trim();
          toast("已更新模块显示信息");
          if (onChanged) await onChanged();
        } catch (err) {
          toast(err.message, true);
        } finally {
          saveMetaBtn.disabled = false;
        }
      },
    });
    kvSection.appendChild(
      el(
        "div",
        { className: "drawer-section" },
        el("h4", { className: "drawer-section-title", text: "中文游戏名与备注（管理员）" }),
        el("div", { className: "form-field" }, dispInp),
        el("div", { className: "form-field" }, descInp),
        saveMetaBtn
      )
    );
  } else if (mod.description) {
    kvSection.appendChild(el("div", { className: "mt-8 muted", text: `备注：${mod.description}` }));
  }
  panel.appendChild(kvSection);

  // 2. Quick clone command & Agent prompt
  const cloneCmd = `lore-mono clone ${mod.name} --dest "./${mod.name}"`;
  const gameTitle = mod.display_name ? `《${mod.display_name}》（模块名 ${mod.name}）` : `模块 ${mod.name}`;
  const agentPrompt = `请阅读当前目录的 AGENTS.md，使用账号 ${currentUser.username} 接入 Kubee（${window.location.origin}），并拉取${gameTitle}到本地目录。`;
  panel.appendChild(
    el(
      "div",
      { className: "drawer-section" },
      el("h4", { className: "drawer-section-title", text: "快捷拉取指令与 Agent 提示词" }),
      el("div", { className: "code-block", text: cloneCmd }),
      el(
        "div",
        { className: "action-row" },
        el("button", { type: "button", className: "btn btn-sm", text: "复制 CLI 拉取命令", onClick: () => copyText(cloneCmd, "拉取命令") }),
        el("button", { type: "button", className: "btn btn-sm", text: "复制本地 Agent 提示词", onClick: () => copyText(agentPrompt, "Agent 提示词") })
      )
    )
  );

  // 3. Admin per-module member access panel
  if (isAdmin && !mod.archived_at) {
    const accessSection = el("div", { className: "drawer-section" }, el("h4", { className: "drawer-section-title", text: "该仓库人员权限分配" }));
    const accessBody = el("div", { className: "muted", text: "正在加载授权名单..." });
    accessSection.appendChild(accessBody);
    panel.appendChild(accessSection);

    api.permissions(projectName).then((permData) => {
      clear(accessBody);
      const grantMap = new Map();
      for (const g of permData.grants || []) {
        if (g.module_id === mod.module_id) grantMap.set(g.user_id, g.permission);
      }
      const draft = new Map(grantMap);
      const selects = [];

      const grid = el("div", { className: "drawer-member-grid" });
      for (const mem of permData.members || []) {
        const cur = draft.get(mem.user_id) || "none";
        const sel = el(
          "select",
          {
            className: `perm-select ${cur === "write" ? "perm-write" : cur === "read" ? "perm-read" : ""}`,
            onChange: () => {
              draft.set(mem.user_id, sel.value);
              sel.className = `perm-select ${sel.value === "write" ? "perm-write" : sel.value === "read" ? "perm-read" : ""}`;
            },
          },
          el("option", { value: "none", text: "无权限" }),
          el("option", { value: "write", text: "write" }),
          el("option", { value: "read", text: "read" })
        );
        sel.value = cur;
        selects.push({ user_id: mem.user_id, sel });
        grid.appendChild(
          el(
            "div",
            { className: "drawer-member-row" },
            el("span", { text: mem.status === "disabled" ? `${mem.username} (已禁用)` : mem.username }),
            sel
          )
        );
      }

      const savePermBtn = el("button", {
        type: "button",
        className: "btn btn-sm btn-primary",
        text: "保存该仓库权限",
        onClick: async () => {
          const changes = [];
          for (const { user_id, sel } of selects) {
            const orig = grantMap.get(user_id) || "none";
            if (sel.value !== orig) {
              changes.push({ user_id, module_id: mod.module_id, permission: sel.value });
            }
          }
          if (changes.length === 0) {
            toast("权限无变化");
            return;
          }
          savePermBtn.disabled = true;
          try {
            const res = await api.batchPermissions(projectName, changes);
            toast(`已更新该仓库权限（生效 ${res.applied} 项）`);
            if (onChanged) await onChanged();
            // Refresh drawer if current admin changed their own permission
            const myId = Number(currentUser.user_id);
            const selfChange = changes.find((c) => c.user_id === myId);
            if (selfChange) {
              mod.my_permission = selfChange.permission === "none" ? "" : selfChange.permission;
              openModuleDrawer({ mod, projectName, currentUser, isAdmin, onChanged });
              return;
            }
            for (const c of changes) {
              if (c.permission === "none") grantMap.delete(c.user_id);
              else grantMap.set(c.user_id, c.permission);
            }
          } catch (err) {
            toast(err.message, true);
          } finally {
            savePermBtn.disabled = false;
          }
        },
      });

      const setAll = (val) => {
        for (const { user_id, sel } of selects) {
          sel.value = val;
          draft.set(user_id, val);
          sel.className = `perm-select ${val === "write" ? "perm-write" : val === "read" ? "perm-read" : ""}`;
        }
      };

      accessBody.append(
        el(
          "div",
          { className: "action-row mb-8" },
          el("button", { type: "button", className: "btn btn-xs", text: "全员设为 write", onClick: () => setAll("write") }),
          el("button", { type: "button", className: "btn btn-xs", text: "全员清空", onClick: () => setAll("none") }),
          savePermBtn
        ),
        grid
      );
    }).catch((err) => {
      accessBody.textContent = `加载授权信息失败：${err.message}`;
    });
  }

  // 4. Branches/Tags & Commit History (only when caller has explicit read/write grant)
  const contentSection = el("div", { className: "drawer-section" });
  panel.appendChild(contentSection);

  if (!mod.my_permission) {
    contentSection.appendChild(el("h4", { className: "drawer-section-title", text: "分支与提交历史" }));
    const selfGrantBox = el(
      "div",
      { className: "info-banner" },
      el("div", { text: "根据仓库内容隔离策略，当前管理员账号尚未给自己授予此模块的读取权限，因此不直接读取分支与提交正文。" })
    );
    if (isAdmin && !mod.archived_at) {
      const selfBtn = el("button", {
        type: "button",
        className: "btn btn-sm btn-primary mt-8",
        text: "为当前管理员账号授予 write 权限并查看",
        onClick: async () => {
          selfBtn.disabled = true;
          try {
            await api.batchPermissions(projectName, [
              { user_id: Number(currentUser.user_id), module_id: mod.module_id, permission: "write" },
            ]);
            mod.my_permission = "write";
            toast("已为当前账号授权");
            if (onChanged) await onChanged();
            openModuleDrawer({ mod, projectName, currentUser, isAdmin, onChanged });
          } catch (err) {
            toast(err.message, true);
            selfBtn.disabled = false;
          }
        },
      });
      selfGrantBox.appendChild(selfBtn);
    }
    contentSection.appendChild(selfGrantBox);
    return;
  }

  // Refs
  const refsWrap = el("div", {}, el("h4", { className: "drawer-section-title", text: "分支与 Tag" }));
  const refsBody = el("div", { className: "muted", text: "正在加载分支与 Tag..." });
  refsWrap.appendChild(refsBody);
  contentSection.appendChild(refsWrap);

  const loadRefs = () => {
    clear(refsBody);
    refsBody.textContent = "正在加载分支与 Tag...";
    api.moduleRefs(mod.module_id).then((res) => {
      clear(refsBody);
      const refs = res.refs || [];
      if (refs.length === 0) {
        refsBody.textContent = "暂无记录分支或 Tag";
        return;
      }
      const badges = el("div", { className: "action-row" });
      for (const r of refs) {
        const cls = r.type === "tag" ? "badge badge-warn" : r.is_default ? "badge badge-primary" : "badge badge-neutral";
        const prefix = r.type === "tag" ? "tag:" : "";
        const suffix = r.is_default ? " (默认)" : "";
        badges.appendChild(
          el("span", {
            className: cls,
            title: `Lore: ${r.lore_revision}${r.source_commit_id ? `\nGit: ${r.source_commit_id}` : ""}`,
            text: `${prefix}${r.name}${suffix} · ${shortID(r.source_commit_id || r.lore_revision, 8)}`,
          })
        );
      }
      refsBody.appendChild(badges);
    }).catch((err) => {
      refsBody.textContent = `加载分支失败：${err.message}`;
    });
  };
  loadRefs();

  // Commits
  const commitList = el("div", { className: "commit-list" });
  const moreWrap = el("div", { className: "mt-12" });
  let loadCommits;
  const syncModBtn = el("button", {
    type: "button",
    className: "btn btn-xs",
    text: "同步此模块",
    onClick: async () => {
      syncModBtn.disabled = true;
      syncModBtn.textContent = "同步中...";
      try {
        const stats = await api.syncModuleHistory(mod.module_id);
        clear(commitList);
        loadRefs();
        await loadCommits();
        if (onChanged) await onChanged();
        toast(stats.commits_upserted > 0 ? `已同步 +${stats.commits_upserted} 条提交` : "当前已是最新");
      } catch (err) {
        toast(err.message, true);
      } finally {
        syncModBtn.disabled = false;
        syncModBtn.textContent = "同步此模块";
      }
    },
  });
  const histWrap = el(
    "div",
    { className: "drawer-section" },
    el(
      "div",
      { className: "toolbar" },
      el("h4", { className: "drawer-section-title", text: "最近提交记录" }),
      syncModBtn
    )
  );
  histWrap.append(commitList, moreWrap);
  contentSection.appendChild(histWrap);

  loadCommits = async (cursor = "") => {
    clear(moreWrap);
    moreWrap.appendChild(el("span", { className: "muted", text: "正在加载提交记录..." }));
    try {
      const page = await api.moduleHistory(mod.module_id, cursor, 20);
      clear(moreWrap);
      const commits = page.commits || [];
      if (!cursor && commits.length === 0) {
        commitList.appendChild(el("div", { className: "muted", text: "暂无提交记录" }));
        return;
      }
      for (const c of commits) {
        commitList.appendChild(
          el(
            "div",
            { className: "commit-item" },
            el(
              "div",
              { className: "commit-item-top" },
              el("span", { text: c.subject || "(无提交标题)" }),
              el("code", { text: shortID(c.canonical_id, 10) })
            ),
            el(
              "div",
              { className: "cell-sub" },
              `${c.author_name || "未知作者"} · ${fmtTime(c.committed_at)} · Lore ${shortID(c.lore_revision, 10)}`
            )
          )
        );
      }
      if (page.has_more && page.next_cursor) {
        moreWrap.appendChild(
          el("button", {
            type: "button",
            className: "btn btn-sm",
            text: `加载更多（共 ${page.total_matching} 条）`,
            onClick: () => loadCommits(page.next_cursor),
          })
        );
      }
    } catch (err) {
      clear(moreWrap);
      moreWrap.appendChild(el("span", { className: "muted", text: `加载历史失败：${err.message}` }));
    }
  };
  loadCommits();
}
