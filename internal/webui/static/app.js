import { api, getToken, setToken, setUnauthorizedHandler } from "./api.js";
import { el, clear, shortID, fmtTime, copyText, toast } from "./dom.js";
import {
  closeModal,
  openConfirmModal,
  openOwnPasswordModal,
  openResetMemberPasswordModal,
  openCreateMemberModal,
  openAddExistingUserModal,
  openBulkMetadataModal,
} from "./modals.js";
import { openModuleDrawer, closeDrawer } from "./drawer.js";

const state = {
  me: null,
  versionInfo: null,
  projects: [],
  currentProject: "",
  activeTab: "repos", // "repos" | "members" | "matrix" | "ops"
  opsSubtab: "snapshots", // "snapshots" | "imports" | "audit"

  overview: null,
  membersData: null,
  matrixData: null,
  matrixDraft: new Map(), // "uid:mid" -> "none" | "read" | "write"
  snapshotsData: null,
  importsData: null,
  auditData: null,

  repoSearch: "",
  repoBranchFilter: "",
  repoScopeFilter: "active", // "active" | "mine" | "unnamed" | "archived"
  memberSearch: "",
  matrixRepoFilter: "",
  matrixUserFilter: "",
  auditSearch: "",
};

const appRoot = document.getElementById("app");

async function downloadCACert() {
  try {
    const info = await api.clientInfo();
    if (!info || !info.ca_pem) {
      toast("当前服务端未配置公开 CA 证书文件", true);
      return;
    }
    const blob = new Blob([info.ca_pem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "kubee-ca.pem";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast("已下载 kubee-ca.pem");
  } catch (err) {
    toast(`获取证书失败：${err.message}`, true);
  }
}

function isProjectAdmin() {
  return Boolean(state.overview && state.overview.role === "project_admin");
}

function renderLogin(reason = "") {
  closeModal();
  closeDrawer();
  clear(appRoot);

  const errBox = el("div", { className: "error-banner", hidden: !reason, text: reason || "" });
  const userInp = el("input", {
    type: "text",
    className: "input input-full",
    placeholder: "输入用户名",
    autocomplete: "username",
  });
  const pwInp = el("input", {
    type: "password",
    className: "input input-full",
    placeholder: "输入密码",
    autocomplete: "current-password",
  });
  const submitBtn = el("button", { type: "submit", className: "btn btn-primary btn-full", text: "登录控制台" });

  const form = el(
    "form",
    {
      onSubmit: async (ev) => {
        ev.preventDefault();
        errBox.hidden = true;
        const u = userInp.value.trim();
        const p = pwInp.value;
        if (!u || !p) {
          errBox.textContent = "请输入用户名和密码";
          errBox.hidden = false;
          return;
        }
        submitBtn.disabled = true;
        submitBtn.textContent = "正在验证...";
        try {
          const res = await api.login(u, p);
          setToken(res.identity_token);
          pwInp.value = "";
          await bootAuthenticated();
        } catch (err) {
          errBox.textContent = err.message;
          errBox.hidden = false;
          submitBtn.disabled = false;
          submitBtn.textContent = "登录控制台";
        }
      },
    },
    errBox,
    el("div", { className: "form-field" }, el("label", { className: "form-label", text: "用户名" }), userInp),
    el("div", { className: "form-field" }, el("label", { className: "form-label", text: "密码" }), pwInp),
    submitBtn
  );

  const page = el(
    "div",
    { className: "login-page" },
    el(
      "div",
      { className: "login-card" },
      el(
        "div",
        { className: "login-brand" },
        el("span", { className: "brand-mark", text: "ML" }),
        el("h1", { className: "login-title", text: "Monorepo-Lore 控制台" })
      ),
      el("p", { className: "login-subtitle", text: "查看游戏仓库状态、提交历史，管理项目成员与模块权限。" }),
      form,
      el(
        "div",
        { className: "login-footer" },
        el("span", { text: "会话仅保存在当前标签页" }),
        el("button", { type: "button", className: "btn btn-xs", text: "下载根证书 ca.pem", onClick: downloadCACert })
      )
    )
  );
  appRoot.appendChild(page);
  userInp.focus();
}

async function bootAuthenticated() {
  try {
    const [me, ver] = await Promise.all([api.me(), api.version().catch(() => null)]);
    state.me = me;
    state.versionInfo = ver;
    state.projects = me.projects || [];
    if (state.projects.length === 0) {
      renderEmptyProjects();
      return;
    }
    const hasCurrent = state.projects.some((p) => p.name === state.currentProject);
    if (!hasCurrent) {
      const kubee = state.projects.find((p) => p.name === "Kubee");
      state.currentProject = kubee ? kubee.name : state.projects[0].name;
    }
    await loadCurrentTab(true);
  } catch (err) {
    setToken("");
    renderLogin(err.message);
  }
}

function renderEmptyProjects() {
  clear(appRoot);
  appRoot.appendChild(
    el(
      "div",
      { className: "login-page" },
      el(
        "div",
        { className: "login-card" },
        el("h2", { className: "login-title", text: `你好，${state.me.username}` }),
        el("p", { className: "mt-8 muted", text: "当前账号尚未加入任何项目，请联系项目管理员分配项目成员权限。" }),
        el(
          "div",
          { className: "action-row mt-12" },
          el("button", { type: "button", className: "btn", text: "修改密码", onClick: openOwnPasswordModal }),
          el("button", {
            type: "button",
            className: "btn btn-danger",
            text: "退出登录",
            onClick: () => {
              setToken("");
              renderLogin();
            },
          })
        )
      )
    )
  );
}

async function loadCurrentTab(forceOverview = false) {
  if (!state.currentProject) return;
  if (forceOverview || !state.overview || state.overview.project.name !== state.currentProject) {
    state.overview = await api.overview(state.currentProject);
    if (!isProjectAdmin() && (state.activeTab === "members" || state.activeTab === "matrix")) {
      state.activeTab = "repos";
    }
    if (!isProjectAdmin() && state.opsSubtab !== "snapshots") {
      state.opsSubtab = "snapshots";
    }
  }

  if (state.activeTab === "members" && isProjectAdmin()) {
    state.membersData = await api.members(state.currentProject);
  } else if (state.activeTab === "matrix" && isProjectAdmin()) {
    state.matrixData = await api.permissions(state.currentProject);
    state.matrixDraft.clear();
  } else if (state.activeTab === "ops") {
    if (state.opsSubtab === "snapshots") {
      state.snapshotsData = await api.snapshots(state.currentProject);
    } else if (state.opsSubtab === "imports" && isProjectAdmin()) {
      state.importsData = await api.imports(state.currentProject);
    } else if (state.opsSubtab === "audit" && isProjectAdmin()) {
      state.auditData = await api.audit(state.currentProject, 150);
    }
  }
  renderShell();
}

function renderShell() {
  clear(appRoot);
  const admin = isProjectAdmin();

  const projSel = el(
    "select",
    {
      className: "select",
      "aria-label": "切换项目",
      onChange: async () => {
        state.currentProject = projSel.value;
        state.overview = null;
        state.matrixDraft.clear();
        try {
          await loadCurrentTab(true);
        } catch (err) {
          toast(err.message, true);
        }
      },
    },
    state.projects.map((p) => el("option", { value: p.name, text: `项目：${p.name}` }))
  );
  projSel.value = state.currentProject;

  const roleBadge = el("span", {
    className: admin ? "badge badge-primary" : "badge badge-neutral",
    text: admin ? "管理员 (project_admin)" : "项目成员 (project_member)",
  });

  const topbar = el(
    "header",
    { className: "topbar" },
    el(
      "div",
      { className: "topbar-left" },
      el("span", { className: "brand-mark", text: "ML" }),
      el("span", { className: "topbar-title", text: "Monorepo-Lore" }),
      el("span", { className: "divider-v" }),
      projSel,
      el("button", {
        type: "button",
        className: "btn btn-sm",
        text: "刷新数据",
        onClick: async () => {
          try {
            await loadCurrentTab(true);
            toast("数据已刷新");
          } catch (err) {
            toast(err.message, true);
          }
        },
      })
    ),
    el(
      "div",
      { className: "topbar-right" },
      el("span", { className: "mono", text: state.me.username }),
      roleBadge,
      el("button", { type: "button", className: "btn btn-sm", text: "下载 CA 证书", onClick: downloadCACert }),
      el("button", { type: "button", className: "btn btn-sm", text: "修改密码", onClick: openOwnPasswordModal }),
      el("button", {
        type: "button",
        className: "btn btn-sm",
        text: "退出",
        onClick: () => {
          setToken("");
          renderLogin();
        },
      })
    )
  );

  const tabsDef = [{ id: "repos", label: `仓库总览 (${(state.overview.modules || []).filter((m) => !m.archived_at).length})` }];
  if (admin) {
    tabsDef.push(
      { id: "members", label: `人员管理 (${state.overview.summary.member_count ?? "—"})` },
      { id: "matrix", label: "权限矩阵" }
    );
  }
  tabsDef.push({ id: "ops", label: admin ? "快照 · 导入 · 审计" : "快照记录" });

  const nav = el(
    "nav",
    { className: "nav-tabs" },
    tabsDef.map((t) =>
      el("button", {
        type: "button",
        className: state.activeTab === t.id ? "nav-tab active" : "nav-tab",
        text: t.label,
        onClick: async () => {
          if (state.activeTab === t.id) return;
          state.activeTab = t.id;
          try {
            await loadCurrentTab(false);
          } catch (err) {
            toast(err.message, true);
          }
        },
      })
    )
  );

  const main = el("main", { className: "main-container" });
  if (state.activeTab === "repos") {
    main.appendChild(buildReposView());
  } else if (state.activeTab === "members" && admin) {
    main.appendChild(buildMembersView());
  } else if (state.activeTab === "matrix" && admin) {
    main.appendChild(buildMatrixView());
  } else if (state.activeTab === "ops") {
    main.appendChild(buildOpsView());
  }

  appRoot.append(topbar, nav, main);
}

/* ============================ Tab 1: Repositories ============================ */

function buildReposView() {
  const wrap = el("div", {});
  const ov = state.overview;
  const sum = ov.summary || {};
  const admin = isProjectAdmin();
  const allMods = ov.modules || [];
  const activeMods = allMods.filter((m) => !m.archived_at);
  const myReadableCount = activeMods.filter((m) => Boolean(m.my_permission)).length;

  const cards = [
    el(
      "div",
      { className: "stat-card" },
      el("div", { className: "stat-label", text: admin ? "活跃游戏仓库" : "已授权游戏仓库" }),
      el("div", { className: "stat-value", text: sum.active_modules ?? activeMods.length }),
      el("div", { className: "stat-sub", text: admin ? `已标记中文名 ${activeMods.filter((m) => m.display_name).length} 款` : "当前账号可克隆/同步" })
    ),
    el(
      "div",
      { className: "stat-card" },
      el("div", { className: "stat-label", text: "当前账号可读仓库" }),
      el("div", { className: "stat-value", text: myReadableCount }),
      el("div", { className: "stat-sub", text: `项目角色：${ov.role}` })
    ),
  ];
  if (admin) {
    cards.push(
      el(
        "div",
        { className: "stat-card" },
        el("div", { className: "stat-label", text: "项目成员人数" }),
        el("div", { className: "stat-value", text: sum.member_count ?? 0 }),
        el("div", { className: "stat-sub", text: "不含系统导入/发布服务账号" })
      )
    );
  }
  cards.push(
    el(
      "div",
      { className: "stat-card" },
      el("div", { className: "stat-label", text: "最新已发布快照" }),
      el("div", { className: "stat-value", text: sum.latest_snapshot_id ? `Snapshot #${sum.latest_snapshot_id}` : "暂无" }),
      el("div", { className: "stat-sub", text: sum.latest_snapshot_at ? fmtTime(sum.latest_snapshot_at) : "尚未发布父仓库快照" })
    )
  );
  wrap.appendChild(el("div", { className: "stats-grid" }, cards));

  // Filters
  const branches = Array.from(new Set(activeMods.map((m) => m.default_branch).filter(Boolean))).sort();
  const tableMount = el("div", { className: "panel" });

  const searchInp = el("input", {
    type: "search",
    className: "input input-search",
    placeholder: "搜索中文游戏名 / 模块名 / Repo ID / 提交摘要...",
    value: state.repoSearch,
    onInput: () => {
      state.repoSearch = searchInp.value;
      renderTable();
    },
  });

  const branchSel = el(
    "select",
    {
      className: "select",
      onChange: () => {
        state.repoBranchFilter = branchSel.value;
        renderTable();
      },
    },
    el("option", { value: "", text: "全部默认分支" }),
    branches.map((b) => el("option", { value: b, text: `默认分支：${b}` }))
  );
  branchSel.value = state.repoBranchFilter;

  const scopeSel = el(
    "select",
    {
      className: "select",
      hidden: !admin,
      onChange: () => {
        state.repoScopeFilter = scopeSel.value;
        renderTable();
      },
    },
    el("option", { value: "active", text: "全部活跃仓库" }),
    el("option", { value: "mine", text: "仅当前账号已授权" }),
    el("option", { value: "unnamed", text: "尚未设置中文游戏名" }),
    el("option", { value: "archived", text: "已归档仓库" })
  );
  scopeSel.value = state.repoScopeFilter;

  const rightActions = el("div", { className: "toolbar-group" });
  if (admin) {
    rightActions.appendChild(
      el("button", {
        type: "button",
        className: "btn btn-sm btn-primary",
        text: "批量同步中文游戏名",
        onClick: () =>
          openBulkMetadataModal(state.currentProject, activeMods, async () => {
            await loadCurrentTab(true);
          }),
      })
    );
  }

  wrap.append(
    el("div", { className: "toolbar" }, el("div", { className: "toolbar-group" }, searchInp, branchSel, scopeSel), rightActions),
    tableMount
  );

  function renderTable() {
    clear(tableMount);
    const q = state.repoSearch.trim().toLowerCase();
    const filtered = allMods.filter((m) => {
      if (admin) {
        if (state.repoScopeFilter === "archived" && !m.archived_at) return false;
        if (state.repoScopeFilter !== "archived" && m.archived_at) return false;
        if (state.repoScopeFilter === "mine" && !m.my_permission) return false;
        if (state.repoScopeFilter === "unnamed" && m.display_name) return false;
      } else if (m.archived_at) {
        return false;
      }
      if (state.repoBranchFilter && m.default_branch !== state.repoBranchFilter) return false;
      if (!q) return true;
      const hay = [
        m.display_name,
        m.name,
        m.mount_path,
        m.repository_id,
        m.description,
        m.head_commit ? m.head_commit.subject : "",
        m.head_commit ? m.head_commit.author_name : "",
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });

    if (filtered.length === 0) {
      tableMount.appendChild(el("div", { className: "empty-box", text: "没有匹配的仓库记录" }));
      return;
    }

    const tbody = el("tbody", {});
    for (const m of filtered) {
      const openRow = () =>
        openModuleDrawer({
          mod: m,
          projectName: state.currentProject,
          currentUser: state.me,
          isAdmin: admin,
          onChanged: () => loadCurrentTab(true),
        });

      let commitCell;
      if (!m.my_permission) {
        commitCell = el("span", { className: "muted", text: "未对当前账号授权内容读取" });
      } else if (m.head_commit) {
        commitCell = el(
          "div",
          {},
          el("div", { className: "commit-subj", title: m.head_commit.subject, text: m.head_commit.subject || "(无标题)" }),
          el(
            "div",
            { className: "cell-sub" },
            `${shortID(m.head_commit.canonical_id, 8)} · ${m.head_commit.author_name || "未知"} · ${fmtTime(m.head_commit.committed_at)} · 共 ${m.commit_count} 次提交`
          )
        );
      } else {
        commitCell = el("span", { className: "muted", text: "暂无提交索引" });
      }

      const permBadges = el("div", { className: "action-row" });
      if (admin) {
        permBadges.appendChild(el("span", { className: "badge badge-neutral", text: `已授权 ${m.granted_count ?? 0} 人` }));
      }
      if (m.my_permission) {
        permBadges.appendChild(
          el("span", {
            className: m.my_permission === "write" ? "badge badge-success" : "badge badge-primary",
            text: `本人: ${m.my_permission}`,
          })
        );
      }

      const row = el(
        "tr",
        { className: "row-clickable", onClick: openRow },
        el(
          "td",
          {},
          el("div", { className: "cell-title", text: m.display_name || "—" }),
          m.description ? el("div", { className: "cell-sub", text: m.description }) : null
        ),
        el(
          "td",
          {},
          el("div", { className: "mono cell-title", text: m.name }),
          m.mount_path !== m.name ? el("div", { className: "cell-sub mono", text: `mount: ${m.mount_path}` }) : null
        ),
        el(
          "td",
          {},
          el(
            "div",
            { className: "action-row" },
            el("code", { text: shortID(m.repository_id, 12) }),
            el("button", {
              type: "button",
              className: "btn btn-xs",
              text: "复制",
              onClick: (ev) => {
                ev.stopPropagation();
                copyText(m.repository_id, "Repository ID");
              },
            })
          )
        ),
        el(
          "td",
          {},
          el("span", { className: "badge badge-primary mono", text: m.default_branch || "main" }),
          m.my_permission
            ? el("div", { className: "cell-sub mt-8", text: `${m.branch_count} 分支 · ${m.tag_count} Tag` })
            : null
        ),
        el("td", {}, commitCell),
        el("td", {}, permBadges),
        el(
          "td",
          {},
          el("button", {
            type: "button",
            className: "btn btn-sm",
            text: admin ? "详情 / 授权" : "详情 / 拉取命令",
            onClick: (ev) => {
              ev.stopPropagation();
              openRow();
            },
          })
        )
      );
      tbody.appendChild(row);
    }

    const table = el(
      "table",
      { className: "data-table" },
      el(
        "thead",
        {},
        el(
          "tr",
          {},
          el("th", { text: "游戏中文名" }),
          el("th", { text: "模块名" }),
          el("th", { text: "Repository ID" }),
          el("th", { text: "默认分支" }),
          el("th", { text: "最新提交" }),
          el("th", { text: "权限情况" }),
          el("th", { text: "操作" })
        )
      ),
      tbody
    );
    tableMount.appendChild(el("div", { className: "table-scroll" }, table));
  }

  renderTable();
  return wrap;
}

/* ============================ Tab 2: Members ============================ */

function buildMembersView() {
  const wrap = el("div", {});
  const members = (state.membersData && state.membersData.members) || [];
  const activeMods = (state.overview.modules || []).filter((m) => !m.archived_at);
  const projectID = state.overview.project.id;
  const myUserID = Number(state.me.user_id);
  const activeAdminCount = members.filter((m) => m.role === "project_admin" && m.status === "active").length;

  const tableMount = el("div", { className: "panel" });
  const searchInp = el("input", {
    type: "search",
    className: "input input-search",
    placeholder: "搜索成员用户名...",
    value: state.memberSearch,
    onInput: () => {
      state.memberSearch = searchInp.value;
      renderTable();
    },
  });

  const toolbar = el(
    "div",
    { className: "toolbar" },
    el("div", { className: "toolbar-group" }, searchInp),
    el(
      "div",
      { className: "toolbar-group" },
      el("button", {
        type: "button",
        className: "btn btn-sm",
        text: "加入已有账号",
        onClick: () => openAddExistingUserModal(state.currentProject, () => loadCurrentTab(true)),
      }),
      el("button", {
        type: "button",
        className: "btn btn-sm btn-primary",
        text: "+ 新增成员并授权",
        onClick: () => openCreateMemberModal(state.currentProject, activeMods, () => loadCurrentTab(true)),
      })
    )
  );
  wrap.append(toolbar, tableMount);

  function renderTable() {
    clear(tableMount);
    const q = state.memberSearch.trim().toLowerCase();
    const filtered = members.filter((m) => !q || m.username.toLowerCase().includes(q));
    if (filtered.length === 0) {
      tableMount.appendChild(el("div", { className: "empty-box", text: "没有匹配的成员" }));
      return;
    }

    const tbody = el("tbody", {});
    for (const mem of filtered) {
      const isSelf = mem.user_id === myUserID;
      const isLastAdmin = mem.role === "project_admin" && mem.status === "active" && activeAdminCount <= 1;

      const grantAllBtn = el("button", {
        type: "button",
        className: "btn btn-xs",
        text: "全库 Write",
        disabled: activeMods.length === 0 || mem.write_count === activeMods.length,
        onClick: async () => {
          grantAllBtn.disabled = true;
          try {
            const changes = activeMods.map((m) => ({
              user_id: mem.user_id,
              module_id: m.module_id,
              permission: "write",
            }));
            const res = await api.batchPermissions(state.currentProject, changes);
            toast(`已为 ${mem.username} 授予全部活跃仓库 write 权限（更新 ${res.applied} 项）`);
            await loadCurrentTab(true);
          } catch (err) {
            toast(err.message, true);
            grantAllBtn.disabled = false;
          }
        },
      });

      const clearAllBtn = el("button", {
        type: "button",
        className: "btn btn-xs",
        text: "清空仓库权限",
        disabled: mem.write_count + mem.read_count === 0,
        onClick: () =>
          openConfirmModal({
            title: `清空仓库权限：${mem.username}`,
            message: `确定撤销 ${mem.username} 在 ${state.currentProject} 下的全部模块访问权限吗？（保留项目成员身份）`,
            confirmLabel: "确认清空",
            danger: true,
            onConfirm: async () => {
              const changes = activeMods.map((m) => ({
                user_id: mem.user_id,
                module_id: m.module_id,
                permission: "none",
              }));
              const res = await api.batchPermissions(state.currentProject, changes);
              toast(`已清空 ${mem.username} 的仓库权限（撤销 ${res.applied} 项）`);
              await loadCurrentTab(true);
            },
          }),
      });

      const nextRole = mem.role === "project_admin" ? "project_member" : "project_admin";
      const roleBtn = el("button", {
        type: "button",
        className: "btn btn-xs",
        text: mem.role === "project_admin" ? "设为普通成员" : "设为管理员",
        disabled: isSelf || isLastAdmin,
        title: isSelf ? "不可降级当前登录的管理员自身" : isLastAdmin ? "项目至少需保留一名活跃管理员" : "",
        onClick: () =>
          openConfirmModal({
            title: `修改项目角色：${mem.username}`,
            message: `确定将 ${mem.username} 的角色调整为 ${nextRole} 吗？`,
            confirmLabel: "确认调整",
            onConfirm: async () => {
              await api.updateMemberRole(state.currentProject, mem.user_id, nextRole);
              toast(`已将 ${mem.username} 调整为 ${nextRole}`);
              await loadCurrentTab(true);
            },
          }),
      });

      const resetPwBtn = el("button", {
        type: "button",
        className: "btn btn-xs",
        text: "重置密码",
        disabled: !mem.can_manage_account,
        title: !mem.can_manage_account ? "该账号同时属于你未管理的其他项目，禁止跨项目重置全局密码" : "",
        onClick: () => openResetMemberPasswordModal(mem, projectID, () => loadCurrentTab(false)),
      });

      const nextStatus = mem.status === "active" ? "disabled" : "active";
      const statusBtn = el("button", {
        type: "button",
        className: mem.status === "active" ? "btn btn-xs btn-danger" : "btn btn-xs",
        text: mem.status === "active" ? "禁用账号" : "启用账号",
        disabled: !mem.can_manage_account || (mem.status === "active" && (isSelf || isLastAdmin)),
        title: !mem.can_manage_account
          ? "跨项目共享账号不可由此处修改全局状态"
          : isSelf
          ? "不可禁用当前登录账号"
          : isLastAdmin
          ? "不可禁用唯一活跃管理员"
          : "",
        onClick: () =>
          openConfirmModal({
            title: `${nextStatus === "disabled" ? "禁用" : "启用"}账号：${mem.username}`,
            message:
              nextStatus === "disabled"
                ? `禁用后 ${mem.username} 的持久化会话将立即失效，无法继续登录或换取新仓库凭证。是否继续？`
                : `确定重新启用账号 ${mem.username} 吗？`,
            confirmLabel: nextStatus === "disabled" ? "确认禁用" : "确认启用",
            danger: nextStatus === "disabled",
            onConfirm: async () => {
              await api.setUserStatus(mem.username, projectID, nextStatus);
              toast(`账号 ${mem.username} 已${nextStatus === "disabled" ? "禁用" : "启用"}`);
              await loadCurrentTab(true);
            },
          }),
      });

      const removeBtn = el("button", {
        type: "button",
        className: "btn btn-xs btn-danger",
        text: "移出项目",
        disabled: isSelf || isLastAdmin,
        title: isSelf ? "不可将自己移出项目" : isLastAdmin ? "不可移除唯一活跃管理员" : "",
        onClick: () =>
          openConfirmModal({
            title: `移出项目：${mem.username}`,
            message: `确定将 ${mem.username} 从 ${state.currentProject} 中移出吗？其在本项目下的全部仓库授权将同步撤销。`,
            confirmLabel: "确认移出",
            danger: true,
            onConfirm: async () => {
              await api.removeMember(state.currentProject, mem.user_id);
              toast(`已将 ${mem.username} 移出项目`);
              await loadCurrentTab(true);
            },
          }),
      });

      const grantSummary = [];
      grantSummary.push(`write: ${mem.write_count} / ${activeMods.length}`);
      if (mem.read_count > 0) grantSummary.push(`read: ${mem.read_count}`);

      tbody.appendChild(
        el(
          "tr",
          {},
          el(
            "td",
            {},
            el(
              "div",
              { className: "action-row" },
              el("span", { className: "mono cell-title", text: mem.username }),
              isSelf ? el("span", { className: "badge badge-primary", text: "当前登录" }) : null
            ),
            el("div", { className: "cell-sub mono", text: `UID: ${mem.user_id}` })
          ),
          el(
            "td",
            {},
            el("span", {
              className: mem.role === "project_admin" ? "badge badge-primary" : "badge badge-neutral",
              text: mem.role,
            })
          ),
          el(
            "td",
            {},
            el("span", {
              className: mem.status === "active" ? "badge badge-success" : "badge badge-danger",
              text: mem.status,
            })
          ),
          el("td", {}, el("span", { className: "mono", text: grantSummary.join(" · ") })),
          el("td", {}, el("div", { className: "cell-sub", text: `${mem.added_by} · ${fmtTime(mem.added_at)}` })),
          el("td", {}, el("div", { className: "action-row" }, grantAllBtn, clearAllBtn, roleBtn, resetPwBtn, statusBtn, removeBtn))
        )
      );
    }

    tableMount.appendChild(
      el(
        "div",
        { className: "table-scroll" },
        el(
          "table",
          { className: "data-table" },
          el(
            "thead",
            {},
            el(
              "tr",
              {},
              el("th", { text: "用户名" }),
              el("th", { text: "项目角色" }),
              el("th", { text: "账号状态" }),
              el("th", { text: "已授权仓库" }),
              el("th", { text: "加入记录" }),
              el("th", { text: "管理操作" })
            )
          ),
          tbody
        )
      )
    );
  }

  renderTable();
  return wrap;
}

/* ============================ Tab 3: Permissions Matrix ============================ */

function buildMatrixView() {
  const wrap = el("div", {});
  const data = state.matrixData || { modules: [], members: [], grants: [] };
  const origMap = new Map();
  for (const g of data.grants || []) {
    origMap.set(`${g.user_id}:${g.module_id}`, g.permission);
  }

  wrap.appendChild(
    el(
      "div",
      { className: "info-banner" },
      "权限边界提示：Lore 0.10.1 底层暂不支持单仓库内强只读隔离，read 与 write 标签换发的 Access Token 均可推送；撤销授权后，已签发的短效 Access Token 最长 5 分钟自然过期。"
    )
  );

  const repoFilterInp = el("input", {
    type: "search",
    className: "input input-search",
    placeholder: "筛选行：游戏中文名或模块名...",
    value: state.matrixRepoFilter,
  });
  const userFilterInp = el("input", {
    type: "search",
    className: "input input-search",
    placeholder: "筛选列：成员用户名...",
    value: state.matrixUserFilter,
  });

  const panel = el("div", { className: "panel" });
  const saveBar = el("div", { className: "floating-save-bar", hidden: true });
  const saveCountText = el("span", { text: "" });

  const discardBtn = el("button", {
    type: "button",
    className: "btn btn-sm",
    text: "放弃未保存修改",
    onClick: () => {
      state.matrixDraft.clear();
      renderMatrix();
      updateSaveBar();
    },
  });

  const commitBtn = el("button", {
    type: "button",
    className: "btn btn-sm btn-primary",
    text: "保存全部变更",
    onClick: async () => {
      const changes = [];
      for (const [key, perm] of state.matrixDraft.entries()) {
        const orig = origMap.get(key) || "none";
        if (perm !== orig) {
          const [uid, mid] = key.split(":").map(Number);
          changes.push({ user_id: uid, module_id: mid, permission: perm });
        }
      }
      if (changes.length === 0) {
        state.matrixDraft.clear();
        updateSaveBar();
        return;
      }
      commitBtn.disabled = true;
      try {
        const res = await api.batchPermissions(state.currentProject, changes);
        toast(`权限矩阵已保存（生效 ${res.applied} 项）`);
        state.matrixDraft.clear();
        await loadCurrentTab(true);
      } catch (err) {
        toast(err.message, true);
        commitBtn.disabled = false;
      }
    },
  });
  saveBar.append(saveCountText, discardBtn, commitBtn);

  function effectivePerm(uid, mid) {
    const key = `${uid}:${mid}`;
    if (state.matrixDraft.has(key)) return state.matrixDraft.get(key);
    return origMap.get(key) || "none";
  }

  function setDraftPerm(uid, mid, perm) {
    const key = `${uid}:${mid}`;
    const orig = origMap.get(key) || "none";
    if (perm === orig) state.matrixDraft.delete(key);
    else state.matrixDraft.set(key, perm);
  }

  function updateSaveBar() {
    let diffCount = 0;
    for (const [key, perm] of state.matrixDraft.entries()) {
      if ((origMap.get(key) || "none") !== perm) diffCount++;
    }
    saveBar.hidden = diffCount === 0;
    saveCountText.textContent = `待保存权限变更：${diffCount} 项`;
  }

  function renderMatrix() {
    clear(panel);
    const rq = state.matrixRepoFilter.trim().toLowerCase();
    const uq = state.matrixUserFilter.trim().toLowerCase();
    const mods = (data.modules || []).filter(
      (m) => !rq || `${m.display_name || ""} ${m.name} ${m.mount_path}`.toLowerCase().includes(rq)
    );
    const mems = (data.members || []).filter((u) => !uq || u.username.toLowerCase().includes(uq));

    if (mods.length === 0 || mems.length === 0) {
      panel.appendChild(el("div", { className: "empty-box", text: "当前筛选条件下没有可展示的仓库或成员" }));
      return;
    }

    const headRow = el("tr", {}, el("th", { className: "matrix-sticky-col", text: `仓库 (${mods.length}) \\ 成员 (${mems.length})` }));
    for (const u of mems) {
      const setCol = (perm) => {
        for (const m of mods) setDraftPerm(u.user_id, m.module_id, perm);
        renderMatrix();
        updateSaveBar();
      };
      headRow.appendChild(
        el(
          "th",
          { className: "matrix-col-head" },
          el("div", { className: "mono", text: u.username }),
          el("div", { className: "cell-sub", text: u.status === "disabled" ? "已禁用" : u.role === "project_admin" ? "管理员" : "成员" }),
          el(
            "div",
            { className: "matrix-head-actions" },
            el("button", { type: "button", className: "btn btn-xs", text: "全W", title: "当前筛选行全部设为 write", onClick: () => setCol("write") }),
            el("button", { type: "button", className: "btn btn-xs", text: "清空", title: "当前筛选行全部设为无权限", onClick: () => setCol("none") })
          )
        )
      );
    }

    const tbody = el("tbody", {});
    for (const m of mods) {
      const setRow = (perm) => {
        for (const u of mems) setDraftPerm(u.user_id, m.module_id, perm);
        renderMatrix();
        updateSaveBar();
      };
      const tr = el(
        "tr",
        {},
        el(
          "td",
          { className: "matrix-sticky-col" },
          el("div", { className: "cell-title", text: m.display_name || m.name }),
          m.display_name ? el("div", { className: "cell-sub mono", text: m.name }) : null,
          el(
            "div",
            { className: "matrix-row-actions" },
            el("button", { type: "button", className: "btn btn-xs", text: "全员W", onClick: () => setRow("write") }),
            el("button", { type: "button", className: "btn btn-xs", text: "全清", onClick: () => setRow("none") })
          )
        )
      );

      for (const u of mems) {
        const cur = effectivePerm(u.user_id, m.module_id);
        const orig = origMap.get(`${u.user_id}:${m.module_id}`) || "none";
        const td = el("td", { className: cur !== orig ? "matrix-cell changed" : "matrix-cell" });
        const sel = el(
          "select",
          {
            className: `perm-select ${cur === "write" ? "perm-write" : cur === "read" ? "perm-read" : ""}`,
            onChange: () => {
              const next = sel.value;
              setDraftPerm(u.user_id, m.module_id, next);
              sel.className = `perm-select ${next === "write" ? "perm-write" : next === "read" ? "perm-read" : ""}`;
              td.className = next !== orig ? "matrix-cell changed" : "matrix-cell";
              updateSaveBar();
            },
          },
          el("option", { value: "none", text: "—" }),
          el("option", { value: "write", text: "write" }),
          el("option", { value: "read", text: "read" })
        );
        sel.value = cur;
        td.appendChild(sel);
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }

    panel.appendChild(el("div", { className: "matrix-scroll" }, el("table", { className: "matrix-table" }, el("thead", {}, headRow), tbody)));
  }

  repoFilterInp.addEventListener("input", () => {
    state.matrixRepoFilter = repoFilterInp.value;
    renderMatrix();
  });
  userFilterInp.addEventListener("input", () => {
    state.matrixUserFilter = userFilterInp.value;
    renderMatrix();
  });

  wrap.append(
    el("div", { className: "toolbar" }, el("div", { className: "toolbar-group" }, repoFilterInp, userFilterInp)),
    panel,
    saveBar
  );
  renderMatrix();
  updateSaveBar();
  return wrap;
}

/* ============================ Tab 4: Snapshots / Imports / Audit ============================ */

function buildOpsView() {
  const wrap = el("div", {});
  const admin = isProjectAdmin();

  if (admin) {
    const subDefs = [
      { id: "snapshots", label: "快照记录 (Snapshots)" },
      { id: "imports", label: "Git 导入任务 (Imports)" },
      { id: "audit", label: "安全审计日志 (Audit)" },
    ];
    wrap.appendChild(
      el(
        "div",
        { className: "subtabs" },
        subDefs.map((s) =>
          el("button", {
            type: "button",
            className: state.opsSubtab === s.id ? "subtab active" : "subtab",
            text: s.label,
            onClick: async () => {
              if (state.opsSubtab === s.id) return;
              state.opsSubtab = s.id;
              try {
                await loadCurrentTab(false);
              } catch (err) {
                toast(err.message, true);
              }
            },
          })
        )
      )
    );
  }

  if (state.opsSubtab === "snapshots") {
    wrap.appendChild(buildSnapshotsPanel(admin));
  } else if (state.opsSubtab === "imports" && admin) {
    wrap.appendChild(buildImportsPanel());
  } else if (state.opsSubtab === "audit" && admin) {
    wrap.appendChild(buildAuditPanel());
  }
  return wrap;
}

function buildSnapshotsPanel(admin) {
  const panel = el("div", { className: "panel" });
  const snaps = (((state.snapshotsData && state.snapshotsData.snapshots) || []).slice()).reverse();
  if (snaps.length === 0) {
    panel.appendChild(el("div", { className: "empty-box", text: "暂无已发布的项目快照" }));
    return panel;
  }

  const tbody = el("tbody", {});
  for (const s of snaps) {
    const pins = s.Pins || [];
    const detailRow = el("tr", { hidden: true });
    const detailCell = el("td", { colspan: "5" });
    detailRow.appendChild(detailCell);

    const toggleBtn = el("button", {
      type: "button",
      className: "btn btn-xs",
      text: `展开模块列表 (${pins.length})`,
      disabled: pins.length === 0,
      onClick: () => {
        detailRow.hidden = !detailRow.hidden;
        toggleBtn.textContent = detailRow.hidden ? `展开模块列表 (${pins.length})` : "收起模块列表";
        if (!detailRow.hidden && !detailCell.firstChild) {
          const lines = pins.map((p) => `${p.name.padEnd(28, " ")}  repo=${p.repository_id}  rev=${shortID(p.revision, 16)}`);
          detailCell.appendChild(el("div", { className: "code-block", text: lines.join("\n") }));
        }
      },
    });

    const countText = admin && s.TotalPins ? `可见 ${pins.length} / 总计 ${s.TotalPins} 个模块` : `${pins.length} 个已授权模块`;
    tbody.append(
      el(
        "tr",
        {},
        el("td", { className: "mono cell-title", text: `Snapshot #${s.ID}` }),
        el("td", { text: fmtTime(s.CreatedAt) }),
        el("td", { className: "mono", text: s.Description || "—" }),
        el("td", { text: countText }),
        el("td", {}, toggleBtn)
      ),
      detailRow
    );
  }

  panel.appendChild(
    el(
      "div",
      { className: "table-scroll" },
      el(
        "table",
        { className: "data-table" },
        el("thead", {}, el("tr", {}, el("th", { text: "快照编号" }), el("th", { text: "发布时间" }), el("th", { text: "操作标识" }), el("th", { text: "固定模块数" }), el("th", { text: "详情" }))),
        tbody
      )
    )
  );
  return panel;
}

function buildImportsPanel() {
  const panel = el("div", { className: "panel" });
  const jobs = (state.importsData && state.importsData.jobs) || [];
  if (jobs.length === 0) {
    panel.appendChild(el("div", { className: "empty-box", text: "暂无外部 Git 导入记录" }));
    return panel;
  }

  const tbody = el("tbody", {});
  for (const j of jobs) {
    const items = j.items || [];
    const detailRow = el("tr", { hidden: true });
    const detailCell = el("td", { colspan: "6" });
    detailRow.appendChild(detailCell);

    const toggleBtn = el("button", {
      type: "button",
      className: "btn btn-xs",
      text: `查看子项 (${items.length})`,
      disabled: items.length === 0,
      onClick: () => {
        detailRow.hidden = !detailRow.hidden;
        toggleBtn.textContent = detailRow.hidden ? `查看子项 (${items.length})` : "收起子项";
        if (!detailRow.hidden && !detailCell.firstChild) {
          const lines = items.map((it) => {
            const v = it.verification || {};
            return `[${it.status}] ${it.module_name} | passed=${Boolean(v.passed)} | commits=${v.mapped_commits ?? v.source_commits ?? 0}/${v.raw_source_commits ?? 0} | branches=${v.imported_branches ?? v.source_branches ?? 0}${it.error ? ` | err=${it.error}` : ""}`;
          });
          detailCell.appendChild(el("div", { className: "code-block", text: lines.join("\n") }));
        }
      },
    });

    const badgeCls =
      j.status === "succeeded" ? "badge badge-success" : j.status === "running" ? "badge badge-primary" : "badge badge-danger";

    tbody.append(
      el(
        "tr",
        {},
        el("td", { className: "mono cell-title", text: `#${j.job_id}` }),
        el("td", { className: "mono", text: j.job_key }),
        el("td", {}, el("span", { className: "badge badge-neutral mono", text: j.mode })),
        el("td", {}, el("span", { className: badgeCls, text: j.status })),
        el("td", { className: "mono", text: `成功 ${j.succeeded_items} · 跳过 ${j.skipped_items} · 失败 ${j.failed_items} / 共 ${j.total_items}` }),
        el("td", {}, toggleBtn)
      ),
      detailRow
    );
  }

  panel.appendChild(
    el(
      "div",
      { className: "table-scroll" },
      el(
        "table",
        { className: "data-table" },
        el("thead", {}, el("tr", {}, el("th", { text: "Job ID" }), el("th", { text: "Job Key" }), el("th", { text: "模式" }), el("th", { text: "状态" }), el("th", { text: "结果统计" }), el("th", { text: "子项" }))),
        tbody
      )
    )
  );
  return panel;
}

function buildAuditPanel() {
  const outer = el("div", {});
  const entries = (state.auditData && state.auditData.entries) || [];
  const panel = el("div", { className: "panel" });

  const searchInp = el("input", {
    type: "search",
    className: "input input-search",
    placeholder: "过滤审计动作 / 操作人 / 目标 / 详情...",
    value: state.auditSearch,
    onInput: () => {
      state.auditSearch = searchInp.value;
      renderRows();
    },
  });
  outer.append(el("div", { className: "toolbar" }, el("div", { className: "toolbar-group" }, searchInp)), panel);

  function renderRows() {
    clear(panel);
    const q = state.auditSearch.trim().toLowerCase();
    const filtered = entries.filter(
      (e) => !q || `${e.actor} ${e.action} ${e.target} ${e.detail}`.toLowerCase().includes(q)
    );
    if (filtered.length === 0) {
      panel.appendChild(el("div", { className: "empty-box", text: "没有匹配的审计记录" }));
      return;
    }
    const tbody = el("tbody", {});
    for (const e of filtered) {
      tbody.appendChild(
        el(
          "tr",
          {},
          el("td", { className: "mono cell-sub", text: `#${e.audit_id}` }),
          el("td", { className: "mono", text: fmtTime(e.at) }),
          el("td", { className: "mono cell-title", text: e.actor }),
          el("td", {}, el("span", { className: "badge badge-neutral mono", text: e.action })),
          el("td", { className: "mono", text: e.target || "—" }),
          el("td", { className: "mono cell-sub", text: e.detail || "—" })
        )
      );
    }
    panel.appendChild(
      el(
        "div",
        { className: "table-scroll" },
        el(
          "table",
          { className: "data-table" },
          el("thead", {}, el("tr", {}, el("th", { text: "ID" }), el("th", { text: "时间" }), el("th", { text: "操作者" }), el("th", { text: "动作" }), el("th", { text: "目标" }), el("th", { text: "详情" }))),
          tbody
        )
      )
    );
  }

  renderRows();
  return outer;
}

/* ============================ Bootstrap ============================ */

setUnauthorizedHandler((msg) => {
  renderLogin(`登录状态已失效：${msg}`);
});

window.addEventListener("console:relogin", () => {
  setToken("");
  renderLogin();
});

window.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") {
    closeModal();
    closeDrawer();
  }
});

if (getToken()) {
  bootAuthenticated();
} else {
  renderLogin();
}
