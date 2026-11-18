import { api } from "./api.js";
import { el, clear, toast } from "./dom.js";
import { KUBEE_KNOWN_NAMES } from "./presets.js";

function modalRoot() {
  return document.getElementById("modal-root");
}

export function closeModal() {
  const root = modalRoot();
  if (!root) return;
  root.hidden = true;
  clear(root);
}

export function showModal(title, buildBody) {
  const root = modalRoot();
  clear(root);
  const card = el("div", { className: "modal-card" });
  const header = el(
    "div",
    { className: "modal-header" },
    el("h3", { className: "modal-title", text: title }),
    el("button", { type: "button", className: "btn btn-sm", text: "关闭", onClick: closeModal })
  );
  card.appendChild(header);
  buildBody(card);
  root.onclick = (ev) => {
    if (ev.target === root) closeModal();
  };
  root.appendChild(card);
  root.hidden = false;
}

export function openConfirmModal({ title, message, confirmLabel = "确认执行", danger = false, onConfirm }) {
  showModal(title, (card) => {
    const errBox = el("div", { className: "error-banner", hidden: true });
    const msgEl = el("p", { text: message });
    const submitBtn = el("button", {
      type: "button",
      className: danger ? "btn btn-danger" : "btn btn-primary",
      text: confirmLabel,
      onClick: async () => {
        errBox.hidden = true;
        submitBtn.disabled = true;
        try {
          await onConfirm();
          closeModal();
        } catch (err) {
          errBox.textContent = err.message;
          errBox.hidden = false;
          submitBtn.disabled = false;
        }
      },
    });
    card.append(
      errBox,
      msgEl,
      el(
        "div",
        { className: "modal-actions" },
        el("button", { type: "button", className: "btn", text: "取消", onClick: closeModal }),
        submitBtn
      )
    );
  });
}

export function openOwnPasswordModal() {
  showModal("修改当前登录密码", (card) => {
    const errBox = el("div", { className: "error-banner", hidden: true });
    const pwInput = el("input", {
      type: "password",
      className: "input input-full",
      placeholder: "输入新密码（修改后其他设备旧会话将失效）",
      autocomplete: "new-password",
    });
    const pw2Input = el("input", {
      type: "password",
      className: "input input-full",
      placeholder: "再次输入新密码确认",
      autocomplete: "new-password",
    });
    const submitBtn = el("button", { type: "submit", className: "btn btn-primary", text: "保存新密码" });
    const form = el(
      "form",
      {
        onSubmit: async (ev) => {
          ev.preventDefault();
          errBox.hidden = true;
          if (!pwInput.value) {
            errBox.textContent = "新密码不能为空";
            errBox.hidden = false;
            return;
          }
          if (pwInput.value !== pw2Input.value) {
            errBox.textContent = "两次输入的密码不一致";
            errBox.hidden = false;
            return;
          }
          submitBtn.disabled = true;
          try {
            await api.changeOwnPassword(pwInput.value);
            closeModal();
            toast("密码已更新，请使用新密码重新登录");
            window.dispatchEvent(new CustomEvent("console:relogin"));
          } catch (err) {
            errBox.textContent = err.message;
            errBox.hidden = false;
            submitBtn.disabled = false;
          }
        },
      },
      errBox,
      el("div", { className: "form-field" }, el("label", { className: "form-label", text: "新密码" }), pwInput),
      el("div", { className: "form-field" }, el("label", { className: "form-label", text: "确认新密码" }), pw2Input),
      el(
        "div",
        { className: "modal-actions" },
        el("button", { type: "button", className: "btn", text: "取消", onClick: closeModal }),
        submitBtn
      )
    );
    card.appendChild(form);
    pwInput.focus();
  });
}

export function openResetMemberPasswordModal(member, projectId, onDone) {
  showModal(`重置密码：${member.username}`, (card) => {
    const errBox = el("div", { className: "error-banner", hidden: true });
    const pwInput = el("input", {
      type: "text",
      className: "input input-full",
      placeholder: "输入新的初始密码",
      value: member.username,
    });
    const submitBtn = el("button", { type: "submit", className: "btn btn-primary", text: "确认重置" });
    const form = el(
      "form",
      {
        onSubmit: async (ev) => {
          ev.preventDefault();
          errBox.hidden = true;
          if (!pwInput.value) {
            errBox.textContent = "密码不能为空";
            errBox.hidden = false;
            return;
          }
          submitBtn.disabled = true;
          try {
            await api.resetUserPassword(member.username, projectId, pwInput.value);
            closeModal();
            toast(`已重置 ${member.username} 的密码，旧会话已失效`);
            if (onDone) await onDone();
          } catch (err) {
            errBox.textContent = err.message;
            errBox.hidden = false;
            submitBtn.disabled = false;
          }
        },
      },
      errBox,
      el(
        "div",
        { className: "form-field" },
        el("label", { className: "form-label", text: "新密码" }),
        pwInput,
        el("div", { className: "form-hint", text: "默认预填为与用户名相同，可改为任意口令；重置后该成员旧登录态立即失效。" })
      ),
      el(
        "div",
        { className: "modal-actions" },
        el("button", { type: "button", className: "btn", text: "取消", onClick: closeModal }),
        submitBtn
      )
    );
    card.appendChild(form);
    pwInput.select();
  });
}

export function openCreateMemberModal(projectName, activeModules, onDone) {
  showModal(`新增成员并授权（${projectName}）`, (card) => {
    const errBox = el("div", { className: "error-banner", hidden: true });
    const userInp = el("input", {
      type: "text",
      className: "input input-full",
      placeholder: "小写字母/数字/下划线/连字符，如 alexisliao",
      autocomplete: "off",
    });
    const pwInp = el("input", {
      type: "text",
      className: "input input-full",
      placeholder: "初始密码",
      autocomplete: "off",
    });
    const sameCheck = el("input", { type: "checkbox", checked: true });

    userInp.addEventListener("input", () => {
      if (sameCheck.checked) {
        pwInp.value = userInp.value.trim();
      }
    });
    sameCheck.addEventListener("change", () => {
      pwInp.disabled = sameCheck.checked;
      if (sameCheck.checked) pwInp.value = userInp.value.trim();
    });
    pwInp.disabled = true;

    const roleSel = el(
      "select",
      { className: "select select-full" },
      el("option", { value: "project_member", text: "普通成员 (project_member)" }),
      el("option", { value: "project_admin", text: "项目管理员 (project_admin)" })
    );

    const grantSel = el(
      "select",
      { className: "select select-full" },
      el("option", { value: "all_write", text: `授予全部活跃仓库 write 权限（共 ${activeModules.length} 个）` }),
      el("option", { value: "selected_write", text: "自定义勾选指定仓库（write）" }),
      el("option", { value: "all_read", text: `授予全部活跃仓库 read 标签（共 ${activeModules.length} 个）` }),
      el("option", { value: "none", text: "仅加入项目，暂不分配仓库权限" })
    );

    const selectedIDs = new Set();
    const checkListWrap = el("div", { className: "form-field", hidden: true });
    const checkList = el("div", { className: "module-check-list" });
    for (const m of activeModules) {
      const cb = el("input", {
        type: "checkbox",
        onChange: () => {
          if (cb.checked) selectedIDs.add(m.module_id);
          else selectedIDs.delete(m.module_id);
        },
      });
      const labelTxt = m.display_name ? `${m.display_name} (${m.name})` : m.name;
      checkList.appendChild(el("label", { className: "checkbox-row" }, cb, el("span", { text: labelTxt })));
    }
    checkListWrap.append(el("label", { className: "form-label", text: "勾选要授权的仓库" }), checkList);

    grantSel.addEventListener("change", () => {
      checkListWrap.hidden = grantSel.value !== "selected_write";
    });

    const submitBtn = el("button", { type: "submit", className: "btn btn-primary", text: "创建并授权" });
    const form = el(
      "form",
      {
        onSubmit: async (ev) => {
          ev.preventDefault();
          errBox.hidden = true;
          const username = userInp.value.trim();
          const password = sameCheck.checked ? username : pwInp.value;
          if (!username || !password) {
            errBox.textContent = "用户名和密码均不能为空";
            errBox.hidden = false;
            return;
          }
          if (grantSel.value === "selected_write" && selectedIDs.size === 0) {
            errBox.textContent = "请至少勾选一个要授权的仓库，或切换授权策略";
            errBox.hidden = false;
            return;
          }
          submitBtn.disabled = true;
          try {
            const res = await api.createProjectUser(projectName, {
              username,
              password,
              role: roleSel.value,
              grant_mode: grantSel.value,
              module_ids: Array.from(selectedIDs),
            });
            closeModal();
            toast(`已创建用户 ${res.username}（已授权 ${res.granted_modules} 个仓库）`);
            if (onDone) await onDone();
          } catch (err) {
            errBox.textContent = err.message;
            errBox.hidden = false;
            submitBtn.disabled = false;
          }
        },
      },
      errBox,
      el("div", { className: "form-field" }, el("label", { className: "form-label", text: "用户名" }), userInp),
      el(
        "div",
        { className: "form-field" },
        el("label", { className: "form-label", text: "初始密码" }),
        pwInp,
        el("label", { className: "checkbox-row" }, sameCheck, el("span", { text: "初始密码与用户名相同" }))
      ),
      el("div", { className: "form-field" }, el("label", { className: "form-label", text: "项目角色" }), roleSel),
      el("div", { className: "form-field" }, el("label", { className: "form-label", text: "初始仓库权限" }), grantSel),
      checkListWrap,
      el(
        "div",
        { className: "modal-actions" },
        el("button", { type: "button", className: "btn", text: "取消", onClick: closeModal }),
        submitBtn
      )
    );
    card.appendChild(form);
    userInp.focus();
  });
}

export function openAddExistingUserModal(projectName, onDone) {
  showModal(`将已有账号加入 ${projectName}`, (card) => {
    const errBox = el("div", { className: "error-banner", hidden: true });
    const userInp = el("input", {
      type: "text",
      className: "input input-full",
      placeholder: "系统中已存在的用户名",
    });
    const roleSel = el(
      "select",
      { className: "select select-full" },
      el("option", { value: "project_member", text: "普通成员 (project_member)" }),
      el("option", { value: "project_admin", text: "项目管理员 (project_admin)" })
    );
    const submitBtn = el("button", { type: "submit", className: "btn btn-primary", text: "加入项目" });
    const form = el(
      "form",
      {
        onSubmit: async (ev) => {
          ev.preventDefault();
          errBox.hidden = true;
          const username = userInp.value.trim();
          if (!username) {
            errBox.textContent = "请输入用户名";
            errBox.hidden = false;
            return;
          }
          submitBtn.disabled = true;
          try {
            await api.addExistingMember(projectName, username, roleSel.value);
            closeModal();
            toast(`已将 ${username} 加入项目`);
            if (onDone) await onDone();
          } catch (err) {
            errBox.textContent = err.message;
            errBox.hidden = false;
            submitBtn.disabled = false;
          }
        },
      },
      errBox,
      el("div", { className: "form-field" }, el("label", { className: "form-label", text: "用户名" }), userInp),
      el("div", { className: "form-field" }, el("label", { className: "form-label", text: "项目角色" }), roleSel),
      el(
        "div",
        { className: "modal-actions" },
        el("button", { type: "button", className: "btn", text: "取消", onClick: closeModal }),
        submitBtn
      )
    );
    card.appendChild(form);
    userInp.focus();
  });
}

export function openBulkMetadataModal(projectName, existingModules, onDone) {
  showModal(`批量同步游戏中文名（${projectName}）`, (card) => {
    const errBox = el("div", { className: "error-banner", hidden: true });
    const existingSet = new Set(existingModules.map((m) => m.name));
    const ta = el("textarea", {
      className: "textarea textarea-full",
      placeholder: "每行一条：模块名=中文游戏名\n例如：\ntide-holiday=潮汐假日\ncloudpunk-web-study=吸就完事了",
    });

    const fillKnown = () => {
      const lines = KUBEE_KNOWN_NAMES.filter((x) => existingSet.has(x.module_name)).map(
        (x) => `${x.module_name}=${x.display_name}`
      );
      ta.value = lines.join("\n");
    };
    fillKnown();

    const submitBtn = el("button", { type: "submit", className: "btn btn-primary", text: "保存映射" });
    const form = el(
      "form",
      {
        onSubmit: async (ev) => {
          ev.preventDefault();
          errBox.hidden = true;
          const items = [];
          const raw = ta.value.trim();
          if (!raw) {
            errBox.textContent = "请输入至少一条映射";
            errBox.hidden = false;
            return;
          }
          for (const line of raw.split(/\r?\n/)) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith("#")) continue;
            const sep = trimmed.includes("=") ? "=" : "\t";
            const idx = trimmed.indexOf(sep);
            if (idx <= 0) {
              errBox.textContent = `格式错误（需为 模块名=中文名）：${trimmed}`;
              errBox.hidden = false;
              return;
            }
            const module_name = trimmed.slice(0, idx).trim();
            const display_name = trimmed.slice(idx + 1).trim();
            items.push({ module_name, display_name });
          }
          submitBtn.disabled = true;
          try {
            const res = await api.bulkModuleMetadata(projectName, items);
            closeModal();
            toast(`已同步游戏中文名（更新 ${res.updated} 项）`);
            if (onDone) await onDone();
          } catch (err) {
            errBox.textContent = err.message;
            errBox.hidden = false;
            submitBtn.disabled = false;
          }
        },
      },
      errBox,
      el(
        "div",
        { className: "form-field" },
        el(
          "div",
          { className: "toolbar" },
          el("label", { className: "form-label", text: "模块名=中文游戏名（每行一条）" }),
          el("button", { type: "button", className: "btn btn-xs", text: "填入内置 Kubee 38 款映射", onClick: fillKnown })
        ),
        ta,
        el("div", { className: "form-hint", text: "仅更新本项目中匹配的活跃仓库显示名，不影响底层仓库目录与分支。" })
      ),
      el(
        "div",
        { className: "modal-actions" },
        el("button", { type: "button", className: "btn", text: "取消", onClick: closeModal }),
        submitBtn
      )
    );
    card.appendChild(form);
  });
}
