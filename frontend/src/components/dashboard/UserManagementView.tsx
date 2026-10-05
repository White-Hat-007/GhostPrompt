'use client';

import React, { useState, useEffect, useCallback } from "react";
import { Users, Shield, Trash2, ShieldAlert, Loader2, Check, X, Key, Plus, AlertTriangle, Pencil } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

// ── Built-in role definitions (read-only, mirrored from backend) ──
const BUILTIN_ROLES = [
  { id: "org_owner", name: "Owner" },
  { id: "org_admin", name: "Admin" },
  { id: "security_analyst", name: "Analyst" },
  { id: "developer", name: "Developer" },
  { id: "read_only", name: "Read Only" },
];

const PERMISSION_GROUPS = [
  {
    group: "Platform",
    items: [
      { id: "dashboard.view", label: "View Dashboard" },
      { id: "settings.manage", label: "Manage Settings" },
      { id: "billing.manage", label: "Manage Billing" },
    ],
  },
  {
    group: "Scanning",
    items: [
      { id: "scan.view", label: "View Scans" },
      { id: "scan.create", label: "Create Scans" },
      { id: "scan.execute", label: "Execute Scans" },
    ],
  },
  {
    group: "Security",
    items: [
      { id: "incidents.view", label: "View Incidents" },
      { id: "incidents.edit", label: "Edit Incidents" },
      { id: "policies.manage", label: "Manage Policies" },
      { id: "red_team.execute", label: "Run Red Team" },
    ],
  },
  {
    group: "Intelligence",
    items: [
      { id: "cybermap.view", label: "View Cybermap" },
      { id: "threat_intel.view", label: "View Threat Intel" },
      { id: "attribution.view", label: "View Attribution" },
      { id: "audit_log.view", label: "View Audit Log" },
    ],
  },
  {
    group: "Admin",
    items: [
      { id: "members.manage", label: "Manage Members" },
      { id: "roles.manage", label: "Manage Roles" },
      { id: "api_keys.manage", label: "Manage API Keys" },
      { id: "integrations.manage", label: "Manage Integrations" },
    ],
  },
];

// Static built-in role permission mapping
const DEFAULT_MATRIX: Record<string, string[]> = {
  org_owner: [
    "dashboard.view", "settings.manage", "billing.manage",
    "scan.view", "scan.create", "scan.execute",
    "incidents.view", "incidents.edit", "policies.manage", "red_team.execute",
    "cybermap.view", "threat_intel.view", "attribution.view", "audit_log.view",
    "members.manage", "roles.manage", "api_keys.manage", "integrations.manage",
  ],
  org_admin: [
    "dashboard.view", "settings.manage",
    "scan.view", "scan.create", "scan.execute",
    "incidents.view", "incidents.edit", "policies.manage", "red_team.execute",
    "cybermap.view", "threat_intel.view", "attribution.view", "audit_log.view",
    "members.manage", "api_keys.manage", "integrations.manage",
  ],
  security_analyst: [
    "dashboard.view",
    "scan.view", "scan.create", "scan.execute",
    "incidents.view", "incidents.edit", "red_team.execute",
    "cybermap.view", "threat_intel.view", "attribution.view", "audit_log.view",
  ],
  developer: [
    "dashboard.view",
    "scan.view", "scan.create", "scan.execute",
    "incidents.view",
    "cybermap.view",
    "api_keys.manage",
  ],
  read_only: [
    "dashboard.view",
    "scan.view",
    "incidents.view",
    "cybermap.view",
    "audit_log.view",
  ],
};

interface CustomRole {
  id: string;
  name: string;
  description: string | null;
  is_builtin: boolean;
  permissions: Record<string, boolean>;
  organization_id: string | null;
}

interface UserRecord {
  id: string;
  email: string;
  full_name: string | null;
  username: string | null;
  role: string;
  is_active: boolean;
  is_verified: boolean;
}

export default function UserManagementView({ isDemo = false }: { isDemo?: boolean }) {
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [customRoles, setCustomRoles] = useState<CustomRole[]>([]);
  const [loading, setLoading] = useState(true);
  const [rolesLoading, setRolesLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<"users" | "matrix">("users");

  // Create Role Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newRoleName, setNewRoleName] = useState("");
  const [newRoleDesc, setNewRoleDesc] = useState("");
  const [newRolePerms, setNewRolePerms] = useState<Record<string, boolean>>({});
  const [creating, setCreating] = useState(false);

  // Saving indicator
  const [savingPerm, setSavingPerm] = useState<string | null>(null);

  const getAuthHeader = useCallback(() => {
    const token = localStorage.getItem('access_token');
    return { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };
  }, []);

  // ── Fetch Users ──
  const fetchUsers = useCallback(async () => {
    const token = localStorage.getItem('access_token');
    if (isDemo || !token) {
      setUsers([
        { id: "1", email: "alice@acme.corp", full_name: "Alice Smith", username: "alice", role: "owner", is_active: true, is_verified: true },
        { id: "2", email: "bob@acme.corp", full_name: "Bob Jones", username: "bob", role: "admin", is_active: true, is_verified: true },
      ]);
      setLoading(false);
      return;
    }

    try {
      const res = await fetch(`${API_URL}/api/v1/admin/users`, { headers: getAuthHeader() });
      if (!res.ok) throw new Error("Failed to fetch users");
      const data = await res.json();
      setUsers(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [isDemo, getAuthHeader]);

  // ── Fetch Custom Roles ──
  const fetchRoles = useCallback(async () => {
    const token = localStorage.getItem('access_token');
    if (isDemo || !token) {
      setRolesLoading(false);
      return;
    }

    try {
      const res = await fetch(`${API_URL}/api/v1/admin/roles`, { headers: getAuthHeader() });
      if (!res.ok) throw new Error("Failed to fetch roles");
      const data: CustomRole[] = await res.json();
      // Filter to only show custom (non-builtin) roles
      setCustomRoles(data.filter(r => !r.is_builtin));
    } catch (err: any) {
      console.error("Failed to fetch roles:", err);
    } finally {
      setRolesLoading(false);
    }
  }, [isDemo, getAuthHeader]);

  useEffect(() => {
    fetchUsers();
    fetchRoles();
  }, [fetchUsers, fetchRoles]);

  // ── Update User ──
  const updateUser = async (userId: string, updates: any) => {
    if (isDemo) { alert("Disabled in demo mode."); return; }
    try {
      const res = await fetch(`${API_URL}/api/v1/admin/users/${userId}`, {
        method: "PUT",
        headers: getAuthHeader(),
        body: JSON.stringify(updates),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || "Failed to update user");
      }
      fetchUsers();
    } catch (err: any) {
      alert(err.message);
    }
  };

  // ── Delete User ──
  const deleteUser = async (userId: string) => {
    if (isDemo) { alert("Disabled in demo mode."); return; }
    if (!confirm("Are you sure you want to permanently delete this user?")) return;
    try {
      const res = await fetch(`${API_URL}/api/v1/admin/users/${userId}`, {
        method: "DELETE",
        headers: getAuthHeader(),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || "Failed to delete user");
      }
      fetchUsers();
    } catch (err: any) {
      alert(err.message);
    }
  };

  // ── Create Custom Role ──
  const createRole = async () => {
    if (!newRoleName.trim()) return;
    setCreating(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/admin/roles`, {
        method: "POST",
        headers: getAuthHeader(),
        body: JSON.stringify({
          name: newRoleName.trim(),
          description: newRoleDesc.trim() || null,
          permissions: newRolePerms,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || "Failed to create role");
      }
      setShowCreateModal(false);
      setNewRoleName("");
      setNewRoleDesc("");
      setNewRolePerms({});
      fetchRoles();
    } catch (err: any) {
      alert(err.message);
    } finally {
      setCreating(false);
    }
  };

  // ── Toggle Permission on Custom Role ──
  const togglePermission = async (roleId: string, permKey: string, currentVal: boolean) => {
    const savingKey = `${roleId}:${permKey}`;
    setSavingPerm(savingKey);

    const role = customRoles.find(r => r.id === roleId);
    if (!role) return;

    const updatedPerms = { ...role.permissions, [permKey]: !currentVal };

    try {
      const res = await fetch(`${API_URL}/api/v1/admin/roles/${roleId}`, {
        method: "PUT",
        headers: getAuthHeader(),
        body: JSON.stringify({ permissions: updatedPerms }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || "Failed to update permission");
      }
      // Optimistic update
      setCustomRoles(prev => prev.map(r =>
        r.id === roleId ? { ...r, permissions: updatedPerms } : r
      ));
    } catch (err: any) {
      alert(err.message);
    } finally {
      setSavingPerm(null);
    }
  };

  // ── Delete Custom Role ──
  const deleteRole = async (roleId: string, roleName: string) => {
    if (!confirm(`Delete custom role "${roleName}"? Users assigned to it will need to be reassigned.`)) return;
    try {
      const res = await fetch(`${API_URL}/api/v1/admin/roles/${roleId}`, {
        method: "DELETE",
        headers: getAuthHeader(),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || "Failed to delete role");
      }
      fetchRoles();
    } catch (err: any) {
      alert(err.message);
    }
  };

  // ── Resolve display name for a role ──
  const resolveRoleName = (role: string): string => {
    const builtin = BUILTIN_ROLES.find(r => r.id === role);
    if (builtin) return builtin.name;
    // Legacy role names
    if (role === 'owner') return 'Owner';
    if (role === 'admin') return 'Admin';
    if (role === 'analyst') return 'Analyst';
    if (role === 'viewer') return 'Viewer';
    // Custom role UUID
    const custom = customRoles.find(r => r.id === role);
    if (custom) return custom.name;
    return role;
  };

  // ── All permission items flat ──
  const allPermItems = PERMISSION_GROUPS.flatMap(g => g.items);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-bold text-white tracking-tight flex items-center gap-3">
            <ShieldAlert className="w-6 h-6 text-emerald-400" />
            Organization Team Management
          </h2>
          <p className="text-sm text-gray-500 mt-1">Manage users, roles, and granular permissions</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-4 mb-6 border-b border-white/10 pb-4">
        <button
          onClick={() => setActiveTab("users")}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors ${
            activeTab === "users" ? "bg-ghost-500/20 text-ghost-400" : "text-gray-500 hover:text-gray-300"
          }`}
        >
          <Users className="w-4 h-4" /> Team Members
        </button>
        <button
          onClick={() => setActiveTab("matrix")}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors ${
            activeTab === "matrix" ? "bg-ghost-500/20 text-ghost-400" : "text-gray-500 hover:text-gray-300"
          }`}
        >
          <Key className="w-4 h-4" /> Permission Matrix
        </button>
      </div>

      <div className="glass-card p-0 overflow-hidden border border-white/5 shadow-2xl">

        {/* ═══════════════════════════════════════════════════════════
            TAB: TEAM MEMBERS
           ═══════════════════════════════════════════════════════════ */}
        {activeTab === "users" ? (
          <div>
            <div className="p-6 border-b border-white/5 flex items-center gap-3">
              <Users className="w-5 h-5 text-ghost-400" />
              <h3 className="text-lg font-bold text-white">Registered Users</h3>
            </div>

            {error && (
              <div className="p-4 bg-red-500/10 border-b border-red-500/20 text-red-400 text-sm">
                {error}
              </div>
            )}

            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-gray-400">
                <thead className="text-xs uppercase bg-surface-1/50 text-gray-500 border-b border-white/5">
                  <tr>
                    <th className="px-6 py-4 font-semibold tracking-wider">User</th>
                    <th className="px-6 py-4 font-semibold tracking-wider">Role</th>
                    <th className="px-6 py-4 font-semibold tracking-wider">Status</th>
                    <th className="px-6 py-4 font-semibold tracking-wider">Verified</th>
                    <th className="px-6 py-4 font-semibold tracking-wider text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {loading ? (
                    <tr>
                      <td colSpan={5} className="px-6 py-12 text-center">
                        <Loader2 className="w-6 h-6 animate-spin text-ghost-400 mx-auto" />
                      </td>
                    </tr>
                  ) : users.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-6 py-12 text-center text-gray-500">
                        No users found.
                      </td>
                    </tr>
                  ) : (
                    users.map((user) => (
                      <tr key={user.id} className="hover:bg-surface-0/30 transition-colors">
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-ghost-500/20 to-cyber-500/20 flex items-center justify-center border border-white/5">
                              <span className="text-xs font-bold text-white uppercase">
                                {user.full_name?.charAt(0) || user.email.charAt(0)}
                              </span>
                            </div>
                            <div>
                              <div className="text-white font-medium">{user.full_name || user.username || "Unknown"}</div>
                              <div className="text-xs text-gray-500">{user.email}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <select
                            value={user.role}
                            onChange={(e) => updateUser(user.id, { role: e.target.value })}
                            className="bg-surface-0 border border-white/10 rounded px-2 py-1 text-xs text-white focus:outline-none focus:border-ghost-500"
                            disabled={user.role === 'owner'}
                          >
                            <optgroup label="Built-in Roles">
                              <option value="admin">Admin</option>
                              <option value="analyst">Analyst</option>
                              <option value="viewer">Viewer</option>
                              {user.role === 'owner' && <option value="owner">Owner</option>}
                            </optgroup>
                            {customRoles.length > 0 && (
                              <optgroup label="Custom Roles">
                                {customRoles.map(cr => (
                                  <option key={cr.id} value={cr.id}>{cr.name}</option>
                                ))}
                              </optgroup>
                            )}
                          </select>
                          <div className="text-[10px] text-gray-600 mt-0.5 font-mono">
                            {resolveRoleName(user.role)}
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <button
                            onClick={() => updateUser(user.id, { is_active: !user.is_active })}
                            disabled={user.role === 'owner'}
                            className={`px-3 py-1 rounded-full text-[10px] font-semibold tracking-wide transition-colors ${
                              user.is_active
                                ? "bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"
                                : "bg-red-500/10 text-red-400 hover:bg-red-500/20"
                            }`}
                          >
                            {user.is_active ? "ACTIVE" : "DISABLED"}
                          </button>
                        </td>
                        <td className="px-6 py-4">
                          <button
                            onClick={() => updateUser(user.id, { is_verified: !user.is_verified })}
                            className="flex items-center justify-center p-1.5 rounded-md hover:bg-surface-0 transition-colors"
                            title="Toggle verification"
                          >
                            {user.is_verified ? (
                              <Check className="w-4 h-4 text-emerald-400" />
                            ) : (
                              <X className="w-4 h-4 text-red-500" />
                            )}
                          </button>
                        </td>
                        <td className="px-6 py-4 text-right">
                          <button
                            onClick={() => deleteUser(user.id)}
                            disabled={user.role === 'owner'}
                            className="p-2 text-gray-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors disabled:opacity-30"
                            title="Delete User"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

        ) : (
          /* ═══════════════════════════════════════════════════════════
              TAB: PERMISSION MATRIX
             ═══════════════════════════════════════════════════════════ */
          <div className="p-6">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <Shield className="w-5 h-5 text-ghost-400" />
                <h3 className="text-lg font-bold text-white">Role Permissions (RBAC)</h3>
              </div>
              <button
                onClick={() => setShowCreateModal(true)}
                className="btn-primary flex items-center gap-2 text-sm"
              >
                <Plus className="w-4 h-4" /> Create Custom Role
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-gray-400">
                <thead className="text-xs uppercase bg-surface-1/50 text-gray-500 border-b border-white/5">
                  <tr>
                    <th className="px-4 py-3 font-semibold tracking-wider sticky left-0 bg-surface-1/50 z-10">Permission</th>
                    {/* Built-in role columns */}
                    {BUILTIN_ROLES.map(role => (
                      <th key={role.id} className="px-4 py-3 font-semibold tracking-wider text-center min-w-[100px]">
                        <div className="flex flex-col items-center gap-1">
                          <span>{role.name}</span>
                          <span className="text-[8px] text-gray-600 font-normal normal-case">built-in</span>
                        </div>
                      </th>
                    ))}
                    {/* Custom role columns */}
                    {customRoles.map(cr => (
                      <th key={cr.id} className="px-4 py-3 font-semibold tracking-wider text-center min-w-[120px]">
                        <div className="flex flex-col items-center gap-1">
                          <span className="text-ghost-400">{cr.name}</span>
                          <div className="flex items-center gap-1">
                            <span className="text-[8px] text-ghost-500/60 font-normal normal-case">custom</span>
                            <button
                              onClick={() => deleteRole(cr.id, cr.name)}
                              className="p-0.5 text-gray-600 hover:text-red-400 transition-colors"
                              title={`Delete "${cr.name}" role`}
                            >
                              <Trash2 className="w-2.5 h-2.5" />
                            </button>
                          </div>
                        </div>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {PERMISSION_GROUPS.map(group => (
                    <React.Fragment key={group.group}>
                      {/* Group header */}
                      <tr className="bg-surface-0/50">
                        <td
                          colSpan={BUILTIN_ROLES.length + customRoles.length + 1}
                          className="px-4 py-2 text-xs font-bold text-ghost-400 uppercase tracking-widest"
                        >
                          {group.group}
                        </td>
                      </tr>
                      {/* Permission rows */}
                      {group.items.map(item => (
                        <tr key={item.id} className="hover:bg-surface-0/30 transition-colors">
                          <td className="px-4 py-3 text-gray-300 sticky left-0 bg-[#0a0e1a]/95 z-10">
                            {item.label}
                            <div className="text-[10px] text-gray-600 font-mono">{item.id}</div>
                          </td>
                          {/* Built-in role cells (read-only) */}
                          {BUILTIN_ROLES.map(role => {
                            const hasPerm = DEFAULT_MATRIX[role.id]?.includes(item.id);
                            return (
                              <td key={role.id} className="px-4 py-3 text-center">
                                {hasPerm ? (
                                  <Check className="w-4 h-4 text-emerald-400 mx-auto" />
                                ) : (
                                  <X className="w-4 h-4 text-white/10 mx-auto" />
                                )}
                              </td>
                            );
                          })}
                          {/* Custom role cells (interactive) */}
                          {customRoles.map(cr => {
                            const hasPerm = !!cr.permissions[item.id];
                            const isSaving = savingPerm === `${cr.id}:${item.id}`;
                            return (
                              <td key={cr.id} className="px-4 py-3 text-center">
                                <button
                                  onClick={() => togglePermission(cr.id, item.id, hasPerm)}
                                  disabled={isSaving}
                                  className={`w-6 h-6 rounded-md border transition-all duration-200 flex items-center justify-center mx-auto ${
                                    hasPerm
                                      ? "bg-ghost-500/20 border-ghost-500/40 hover:bg-ghost-500/30"
                                      : "bg-transparent border-white/10 hover:border-white/30 hover:bg-white/5"
                                  }`}
                                  title={`${hasPerm ? "Revoke" : "Grant"} ${item.id} for ${cr.name}`}
                                >
                                  {isSaving ? (
                                    <Loader2 className="w-3 h-3 animate-spin text-ghost-400" />
                                  ) : hasPerm ? (
                                    <Check className="w-3.5 h-3.5 text-ghost-400" />
                                  ) : null}
                                </button>
                              </td>
                            );
                          })}
                        </tr>
                      ))}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="mt-4 text-xs text-gray-500 flex items-center justify-between">
              <span>* Built-in roles are read-only. Custom roles can be toggled per permission.</span>
              <span className="text-ghost-500/50 font-mono">{customRoles.length} custom role{customRoles.length !== 1 ? 's' : ''}</span>
            </div>
          </div>
        )}
      </div>

      {/* ═══════════════════════════════════════════════════════════
          CREATE CUSTOM ROLE MODAL
         ═══════════════════════════════════════════════════════════ */}
      <AnimatePresence>
        {showCreateModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setShowCreateModal(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="glass-card w-full max-w-2xl max-h-[85vh] overflow-y-auto border border-white/10 shadow-2xl"
            >
              <div className="p-6 border-b border-white/5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-ghost-500/10 border border-ghost-500/20 flex items-center justify-center">
                      <Shield className="w-5 h-5 text-ghost-400" />
                    </div>
                    <div>
                      <h3 className="text-lg font-bold text-white">Create Custom Role</h3>
                      <p className="text-xs text-gray-500">Define granular permissions for your team</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setShowCreateModal(false)}
                    className="p-2 text-gray-500 hover:text-white rounded-lg hover:bg-surface-0 transition-colors"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
              </div>

              <div className="p-6 space-y-6">
                {/* Role Name */}
                <div>
                  <label className="block text-sm text-gray-400 mb-2">Role Name</label>
                  <input
                    type="text"
                    value={newRoleName}
                    onChange={(e) => setNewRoleName(e.target.value)}
                    placeholder="e.g. SOC Operator, Compliance Auditor"
                    className="w-full bg-surface-0 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white placeholder:text-gray-600 focus:outline-none focus:border-ghost-500 transition-colors"
                    maxLength={64}
                  />
                </div>

                {/* Description */}
                <div>
                  <label className="block text-sm text-gray-400 mb-2">Description (optional)</label>
                  <input
                    type="text"
                    value={newRoleDesc}
                    onChange={(e) => setNewRoleDesc(e.target.value)}
                    placeholder="Brief description of this role's purpose"
                    className="w-full bg-surface-0 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white placeholder:text-gray-600 focus:outline-none focus:border-ghost-500 transition-colors"
                  />
                </div>

                {/* Permission Picker */}
                <div>
                  <label className="block text-sm text-gray-400 mb-3">Permissions</label>
                  <div className="space-y-4">
                    {PERMISSION_GROUPS.map(group => (
                      <div key={group.group}>
                        <div className="text-[10px] text-ghost-400 font-bold uppercase tracking-widest mb-2">{group.group}</div>
                        <div className="grid grid-cols-2 gap-2">
                          {group.items.map(item => {
                            const isChecked = !!newRolePerms[item.id];
                            return (
                              <button
                                key={item.id}
                                onClick={() => setNewRolePerms(prev => ({ ...prev, [item.id]: !prev[item.id] }))}
                                className={`flex items-center gap-2.5 px-3 py-2 rounded-lg border transition-all text-left ${
                                  isChecked
                                    ? "bg-ghost-500/10 border-ghost-500/30 text-white"
                                    : "bg-surface-0/50 border-white/5 text-gray-500 hover:border-white/20 hover:text-gray-300"
                                }`}
                              >
                                <div className={`w-4 h-4 rounded border flex items-center justify-center flex-shrink-0 ${
                                  isChecked ? "bg-ghost-500 border-ghost-500" : "border-white/20"
                                }`}>
                                  {isChecked && <Check className="w-3 h-3 text-white" />}
                                </div>
                                <div>
                                  <div className="text-xs font-medium">{item.label}</div>
                                  <div className="text-[9px] font-mono text-gray-600">{item.id}</div>
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Footer */}
              <div className="p-6 border-t border-white/5 flex items-center justify-between">
                <div className="text-xs text-gray-500">
                  {Object.values(newRolePerms).filter(Boolean).length} permission{Object.values(newRolePerms).filter(Boolean).length !== 1 ? 's' : ''} selected
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => setShowCreateModal(false)}
                    className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={createRole}
                    disabled={creating || !newRoleName.trim()}
                    className="btn-primary flex items-center gap-2 text-sm disabled:opacity-50"
                  >
                    {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                    Create Role
                  </button>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
