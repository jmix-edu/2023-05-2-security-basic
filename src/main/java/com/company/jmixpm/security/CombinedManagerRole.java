package com.company.jmixpm.security;

import io.jmix.security.role.annotation.ResourceRole;
import io.jmix.securityui.role.UiMinimalRole;

import javax.annotation.Nonnull;

@Nonnull
@ResourceRole(name = "CombinedManagerRole", code = "combined-manager-role")
public interface CombinedManagerRole extends ProjectManagementRole, UiMinimalRole {
}