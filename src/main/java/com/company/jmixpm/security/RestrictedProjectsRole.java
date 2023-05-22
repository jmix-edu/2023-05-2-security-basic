package com.company.jmixpm.security;

import com.company.jmixpm.entity.Project;
import com.company.jmixpm.entity.User;
import io.jmix.core.security.CurrentAuthentication;
import io.jmix.security.model.RowLevelBiPredicate;
import io.jmix.security.model.RowLevelPolicyAction;
import io.jmix.security.role.annotation.PredicateRowLevelPolicy;
import io.jmix.security.role.annotation.RowLevelRole;
import org.springframework.context.ApplicationContext;

import javax.annotation.Nonnull;

@Nonnull
@RowLevelRole(name = "RestrictedProjectsRole", code = "restricted-projects-role")
public interface RestrictedProjectsRole {

    @PredicateRowLevelPolicy(entityClass = Project.class, actions = {RowLevelPolicyAction.UPDATE, RowLevelPolicyAction.DELETE})
    default RowLevelBiPredicate<Project, ApplicationContext> allowOnlyManagerUpdateOrDeleteProject() {
        return (project, context) -> {
            CurrentAuthentication currentAuth = context.getBean(CurrentAuthentication.class);
            User user = (User) currentAuth.getUser();
            return user.equals(project.getManager());
        };
    }
}