package com.company.jmixpm.security;

import com.company.jmixpm.entity.Document;
import io.jmix.security.role.annotation.JpqlRowLevelPolicy;
import io.jmix.security.role.annotation.RowLevelRole;

import javax.annotation.Nonnull;

@Nonnull
@RowLevelRole(name = "RestrictedDocumentsRole", code = "restricted-documents-role")
public interface RestrictedDocumentsRole {

    @JpqlRowLevelPolicy(entityClass = Document.class, join="join {E}.project proj",
            where="proj.manager.id = :current_user_id or {E}.createdBy = :current_user_username")
    void restrictedDocumentByProjectManager();
}