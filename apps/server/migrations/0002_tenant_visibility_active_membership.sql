-- Security review finding F-15: the tenants SELECT policy matched any
-- membership row, including SUSPENDED and REMOVED ones. The application
-- already checks membership status, but row-level security is the
-- defence-in-depth layer and should apply the same rule.

DROP POLICY tenants_select ON tenants;
CREATE POLICY tenants_select ON tenants FOR SELECT TO aegis_app USING (
  id = app_tenant_id()
  OR app_platform_scope()
  OR EXISTS (SELECT 1 FROM memberships m
              WHERE m.tenant_id = tenants.id
                AND m.principal_id = app_principal_id()
                AND m.status = 'ACTIVE'));
