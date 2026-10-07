-- =====================================================================
--  LOUNGE  ·  upgrade 9: deny with a reason
--  Run ONCE in Supabase SQL Editor
-- =====================================================================

alter table public.profiles add column if not exists denied_reason text check (char_length(denied_reason) <= 200);

create or replace function public.admin_deny(p_user uuid, p_reason text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'Admins only'; end if;
  if exists (select 1 from profiles where id = p_user and approved) then raise exception 'They are already in. Ban them instead.'; end if;
  update profiles set denied_reason = coalesce(nullif(trim(p_reason), ''), 'No reason given') where id = p_user;
end $$;

-- letting someone in clears any old denial
create or replace function public.admin_approve(p_user uuid, p_ok boolean) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if not is_admin() then raise exception 'Admins only'; end if;
  if p_ok then
    update profiles set approved = true, denied_reason = null where id = p_user;
  else
    if exists (select 1 from profiles where id = p_user and approved) then raise exception 'They are already in. Ban them instead.'; end if;
    delete from auth.users where id = p_user;
  end if;
end $$;
