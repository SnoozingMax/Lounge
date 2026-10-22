-- =====================================================================
--  LOUNGE  ·  upgrade 13: revive animation on unban
--  Run ONCE in Supabase SQL Editor
-- =====================================================================

alter table public.executions add column if not exists kind text not null default 'execute'
  check (kind in ('execute','revive'));

create or replace function public.admin_revive(p_user uuid) returns bigint
language plpgsql security definer set search_path = public as $$
declare eid bigint;
begin
  if not is_admin() then raise exception 'Admins only'; end if;
  update profiles set banned = false where id = p_user;
  if not found then raise exception 'User not found'; end if;
  insert into executions (user_id, by_id, kind) values (p_user, auth.uid(), 'revive') returning id into eid;
  return eid;
end $$;
