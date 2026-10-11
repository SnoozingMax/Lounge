-- =====================================================================
--  LOUNGE  ·  upgrade 10: /execute that people see even if offline
--  Run ONCE in Supabase SQL Editor
-- =====================================================================

create table if not exists public.executions (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  by_id uuid references public.profiles(id) on delete set null,
  at timestamptz not null default now()
);
alter table public.executions enable row level security;
drop policy if exists "executions read" on public.executions;
create policy "executions read" on public.executions for select to authenticated
  using (public.is_approved() or user_id = auth.uid());

create or replace function public.admin_execute(p_user uuid) returns bigint
language plpgsql security definer set search_path = public as $$
declare eid bigint;
begin
  if not is_admin() then raise exception 'Admins only'; end if;
  if p_user = auth.uid() then raise exception 'You can''t execute yourself'; end if;
  update profiles set banned = true where id = p_user;
  if not found then raise exception 'User not found'; end if;
  insert into executions (user_id, by_id) values (p_user, auth.uid()) returning id into eid;
  delete from executions where at < now() - interval '7 days';
  return eid;
end $$;

do $$ begin
  alter publication supabase_realtime add table public.executions;
exception when duplicate_object then null; end $$;
