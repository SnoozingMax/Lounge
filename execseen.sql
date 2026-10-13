-- =====================================================================
--  LOUNGE  ·  upgrade 12: /execute replay seen once per account
--  Run ONCE in Supabase SQL Editor
-- =====================================================================

create table if not exists public.exec_seen (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  last_id bigint not null default 0
);
alter table public.exec_seen enable row level security;
drop policy if exists "exec seen own" on public.exec_seen;
create policy "exec seen own" on public.exec_seen for select to authenticated using (user_id = auth.uid());

create or replace function public.mark_exec_seen(p_id bigint) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return; end if;
  insert into exec_seen (user_id, last_id) values (auth.uid(), p_id)
  on conflict (user_id) do update set last_id = greatest(exec_seen.last_id, excluded.last_id);
end $$;
