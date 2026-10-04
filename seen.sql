-- =====================================================================
--  LOUNGE  ·  upgrade 8: last online
--  Run ONCE in Supabase SQL Editor
-- =====================================================================

create table if not exists public.last_seen (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  at timestamptz not null default now()
);
alter table public.last_seen enable row level security;
drop policy if exists "seen read" on public.last_seen;
create policy "seen read" on public.last_seen for select to authenticated using (public.is_approved());

create or replace function public.touch_seen() returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return; end if;
  insert into last_seen (user_id, at) values (auth.uid(), now())
  on conflict (user_id) do update set at = now();
end $$;
