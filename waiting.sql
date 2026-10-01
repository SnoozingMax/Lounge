-- =====================================================================
--  LOUNGE  ·  upgrade 5: waiting room
--  Run ONCE in Supabase SQL Editor
-- =====================================================================

alter table public.profiles add column if not exists approved boolean not null default false;
update public.profiles set approved = true;   -- everyone already here is in

create table if not exists public.app_settings (
  id int primary key default 1 check (id = 1),
  require_approval boolean not null default true
);
insert into public.app_settings (id) values (1) on conflict do nothing;
alter table public.app_settings enable row level security;
drop policy if exists "settings read" on public.app_settings;
create policy "settings read" on public.app_settings for select to authenticated using (true);

create or replace function public.is_approved() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select approved and not banned from profiles where id = auth.uid()), false);
$$;

-- waiting-room people count as "can't post" everywhere is_banned() is checked
create or replace function public.is_banned() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select banned or not approved from profiles where id = auth.uid()), true);
$$;

-- waiting-room people can't see any channels or messages
create or replace function public.can_access(ch uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select is_approved() and exists (
    select 1 from channels c
    where c.id = ch and (
      c.kind = 'public'
      or exists (select 1 from channel_members m where m.channel_id = ch and m.user_id = auth.uid())
    )
  );
$$;

-- people only see approved profiles (admins see everyone, you always see yourself)
drop policy if exists "profiles read" on public.profiles;
create policy "profiles read" on public.profiles for select to authenticated
  using (id = auth.uid() or is_admin() or (approved and is_approved()));

-- new signups: approved right away only if the waiting room is off (first account is always in)
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  first_user boolean;
  needs boolean;
  palette text[] := array['#ff5b2e','#e5484d','#d6409f','#8e4ec6','#5b5bd6','#2f6bff','#0894b3','#12a594','#3e9b4f','#b3831a'];
begin
  select not exists (select 1 from profiles) into first_user;
  select coalesce((select require_approval from app_settings where id = 1), true) into needs;
  insert into profiles (id, username, color, is_admin, approved)
  values (new.id, new.raw_user_meta_data->>'username', palette[1 + floor(random() * 10)::int], first_user, first_user or not needs);
  return new;
end $$;

-- DMs need both people to be in
create or replace function public.open_dm(other uuid) returns uuid
language plpgsql security definer set search_path = public as $$
declare k text; cid uuid;
begin
  if auth.uid() is null or other = auth.uid() then raise exception 'Pick someone else'; end if;
  if not is_approved() then raise exception 'You are still in the waiting room'; end if;
  if not exists (select 1 from profiles where id = other and approved) then raise exception 'User not found'; end if;
  k := least(auth.uid()::text, other::text) || ':' || greatest(auth.uid()::text, other::text);
  select id into cid from channels where dm_key = k;
  if cid is null then
    insert into channels (kind, dm_key, created_by) values ('dm', k, auth.uid()) returning id into cid;
    insert into channel_members (channel_id, user_id) values (cid, auth.uid()), (cid, other);
  end if;
  return cid;
end $$;

-- admin: let someone in, or deny (deletes the account so the name is free again)
create or replace function public.admin_approve(p_user uuid, p_ok boolean) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if not is_admin() then raise exception 'Admins only'; end if;
  if p_ok then
    update profiles set approved = true where id = p_user;
  else
    if exists (select 1 from profiles where id = p_user and approved) then raise exception 'They are already in. Ban them instead.'; end if;
    delete from auth.users where id = p_user;
  end if;
end $$;

create or replace function public.admin_set_approval(p_on boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'Admins only'; end if;
  update app_settings set require_approval = p_on where id = 1;
end $$;
