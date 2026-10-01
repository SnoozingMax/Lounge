-- =====================================================================
--  LOUNGE  ·  upgrade 2: profiles, mutes, 5-minute deletes, admin tools
--  Run ONCE in Supabase SQL Editor (safe on top of setup.sql)
-- =====================================================================

-- profile fields
alter table public.profiles
  add column if not exists display_name text check (char_length(display_name) <= 32),
  add column if not exists status text not null default '' check (char_length(status) <= 60),
  add column if not exists avatar_url text,
  add column if not exists muted_until timestamptz;

revoke update on public.profiles from authenticated, anon;
grant update (color, bio, avatar_url, display_name, status) on public.profiles to authenticated;

create or replace function public.is_muted() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select muted_until > now() from profiles where id = auth.uid()), false);
$$;

-- muted people can't send or edit; normal users can only delete within 5 minutes
drop policy if exists "messages send" on public.messages;
create policy "messages send" on public.messages for insert to authenticated
  with check (user_id = auth.uid() and not is_banned() and not is_muted() and can_access(channel_id));

drop policy if exists "messages edit own" on public.messages;
create policy "messages edit own" on public.messages for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid() and not is_muted());

drop policy if exists "messages delete" on public.messages;
create policy "messages delete" on public.messages for delete to authenticated
  using (is_admin() or (user_id = auth.uid() and created_at > now() - interval '5 minutes'));

-- admin tools
create or replace function public.admin_mute(p_user uuid, p_minutes int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'Admins only'; end if;
  if p_user = auth.uid() then raise exception 'You can''t mute yourself'; end if;
  update profiles
     set muted_until = case when coalesce(p_minutes, 0) <= 0 then null
                            else now() + make_interval(mins => least(p_minutes, 525600)) end
   where id = p_user;
end $$;

create or replace function public.admin_purge(p_user uuid) returns int
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if not is_admin() then raise exception 'Admins only'; end if;
  delete from messages where user_id = p_user;
  get diagnostics n = row_count;
  return n;
end $$;

create or replace function public.admin_stats() returns json
language sql stable security definer set search_path = public as $$
  select case when is_admin() then json_build_object(
    'users',    (select count(*) from profiles),
    'banned',   (select count(*) from profiles where banned),
    'muted',    (select count(*) from profiles where muted_until > now()),
    'messages', (select count(*) from messages),
    'today',    (select count(*) from messages where created_at > now() - interval '24 hours'),
    'images',   (select count(*) from messages where image_url is not null),
    'channels', (select count(*) from channels where kind = 'public'),
    'groups',   (select count(*) from channels where kind = 'group'),
    'dms',      (select count(*) from channels where kind = 'dm')
  ) end;
$$;

-- profile pictures
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('avatars', 'avatars', true, 1048576, array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;

drop policy if exists "avatar read" on storage.objects;
drop policy if exists "avatar upload own" on storage.objects;
drop policy if exists "avatar update own" on storage.objects;
drop policy if exists "avatar delete own" on storage.objects;
create policy "avatar read" on storage.objects for select to authenticated
  using (bucket_id = 'avatars');
create policy "avatar upload own" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "avatar update own" on storage.objects for update to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "avatar delete own" on storage.objects for delete to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

-- bye media
delete from public.channels where kind = 'public' and name = 'media';

-- ---------- password recovery (no email needed) ----------
create table if not exists public.recovery (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  key_hash text not null,
  updated_at timestamptz not null default now()
);
alter table public.recovery enable row level security;   -- no policies: nobody can read it directly

create or replace function public.set_recovery_key(p_key text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  if length(p_key) < 8 then raise exception 'Key too short'; end if;
  insert into recovery (user_id, key_hash) values (auth.uid(), crypt(p_key, gen_salt('bf', 8)))
  on conflict (user_id) do update set key_hash = excluded.key_hash, updated_at = now();
end $$;

create or replace function public.recover_password(p_username text, p_key text, p_new text) returns void
language plpgsql security definer set search_path = public, extensions, auth as $$
declare uid uuid;
begin
  perform pg_sleep(0.5);  -- slows down guessing
  if length(p_new) < 6 then raise exception 'Password needs at least 6 characters'; end if;
  select p.id into uid from profiles p join recovery r on r.user_id = p.id
   where lower(p.username) = lower(p_username) and r.key_hash = crypt(p_key, r.key_hash);
  if uid is null then raise exception 'Wrong username or recovery key'; end if;
  update auth.users set encrypted_password = crypt(p_new, gen_salt('bf', 10)), updated_at = now() where id = uid;
end $$;
grant execute on function public.recover_password(text, text, text) to anon, authenticated;

create or replace function public.admin_reset_password(p_user uuid) returns text
language plpgsql security definer set search_path = public, extensions, auth as $$
declare tmp text;
begin
  if not is_admin() then raise exception 'Admins only'; end if;
  if p_user = auth.uid() then raise exception 'Change your own password in settings'; end if;
  tmp := substr(translate(encode(gen_random_bytes(9), 'base64'), '+/=', 'xyz'), 1, 10);
  update auth.users set encrypted_password = crypt(tmp, gen_salt('bf', 10)), updated_at = now() where id = p_user;
  return tmp;
end $$;
