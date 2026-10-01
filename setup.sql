-- =====================================================================
--  LOUNGE CHAT  ·  fresh-start setup
--  Run this ONCE in a NEW Supabase project: SQL Editor -> paste -> Run
-- =====================================================================

-- ---------- tables ----------
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null check (username ~ '^[A-Za-z0-9_.]{3,20}$'),
  color text not null default '#ff5b2e' check (color ~ '^#[0-9a-fA-F]{6}$'),
  bio text not null default '' check (char_length(bio) <= 190),
  is_admin boolean not null default false,
  banned boolean not null default false,
  created_at timestamptz not null default now()
);
create unique index profiles_username_lower on public.profiles (lower(username));

create table public.channels (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('public','group','dm')),
  name text check (char_length(name) <= 40),
  topic text not null default '' check (char_length(topic) <= 120),
  dm_key text unique,
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now()
);

-- membership for groups + DMs (public channels are open to everyone)
create table public.channel_members (
  channel_id uuid references public.channels(id) on delete cascade,
  user_id uuid references public.profiles(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (channel_id, user_id)
);

-- read markers (kept out of realtime so reading doesn't spam everyone)
create table public.reads (
  channel_id uuid references public.channels(id) on delete cascade,
  user_id uuid references public.profiles(id) on delete cascade,
  last_read_at timestamptz not null default now(),
  primary key (channel_id, user_id)
);

create table public.messages (
  id bigint generated always as identity primary key,
  channel_id uuid not null references public.channels(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  content text not null default '' check (char_length(content) <= 2000),
  image_url text,
  reply_to bigint references public.messages(id) on delete set null,
  edited_at timestamptz,
  created_at timestamptz not null default now(),
  check (content <> '' or image_url is not null)
);
create index messages_channel_id on public.messages (channel_id, id desc);

create table public.reactions (
  message_id bigint references public.messages(id) on delete cascade,
  user_id uuid references public.profiles(id) on delete cascade,
  emoji text not null check (char_length(emoji) <= 16),
  created_at timestamptz not null default now(),
  primary key (message_id, user_id, emoji)
);

-- ---------- helpers ----------
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin from profiles where id = auth.uid()), false);
$$;

create or replace function public.is_banned() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select banned from profiles where id = auth.uid()), true);
$$;

create or replace function public.can_access(ch uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from channels c
    where c.id = ch and (
      c.kind = 'public'
      or exists (select 1 from channel_members m where m.channel_id = ch and m.user_id = auth.uid())
    )
  );
$$;

-- new signup -> profile (first account ever becomes admin)
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  first_user boolean;
  palette text[] := array['#ff5b2e','#e5484d','#d6409f','#8e4ec6','#5b5bd6','#2f6bff','#0894b3','#12a594','#3e9b4f','#b3831a'];
begin
  select not exists (select 1 from profiles) into first_user;
  insert into profiles (id, username, color, is_admin)
  values (new.id, new.raw_user_meta_data->>'username', palette[1 + floor(random() * 10)::int], first_user);
  return new;
end $$;

create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

-- ---------- row level security ----------
alter table public.profiles enable row level security;
alter table public.channels enable row level security;
alter table public.channel_members enable row level security;
alter table public.reads enable row level security;
alter table public.messages enable row level security;
alter table public.reactions enable row level security;

-- profiles: everyone signed in can see; you can only edit your own color + bio
create policy "profiles read" on public.profiles for select to authenticated using (true);
create policy "profiles update own" on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());
revoke update on public.profiles from authenticated, anon;
grant update (color, bio) on public.profiles to authenticated;

-- channels
create policy "channels read" on public.channels for select to authenticated using (can_access(id));
create policy "admins create public channels" on public.channels for insert to authenticated
  with check (is_admin() and kind = 'public' and created_by = auth.uid());
create policy "channels edit" on public.channels for update to authenticated
  using (is_admin() or (kind = 'group' and created_by = auth.uid()));
create policy "channels delete" on public.channels for delete to authenticated
  using (is_admin() or (kind = 'group' and created_by = auth.uid()));
revoke update on public.channels from authenticated, anon;
grant update (name, topic) on public.channels to authenticated;

-- members
create policy "members read" on public.channel_members for select to authenticated using (can_access(channel_id));
create policy "leave group" on public.channel_members for delete to authenticated
  using (user_id = auth.uid() and exists (select 1 from channels c where c.id = channel_id and c.kind = 'group'));

-- reads: only your own
create policy "reads own" on public.reads for select to authenticated using (user_id = auth.uid());

-- messages
create policy "messages read" on public.messages for select to authenticated using (can_access(channel_id));
create policy "messages send" on public.messages for insert to authenticated
  with check (user_id = auth.uid() and not is_banned() and can_access(channel_id));
create policy "messages edit own" on public.messages for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "messages delete" on public.messages for delete to authenticated
  using (user_id = auth.uid() or is_admin());
revoke update on public.messages from authenticated, anon;
grant update (content, edited_at) on public.messages to authenticated;

-- reactions
create policy "reactions read" on public.reactions for select to authenticated
  using (exists (select 1 from messages m where m.id = message_id));
create policy "reactions add" on public.reactions for insert to authenticated
  with check (user_id = auth.uid() and not is_banned() and exists (select 1 from messages m where m.id = message_id));
create policy "reactions remove own" on public.reactions for delete to authenticated using (user_id = auth.uid());

-- ---------- functions the app calls ----------
-- look up the hidden login email for a username (lets people rename freely)
create or replace function public.login_email(p_username text) returns text
language sql stable security definer set search_path = public, auth as $$
  select u.email::text from auth.users u join public.profiles p on p.id = u.id
  where lower(p.username) = lower(p_username) limit 1;
$$;
grant execute on function public.login_email(text) to anon, authenticated;

create or replace function public.change_username(p_new text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if p_new !~ '^[A-Za-z0-9_.]{3,20}$' then
    raise exception 'Usernames are 3-20 letters, numbers, _ or .';
  end if;
  update profiles set username = p_new where id = auth.uid();
exception when unique_violation then
  raise exception 'That username is taken';
end $$;

create or replace function public.open_dm(other uuid) returns uuid
language plpgsql security definer set search_path = public as $$
declare k text; cid uuid;
begin
  if auth.uid() is null or other = auth.uid() then raise exception 'Pick someone else'; end if;
  if not exists (select 1 from profiles where id = other) then raise exception 'User not found'; end if;
  k := least(auth.uid()::text, other::text) || ':' || greatest(auth.uid()::text, other::text);
  select id into cid from channels where dm_key = k;
  if cid is null then
    insert into channels (kind, dm_key, created_by) values ('dm', k, auth.uid()) returning id into cid;
    insert into channel_members (channel_id, user_id) values (cid, auth.uid()), (cid, other);
  end if;
  return cid;
end $$;

create or replace function public.create_group(p_name text, p_members uuid[]) returns uuid
language plpgsql security definer set search_path = public as $$
declare cid uuid;
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  if is_banned() then raise exception 'You are banned'; end if;
  if coalesce(trim(p_name), '') = '' then raise exception 'Give the group a name'; end if;
  insert into channels (kind, name, created_by) values ('group', left(trim(p_name), 40), auth.uid()) returning id into cid;
  insert into channel_members (channel_id, user_id)
    select distinct cid, x from unnest(coalesce(p_members, '{}') || auth.uid()) as x
    where exists (select 1 from profiles p where p.id = x)
  on conflict do nothing;
  return cid;
end $$;

create or replace function public.add_to_group(ch uuid, p_members uuid[]) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not exists (
    select 1 from channels c join channel_members m on m.channel_id = c.id
    where c.id = ch and c.kind = 'group' and m.user_id = auth.uid()
  ) then raise exception 'You are not in this group'; end if;
  insert into channel_members (channel_id, user_id)
    select distinct ch, x from unnest(p_members) as x
    where exists (select 1 from profiles p where p.id = x)
  on conflict do nothing;
end $$;

create or replace function public.mark_read(ch uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or not can_access(ch) then return; end if;
  insert into reads (channel_id, user_id, last_read_at) values (ch, auth.uid(), now())
  on conflict (channel_id, user_id) do update set last_read_at = now();
end $$;

-- unread counts, mention counts, and last activity for every channel you can see
create or replace function public.channel_state()
returns table (channel_id uuid, unread int, mentions int, last_at timestamptz)
language sql stable security definer set search_path = public as $$
  with me as (
    select id, lower(username) as u, created_at from profiles where id = auth.uid()
  ),
  acc as (
    select c.id as cid, coalesce(r.last_read_at, (select created_at from me)) as lr
    from channels c
    left join reads r on r.channel_id = c.id and r.user_id = auth.uid()
    where c.kind = 'public'
       or exists (select 1 from channel_members m where m.channel_id = c.id and m.user_id = auth.uid())
  )
  select acc.cid,
    (count(msg.id) filter (where msg.created_at > acc.lr and msg.user_id <> auth.uid()))::int,
    (count(msg.id) filter (where msg.created_at > acc.lr and msg.user_id <> auth.uid()
        and position('@' || (select u from me) in lower(msg.content)) > 0))::int,
    max(msg.created_at)
  from acc left join messages msg on msg.channel_id = acc.cid
  group by acc.cid;
$$;

create or replace function public.admin_set(p_user uuid, p_field text, p_value boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'Admins only'; end if;
  if p_user = auth.uid() then raise exception 'You can''t change your own status'; end if;
  if p_field = 'banned' then
    update profiles set banned = p_value where id = p_user;
  elsif p_field = 'is_admin' then
    update profiles set is_admin = p_value where id = p_user;
  else
    raise exception 'Unknown setting';
  end if;
end $$;

-- ---------- image uploads ----------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('attachments', 'attachments', true, 5242880,
        array['image/png','image/jpeg','image/gif','image/webp'])
on conflict (id) do nothing;

create policy "upload to own folder" on storage.objects for insert to authenticated
  with check (bucket_id = 'attachments' and (storage.foldername(name))[1] = auth.uid()::text);

-- ---------- realtime ----------
alter publication supabase_realtime add table
  public.messages, public.reactions, public.channels, public.channel_members, public.profiles;

-- ---------- starter channels ----------
insert into public.channels (kind, name, topic) values
  ('public', 'general', 'Say hi. Everyone is here.'),
  ('public', 'random', 'Anything goes'),
  ('public', 'media', 'Clips, pics, memes');
