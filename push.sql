-- =====================================================================
--  LOUNGE  ·  upgrade 4: push notifications
--  Run ONCE in Supabase SQL Editor (after the "push" Edge Function exists)
-- =====================================================================

create extension if not exists pg_net;

create table if not exists public.push_subs (
  endpoint text primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  p256dh text not null,
  auth text not null,
  mode text not null default 'pings' check (mode in ('all','pings')),
  created_at timestamptz not null default now()
);
alter table public.push_subs enable row level security;
drop policy if exists "push own" on public.push_subs;
create policy "push own" on public.push_subs for select to authenticated using (user_id = auth.uid());
drop policy if exists "push delete own" on public.push_subs;
create policy "push delete own" on public.push_subs for delete to authenticated using (user_id = auth.uid());
drop policy if exists "push update own" on public.push_subs;
create policy "push update own" on public.push_subs for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- save this device (takes over the device if someone else used it before)
create or replace function public.save_push_sub(p_endpoint text, p_p256dh text, p_auth text, p_mode text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  delete from push_subs where endpoint = p_endpoint;
  insert into push_subs (endpoint, user_id, p256dh, auth, mode)
  values (p_endpoint, auth.uid(), p_p256dh, p_auth, case when p_mode = 'all' then 'all' else 'pings' end);
end $$;

-- when a message is sent, work out who to notify and hand it to the push function
create or replace function public.notify_push() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
declare
  c channels; s profiles; subs jsonb; ttl text; body text;
begin
  select * into c from channels where id = new.channel_id;
  select * into s from profiles where id = new.user_id;

  select jsonb_agg(jsonb_build_object('endpoint', ps.endpoint, 'p256dh', ps.p256dh, 'auth', ps.auth))
    into subs
    from push_subs ps join profiles p on p.id = ps.user_id
   where ps.user_id <> new.user_id
     and not p.banned
     and (
       (c.kind <> 'public' and exists (select 1 from channel_members m where m.channel_id = c.id and m.user_id = ps.user_id))
       or (c.kind = 'public' and (
             ps.mode = 'all'
             or (s.is_admin and new.content ~* '(^|[^A-Za-z0-9_])@everyone([^A-Za-z0-9_.]|$)')
             or new.content ~* ('(^|[^A-Za-z0-9_])@' || regexp_replace(p.username, '([.])', '\\\1', 'g') || '([^A-Za-z0-9_.]|$)')
          ))
     );
  if subs is null then return new; end if;

  ttl := coalesce(s.display_name, s.username)
         || case c.kind when 'public' then ' in #' || c.name when 'group' then ' in ' || c.name else '' end;
  body := case when new.content <> '' then left(regexp_replace(new.content, '^@silent\s*', '', 'i'), 180)
               else '📷 Image' end;

  perform net.http_post(
    url := 'https://nomtlkkplbtnqaxezzoy.supabase.co/functions/v1/push',
    body := jsonb_build_object(
      'title', ttl, 'body', body, 'tag', c.id, 'channel', c.id,
      'silent', new.content ~* '^@silent', 'subs', subs),
    headers := jsonb_build_object('Content-Type', 'application/json', 'x-hook-secret', 'PASTE_HOOK_SECRET')
  );
  return new;
exception when others then
  return new;  -- never block a message because of notifications
end $$;

drop trigger if exists on_message_push on public.messages;
create trigger on_message_push after insert on public.messages
for each row execute function public.notify_push();
