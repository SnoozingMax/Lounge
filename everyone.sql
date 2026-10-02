-- =====================================================================
--  LOUNGE  ·  upgrade 7: @everyone (admins only)
--  Run ONCE in Supabase SQL Editor
-- =====================================================================

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
    (count(msg.id) filter (where msg.created_at > acc.lr and msg.user_id <> auth.uid() and (
        position('@' || (select u from me) in lower(msg.content)) > 0
        or (msg.content ~* '(^|[^A-Za-z0-9_])@everyone([^A-Za-z0-9_.]|$)'
            and exists (select 1 from profiles a where a.id = msg.user_id and a.is_admin))
    )))::int,
    max(msg.created_at)
  from acc left join messages msg on msg.channel_id = acc.cid
  group by acc.cid;
$$;
