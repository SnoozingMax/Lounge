-- =====================================================================
--  LOUNGE  ·  upgrade 3: friends
--  Run ONCE in Supabase SQL Editor
-- =====================================================================

create table if not exists public.friendships (
  requester uuid references public.profiles(id) on delete cascade,
  addressee uuid references public.profiles(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','accepted')),
  created_at timestamptz not null default now(),
  primary key (requester, addressee),
  check (requester <> addressee)
);
create unique index if not exists friendships_pair on public.friendships
  (least(requester, addressee), greatest(requester, addressee));
alter table public.friendships replica identity full;
alter table public.friendships enable row level security;

drop policy if exists "friends read own" on public.friendships;
create policy "friends read own" on public.friendships for select to authenticated
  using (auth.uid() in (requester, addressee));

-- send a request (or auto-accept if they already asked you)
create or replace function public.friend_request(p_user uuid) returns text
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  if auth.uid() is null or p_user = auth.uid() then raise exception 'Pick someone else'; end if;
  if is_banned() then raise exception 'You are banned'; end if;
  if not exists (select 1 from profiles where id = p_user) then raise exception 'User not found'; end if;
  select * into r from friendships
   where least(requester, addressee) = least(auth.uid(), p_user)
     and greatest(requester, addressee) = greatest(auth.uid(), p_user);
  if found then
    if r.status = 'accepted' then return 'friends'; end if;
    if r.requester = p_user then
      update friendships set status = 'accepted' where requester = p_user and addressee = auth.uid();
      return 'friends';
    end if;
    return 'pending';
  end if;
  insert into friendships (requester, addressee) values (auth.uid(), p_user);
  return 'pending';
end $$;

create or replace function public.friend_accept(p_user uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  update friendships set status = 'accepted'
   where requester = p_user and addressee = auth.uid() and status = 'pending';
  if not found then raise exception 'No request from them'; end if;
end $$;

-- decline, cancel, or unfriend
create or replace function public.friend_remove(p_user uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  delete from friendships
   where (requester = auth.uid() and addressee = p_user)
      or (requester = p_user and addressee = auth.uid());
end $$;

do $$ begin
  alter publication supabase_realtime add table public.friendships;
exception when duplicate_object then null; end $$;
