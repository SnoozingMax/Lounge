-- =====================================================================
--  LOUNGE  ·  upgrade 11: /big text
--  Run ONCE in Supabase SQL Editor
-- =====================================================================

alter table public.profiles add column if not exists big_text boolean not null default false;

-- you can change your own; admins can change anyone's
create or replace function public.set_big(p_user uuid, p_on boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  if p_user <> auth.uid() and not is_admin() then raise exception 'Admins only'; end if;
  update profiles set big_text = p_on where id = p_user;
end $$;
